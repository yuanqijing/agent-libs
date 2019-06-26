#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include "sinsp.h"
#include "sinsp_int.h"
#include "../../driver/ppm_ringbuffer.h"

#include "parsers.h"
#include "analyzer_int.h"
#include "analyzer.h"
#include "analyzer_parsers.h"
#include "metrics.h"
#undef min
#undef max
#include "draios.pb.h"
#include "delays.h"
#include "scores.h"
#include "procfs_parser.h"
#include "sinsp_errno.h"
#include "sched_analyzer.h"
#include "analyzer_thread.h"
#include "analyzer_fd.h"

sinsp_analyzer_parsers::sinsp_analyzer_parsers(sinsp_analyzer* const analyzer):
	m_analyzer(analyzer),
	m_sched_analyzer2(nullptr),
	m_last_drop_was_enter(false)
{ }

//
// This is similar to sinsp_parser::process_event, but it's for draios-only event
// processing. Returns false if process_event() should return immediately.
//
bool sinsp_analyzer_parsers::process_event(sinsp_evt* evt)
{
	uint16_t etype = evt->get_type();

	switch(etype)
	{
	case PPME_SCHEDSWITCH_1_E:
	case PPME_SCHEDSWITCH_6_E:
		if(m_analyzer->get_thread_count() < DROP_SCHED_ANALYZER_THRESHOLD)
		{
			m_sched_analyzer2->process_event(evt);
		}
		return false;
	case PPME_SOCKET_ACCEPT_X:
	case PPME_SOCKET_ACCEPT4_X:
	case PPME_SOCKET_ACCEPT_5_X:
	case PPME_SOCKET_ACCEPT4_5_X:
		parse_accept_exit(evt);;
		return true;
	case PPME_SYSCALL_SELECT_X:
	case PPME_SYSCALL_POLL_X:
	case PPME_SYSCALL_EPOLLWAIT_X:
		parse_select_poll_epollwait_exit(evt);
		return true;
	case PPME_SYSCALL_EXECVE_8_X:
	case PPME_SYSCALL_EXECVE_13_X:
	case PPME_SYSCALL_EXECVE_14_X:
	case PPME_SYSCALL_EXECVE_15_X:
	case PPME_SYSCALL_EXECVE_16_X:
	case PPME_SYSCALL_EXECVE_17_X:
	case PPME_SYSCALL_EXECVE_18_X:
	case PPME_SYSCALL_EXECVE_19_X:
		return parse_execve_exit(evt);
	case PPME_DROP_E:
		if(!m_last_drop_was_enter)
		{
			parse_drop(evt);
			m_analyzer->simulate_drop_mode(true);

			//g_logger.log("Executing flush (drop_e)", sinsp_logger::SEV_INFO);
			m_analyzer->flush(evt, evt->get_ts(), false, analyzer_emitter::DF_FORCE_FLUSH);

			m_last_drop_was_enter = true;
		}

		return false;
	case PPME_DROP_X:
		if(m_last_drop_was_enter)
		{
			parse_drop(evt);
			m_analyzer->simulate_drop_mode(false);

			//g_logger.log("Executing flush (drop_x)", sinsp_logger::SEV_INFO);
			m_analyzer->flush(evt, evt->get_ts(), false, analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT);

			m_last_drop_was_enter = false;
		}

		return false;

	case PPME_SYSDIGEVENT_E:
		m_analyzer->set_driver_stopped_dropping(true);
		return false;
	case PPME_CONTAINER_E:
		return false;
	default:
		return true;
	}
}

void sinsp_analyzer_parsers::set_sched_analyzer2(sinsp_sched_analyzer2* const sched_analyzer2)
{
	m_sched_analyzer2 = sched_analyzer2;
}

void sinsp_analyzer_parsers::parse_accept_exit(sinsp_evt* evt)
{
	//
	// Extract the request queue length
	//
	sinsp_evt_param *parinfo = evt->get_param(2);
	ASSERT(parinfo->m_len == sizeof(uint8_t));
	uint8_t queueratio = *(uint8_t*)parinfo->m_val;
	ASSERT(queueratio <= 100);

	if(evt->m_tinfo == NULL)
	{
		return;
	}

	if(queueratio > evt->m_tinfo->m_ainfo->m_connection_queue_usage_pct)
	{
		evt->m_tinfo->m_ainfo->m_connection_queue_usage_pct = queueratio;
	}

	//
	// If this comes after a wait, reset the last wait time, since we don't count
	// time waiting for an accept as I/O time
	//
	evt->m_tinfo->m_ainfo->m_last_wait_duration_ns = 0;
}

void sinsp_analyzer_parsers::parse_select_poll_epollwait_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	uint16_t etype = evt->get_type();

	if(evt->m_tinfo == NULL)
	{
		return;
	}

	if(etype != evt->m_tinfo->m_lastevent_type + 1)
	{
		//
		// Packet drop. Previuos event didn't have a chance to
		//
		return;
	}

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// Check if the syscall was successful
	//
	if(retval >= 0)
	{
		sinsp_threadinfo* tinfo = evt->m_tinfo;

		if(tinfo == NULL)
		{
			ASSERT(false);
			return;
		}

		if(tinfo->is_lastevent_data_valid() && evt->m_tinfo->m_lastevent_data)
		{
			//
			// We categorize this based on the next I/O operation only if the number of
			// FDs that were waited for is 1
			//
			if(retval == 0)
			{
				tinfo->m_ainfo->m_last_wait_duration_ns = 0;
			}
			else
			{
				//
				// If this was a wait on a *single* fd, we can easily categorize it with certainty and
				// we encode the delta as a positive number.
				// If this was a wait on multiple FDs, we encode the delta as a negative number so
				// the next steps will know that it needs to be handled with more care.
				//
				uint64_t sample_duration = m_analyzer->get_configuration_read_only()->get_analyzer_sample_len_ns();
				uint64_t ts = evt->get_ts();

				tinfo->m_ainfo->m_last_wait_end_time_ns = ts;
				uint64_t start_time_ns = MAX(ts - ts % sample_duration, *(uint64_t*)evt->m_tinfo->m_lastevent_data);

				if(retval == 1)
				{
					tinfo->m_ainfo->m_last_wait_duration_ns = ts - start_time_ns;
				}
				else
				{
					tinfo->m_ainfo->m_last_wait_duration_ns = start_time_ns - ts;
				}
			}
		}
	}
}

bool sinsp_analyzer_parsers::parse_execve_exit(sinsp_evt* evt)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();
	if(tinfo == NULL)
	{
		return true;
	}

	//
	// Check the result of the call
	//
	sinsp_evt_param *parinfo;
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	int64_t res = *(int64_t*)parinfo->m_val;

	if(res < 0)
	{
		return true;
	}

	thread_analyzer_info* tainfo = evt->m_tinfo->m_ainfo;
	tainfo->m_called_execve = true;

	const sinsp_configuration* sinsp_conf = m_analyzer->get_configuration_read_only();

	//
	// Detect if this is a stress tool and in that case request to go in nodriver mode
	//
	if(m_analyzer->detect_and_match_stress_tool(tinfo->m_comm))
	{
		return true;
	}

	//
	// If command line capture is disabled, we stop here
	//
	if(!sinsp_conf->get_command_lines_capture_enabled())
	{
		return true;
	}

	//
	// Navigate the parent processes to determine if this is the descendent of a shell
	// and if yes what's the shell ID
	//
	uint32_t shell_dist = 0;
	uint64_t login_shell_id = 0;
	uint32_t cur_dist = 0;
	bool valid_ancestor = false;
	bool found_container_init = false;

	sinsp_threadinfo::visitor_func_t visitor =
		[sinsp_conf, &login_shell_id, &shell_dist, &cur_dist,
		 &valid_ancestor, &found_container_init] (sinsp_threadinfo *ptinfo)
	{
		if(cur_dist && sinsp_conf->is_command_lines_valid_ancestor(ptinfo->m_comm))
		{
			valid_ancestor = true;
		}

		if(ptinfo->m_vpid == 1 && !ptinfo->m_container_id.empty())
		{
			found_container_init = true;
		}

		uint32_t cl = ptinfo->m_comm.size();
		if(cl >= 2 && ptinfo->m_comm[cl - 2] == 's' && ptinfo->m_comm[cl - 1] == 'h')
		{
			//
			// We found a shell. Patch the descendat but don't stop here since there might
			// be another parent shell
			//
			login_shell_id = ptinfo->m_tid;
			shell_dist = cur_dist;
		}

		cur_dist++;
		return true;
	};

	if(visitor(tinfo))
	{
		tinfo->traverse_parent_state(visitor);
	}

	// If the parents chain is broken, ignore login_shell_id and shell_dist because not meaningful
	if(tinfo->m_parent_loop_detected)
	{
		login_shell_id = 0;
		shell_dist = 0;
	}

	bool mode_ok = false;
	switch(sinsp_conf->get_command_lines_capture_mode())
	{
		case sinsp_configuration::command_capture_mode_t::CM_TTY:
			if(tinfo->m_tty)
			{
				mode_ok = true;
			}
			break;
		case sinsp_configuration::command_capture_mode_t::CM_SHELL_ANCESTOR:
			if(login_shell_id)
			{
				mode_ok = true;
			}
			break;
		case sinsp_configuration::command_capture_mode_t::CM_ALL:
			mode_ok = true;
			break;
		default:
			ASSERT(false);
	}

	//
	// Let a process show up if it was executed inside a container but
	// doesn't have the container init as parent (and it's in a separate
	// pid ns), very likely it comes from docker exec
	//
	bool container_exec = false;
	if(!tinfo->m_container_id.empty() && !found_container_init &&
		tinfo->m_vpid != tinfo->m_pid)
	{
		container_exec = true;
	}

	if(!mode_ok && !valid_ancestor && !container_exec)
	{
		return true;
	}

	m_analyzer->incr_command_lines_category(convert_category(tinfo->m_category));

	if(tinfo->is_health_probe() &&
	   !sinsp_conf->get_command_lines_include_container_healthchecks())
	{
		return true;
	}

	//
	// Allocated an executed command storage info and initialize it
	//
	sinsp_executed_command cmdinfo;

	if(tinfo->m_clone_ts != 0)
	{
		cmdinfo.m_ts = tinfo->m_clone_ts;
	}
	else
	{
		cmdinfo.m_ts = evt->get_ts();
	}

	cmdinfo.m_cmdline = tinfo->m_comm;
	cmdinfo.m_exe = tinfo->m_exe;
	cmdinfo.m_comm = tinfo->m_comm;
	cmdinfo.m_pid = tinfo->m_pid;
	cmdinfo.m_ppid = tinfo->m_ptid;
	cmdinfo.m_uid = tinfo->m_uid;
	cmdinfo.m_cwd = tinfo->m_cwd;
	cmdinfo.m_tty = tinfo->m_tty;
	cmdinfo.m_category = convert_category(tinfo->m_category);

	//
	// Build the arguments string
	//
	uint32_t nargs = tinfo->m_args.size();

	for(uint32_t j = 0; j < nargs; j++)
	{
		cmdinfo.m_cmdline += ' ';
		cmdinfo.m_cmdline += tinfo->m_args[j];
	}

	cmdinfo.m_shell_id = login_shell_id;
	cmdinfo.m_login_shell_distance = shell_dist;

	//
	// Determine if this command was executed in a pipe and if yes
	// where it belongs in the pipe
	//
	if((tinfo->m_flags & (PPM_CL_PIPE_SRC | PPM_CL_PIPE_DST)) == (PPM_CL_PIPE_SRC | PPM_CL_PIPE_DST))
	{
		cmdinfo.m_flags |= sinsp_executed_command::FL_PIPE_MIDDLE;
	}
	else if((tinfo->m_flags & (PPM_CL_PIPE_SRC)) == (PPM_CL_PIPE_SRC))
	{
		cmdinfo.m_flags |= sinsp_executed_command::FL_PIPE_HEAD;
	}
	else if((tinfo->m_flags & (PPM_CL_PIPE_DST)) == (PPM_CL_PIPE_DST))
	{
		cmdinfo.m_flags |= sinsp_executed_command::FL_PIPE_TAIL;
	}

	m_analyzer->add_executed_command(tinfo->m_container_id, cmdinfo);

	return true;
}

void sinsp_analyzer_parsers::parse_drop(sinsp_evt* evt)
{
	m_analyzer->set_last_dropmode_switch_time(evt->get_ts());

	//
	// If required, update the sample length
	//
	sinsp_evt_param *parinfo;
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int32_t));

	if(*(uint32_t*)parinfo->m_val != m_analyzer->get_sampling_ratio())
	{
		g_logger.format(sinsp_logger::SEV_INFO, "sinsp Switching sampling ratio from % " PRIu32 " to %" PRIu32,
			m_analyzer->get_sampling_ratio(),
			*(uint32_t*)parinfo->m_val);

		m_analyzer->set_sampling_ratio(*(int32_t*)parinfo->m_val);
	}
}

draiosproto::command_category sinsp_analyzer_parsers::convert_category(sinsp_threadinfo::command_category &tcat)
{
	// Explicitly converting to point out mismatches
	draiosproto::command_category cat;

	switch(tcat)
	{
	case sinsp_threadinfo::CAT_NONE:
		cat = draiosproto::CAT_NONE;
		break;
	case sinsp_threadinfo::CAT_CONTAINER:
		cat = draiosproto::CAT_CONTAINER;
		break;
	case sinsp_threadinfo::CAT_HEALTHCHECK:
		cat = draiosproto::CAT_HEALTHCHECK;
		break;
	case sinsp_threadinfo::CAT_LIVENESS_PROBE:
		cat = draiosproto::CAT_LIVENESS_PROBE;
		break;
	case sinsp_threadinfo::CAT_READINESS_PROBE:
		cat = draiosproto::CAT_READINESS_PROBE;
		break;
	default:
		g_logger.format(sinsp_logger::SEV_ERROR, "Unknown command category %d, using CAT_NONE", tcat);
		cat = draiosproto::CAT_NONE;
	}

	return cat;
}

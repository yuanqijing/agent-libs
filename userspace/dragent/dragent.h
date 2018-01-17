#pragma once

#include "main.h"

#ifndef _WIN32
#include <sys/prctl.h>
#endif

#include "coclient.h"
#include "crash_handler.h"
#include "configuration.h"
#include "connection_manager.h"
#include "blocking_queue.h"
#include "error_handler.h"
#include "capture_job_handler.h"
#include "sinsp_worker.h"
#include "logger.h"
#include "monitor.h"
#include "subprocesses_logger.h"
#include "internal_metrics.h"
#include <atomic>
#include <memory>

#include "sdc_internal.pb.h"
#include "draios.pb.h"
#include "analyzer_utils.h"

class watchdog_state
{
public:
	watchdog_state() noexcept:
		m_pid(0),
		m_memory_used(0),
		m_last_loop_s(0)
	{}

	pid_t pid() const noexcept { return m_pid.load(); }
	uint64_t memory_used() const noexcept { return m_memory_used.load(); }
	uint64_t last_loop_s() const noexcept { return m_last_loop_s.load(); }

	void reset(pid_t pid, uint64_t memory_used, uint64_t last_loop_s)
	{
		m_memory_used.store(memory_used);
		m_last_loop_s.store(last_loop_s);
		m_pid.store(pid);
	}

	void reset()
	{
		reset(0, 0, 0);
	}

	bool valid() const
	{
		return m_pid.load() > 0;
	}

	const std::string& name() const
	{
		return m_name;
	}

private:
	// careful here - only app should access this function
	// at a well-defined time (preferably immediately after object
	// creation); the name string will be read from subprocess
	// logger thread
	void set_name(const std::string& name)
	{
		m_name = name;
	}

	atomic<pid_t> m_pid;
	atomic<uint64_t> m_memory_used;
	atomic<uint64_t> m_last_loop_s;
	std::string m_name;

	friend class dragent_app;
};

class user_event_channel;

///////////////////////////////////////////////////////////////////////////////
// The main application class
///////////////////////////////////////////////////////////////////////////////
class dragent_app: public Poco::Util::ServerApplication
{
public:
	dragent_app();
	~dragent_app();

protected:
	void initialize(Application& self);
	void uninitialize();
	void defineOptions(OptionSet& options);
	void handleOption(const std::string& name, const std::string& value);
	void displayHelp();
	int main(const std::vector<std::string>& args);

private:
	int sdagent_main();
	void watchdog_check(uint64_t uptime_s);
	void dump_heap_profile(uint64_t uptime_s, bool throttle = true);
	void initialize_logging();
	void check_for_clean_shutdown();
	void mark_clean_shutdown();
	Logger* make_console_channel(AutoPtr<Formatter> formatter);
	Logger* make_event_channel();
	void send_internal_metrics(pid_t pid, const std::string& name);
	void update_subprocesses();

	bool m_help_requested;
	bool m_version_requested;
	string m_pidfile;
	dragent_configuration m_configuration;
	dragent_error_handler m_error_handler;
	protocol_queue m_queue;
	atomic<bool> m_enable_autodrop;

	unique_ptr<errpipe_manager> m_jmx_pipes;
	shared_ptr<pipe_manager> m_statsite_pipes;
	unique_ptr<errpipe_manager> m_sdchecks_pipes;
	unique_ptr<errpipe_manager> m_mounted_fs_reader_pipe;
	unique_ptr<errpipe_manager> m_statsite_forwarder_pipe;
	unique_ptr<pipe_manager> m_cointerface_pipes;

	internal_metrics::sptr_t m_internal_metrics;
	sinsp_worker m_sinsp_worker;
	capture_job_handler m_capture_job_handler;
	connection_manager m_connection_manager;
	log_reporter m_log_reporter;
	subprocesses_logger m_subprocesses_logger;
	unordered_map<string, watchdog_state> m_subprocesses_state;
	uint64_t m_last_dump_s;
	std::unique_ptr<coclient> m_coclient;
	run_on_interval m_cointerface_ping_interval = {5*ONE_SECOND_IN_NS};
};
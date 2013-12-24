#ifndef _WIN32
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#endif
#include "sinsp.h"
#include "sinsp_int.h"

///////////////////////////////////////////////////////////////////////////////
// sinsp_fdinfo inomlementation
///////////////////////////////////////////////////////////////////////////////
template <> sinsp_fdinfo_t::sinsp_fdinfo()
{
	m_type = SCAP_FD_UNINITIALIZED;
	m_flags = FLAGS_NONE;
}

template <> string* sinsp_fdinfo_t::tostring()
{
	return &m_name;
}

template <> char sinsp_fdinfo_t::get_typechar()
{
	switch(m_type)
	{
	case SCAP_FD_FILE:
		return CHAR_FD_FILE;
	case SCAP_FD_IPV4_SOCK:
		return CHAR_FD_IPV4_SOCK;
	case SCAP_FD_IPV6_SOCK:
		return CHAR_FD_IPV6_SOCK;
	case SCAP_FD_DIRECTORY:
		return CHAR_FD_DIRECTORY;
	case SCAP_FD_IPV4_SERVSOCK:
		return CHAR_FD_IPV4_SERVSOCK;
	case SCAP_FD_IPV6_SERVSOCK:
		return CHAR_FD_IPV6_SERVSOCK;
	case SCAP_FD_FIFO:
		return CHAR_FD_FIFO;
	case SCAP_FD_UNIX_SOCK:
		return CHAR_FD_UNIX_SOCK;
	case SCAP_FD_EVENT:
		return CHAR_FD_EVENT;
	case SCAP_FD_UNKNOWN:
		return CHAR_FD_UNKNOWN;
	case SCAP_FD_UNSUPPORTED:
		return CHAR_FD_UNSUPPORTED;
	case SCAP_FD_SIGNALFD:
		return CHAR_FD_SIGNAL;
	case SCAP_FD_EVENTPOLL:
		return CHAR_FD_EVENTPOLL;
	case SCAP_FD_INOTIFY:
		return CHAR_FD_INOTIFY;
	case SCAP_FD_TIMERFD:
		return CHAR_FD_TIMERFD;
	default:
		ASSERT(false);
		return '?';
	}
}


template <> void sinsp_fdinfo_t::add_filename(const char* directory, uint32_t directorylen, const char* filename, uint32_t filenamelen)
{
	char fullpath[SCAP_MAX_PATH_SIZE];

	sinsp_utils::concatenate_paths(fullpath, SCAP_MAX_PATH_SIZE, directory, directorylen, filename, filenamelen);
	
	m_name = fullpath;
}

template <> void sinsp_fdinfo_t::print_on(FILE* f)
{
	if(is_unix_socket())
	{
		fprintf(f,"%" PRIx64 "->%" PRIx64 " %d %s\n",m_info.m_unixinfo.m_fields.m_source,m_info.m_unixinfo.m_fields.m_dest,m_flags,m_name.c_str()); 
	}
	else if(is_ipv4_socket())
	{
		fprintf(f,"%s\n",m_name.c_str());
	}
}

template <> void sinsp_fdinfo_t::set_role_by_guessing(sinsp_partial_transaction::direction dir)
{
	if(!(m_flags & (FLAGS_ROLE_CLIENT | FLAGS_ROLE_SERVER)))
	{
		//
		// We just assume that a server usually starts with a read and a client with a write
		//
		if(dir == sinsp_partial_transaction::DIR_IN)
		{
			set_role_server();
		}
		else
		{
			set_role_client();
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_fdtable inomlementation
///////////////////////////////////////////////////////////////////////////////
sinsp_fdtable::sinsp_fdtable(sinsp* inspector)
{
	m_inspector = inspector;
	reset_cache();
}

sinsp_fdinfo_t* sinsp_fdtable::find(int64_t fd)
{
	unordered_map<int64_t, sinsp_fdinfo_t>::iterator fdit = m_table.find(fd);

	//
	// Try looking up in our simple cache
	//
	if(m_last_accessed_fd != -1 && fd == m_last_accessed_fd)
	{
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats.m_n_cached_fd_lookups++;
#endif
		return m_last_accessed_fdinfo;
	}

	//
	// Caching failed, do a real lookup
	//
	fdit = m_table.find(fd);

	if(fdit == m_table.end())
	{
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats.m_n_failed_fd_lookups++;
#endif
		return NULL;
	}
	else
	{
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats.m_n_noncached_fd_lookups++;
#endif
		m_last_accessed_fd = fd;
		m_last_accessed_fdinfo = &(fdit->second);
		return &(fdit->second);
	}
}

void sinsp_fdtable::add(int64_t fd, sinsp_fdinfo_t* fdinfo)
{
	unordered_map<int64_t, sinsp_fdinfo_t>::iterator fdit = m_table.find(fd);

	//
	// Look for the FD in the table
	//
	if(fdit == m_table.end())
	{
		//
		// No entry in the table, this is the normal case
		//
		m_table[fd] = *fdinfo;
		m_last_accessed_fd = -1;
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats.m_n_added_fds++;
#endif
	}
	else
	{
		//
		// the fd is already in the table.
		//
		if(fdit->second.m_flags & sinsp_fdinfo_t::FLAGS_CLOSE_IN_PROGRESS)
		{
			//
			// Sometimes an FD-creating syscall can be called on an FD that is being closed (i.e
			// the close enter has arrived but the close exit has not arrived yet). 
			// If this is the case, mark the new entry so that the successive close exit won't
			// destroy it.
			//
			fdinfo->m_flags &= ~sinsp_fdinfo_t::FLAGS_CLOSE_IN_PROGRESS;
			fdinfo->m_flags |= sinsp_fdinfo_t::FLAGS_CLOSE_CANCELED;
			
			m_table[CANCELED_FD_NUMBER] = fdit->second;
		}
		else
		{
			//
			// This can happen if:
			//  - the event is a dup2 or dup3 that overwrites an existing FD (perfectly legal)
			//  - a close() has been dropped when capturing
			//  - an fd has been closed by clone() or execve() (it happens when the fd is opened with the FD_CLOEXEC flag,
			//    which we don't currently parse.
			// In either case, removing the old fd, replacing it with the new one and keeping going is a reasonable
			// choice. We include an assertion to catch the situation.
			//
			// XXX Can't have this enabled until the FD_CLOEXEC flag is supported
//					ASSERT(false);
		}

		//
		// Replace the fd as a struct copy
		//
		fdit->second = *fdinfo;
	}
}

void sinsp_fdtable::erase(int64_t fd)
{
	unordered_map<int64_t, sinsp_fdinfo_t>::iterator fdit = m_table.find(fd);

	if(fd == m_last_accessed_fd)
	{
		m_last_accessed_fd = -1;		
	}

	if(fdit == m_table.end())
	{
		//
		// Looks like there's no fd to remove.
		// Either the fd creation event was dropped or (more likely) our logic doesn't support the
		// call that created this fd. The assertion will detect it, while in release mode we just
		// keep going.
		//
		ASSERT(false);
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats.m_n_failed_fd_lookups++;
#endif
	}
	else
	{
		m_table.erase(fdit);
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats.m_n_noncached_fd_lookups++;
		m_inspector->m_stats.m_n_removed_fds++;
#endif
	}
}

void sinsp_fdtable::clear()
{
	m_table.clear();
}

size_t sinsp_fdtable::size()
{
	return m_table.size();
}

void sinsp_fdtable::print_on(FILE* f)
{
	unordered_map<int64_t, sinsp_fdinfo_t>::iterator fdit;

	for(fdit = m_table.begin(); fdit != m_table.end(); fdit++)
	{
		fprintf(f,"\tfd %" PRIu64 " = ",fdit->first);
		fdit->second.print_on(f);
		fprintf(f,"\n");
	}
}

void sinsp_fdtable::reset_cache()
{
	m_last_accessed_fd = -1;
}

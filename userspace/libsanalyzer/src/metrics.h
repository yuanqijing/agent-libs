#pragma once

#include <memory>
#include <event.h>
#include <analyzer_settings.h>
#include "scap.h"
#include "sinsp.h"
#include "assert.h"

#ifdef HAS_ANALYZER

//
// Forward declarations
//
class sinsp_counter_time_bytes;
class sinsp_procinfo;
class sinsp_counter_time_bidirectional;
class sinsp_protostate;

namespace draiosproto
{
    class metrics;
	class time_categories;
	class counter_time;
	class counter_time_bidirectional;
	class counter_bytes;
	class counter_time_bytes;
	class transaction_categories;
	class connection_categories;
	class counter_syscall_errors;
	class transaction_breakdown_categories;
	class proto_info;
	class url_details;
};

//
// A super-basic counter: just 32 bit count
//
class sinsp_counter_cnt
{
public:
	sinsp_counter_cnt()
	{
		m_count = 0;
	}

	uint32_t m_count;
};

//
// A basic counter: total time + count
//
class percentile;
class sinsp_counter_percentile
{
public:
	sinsp_counter_percentile(const std::set<double>* percentiles = nullptr,
	                         const sinsp_counter_percentile *shared = nullptr);
	~sinsp_counter_percentile() {}

	void set_percentiles(const std::set<double>& percentiles,
	                     const sinsp_counter_percentile *shared = nullptr);
	void set_serialize_pctl_data(bool val);

	std::shared_ptr<percentile> m_percentile;
	bool m_serialize_pctl_data;
};

class sinsp_counter_percentile_in_out
{
public:
	sinsp_counter_percentile_in_out(const std::set<double>* percentiles = nullptr,
	                                const sinsp_counter_percentile_in_out *shared = nullptr);
	~sinsp_counter_percentile_in_out() {}

	void set_percentiles(const std::set<double>& percentiles,
	                     const sinsp_counter_percentile_in_out *shared = nullptr);
	void set_serialize_pctl_data(bool val);

	std::shared_ptr<percentile> m_percentile_in;
	std::shared_ptr<percentile> m_percentile_out;
	bool m_serialize_pctl_data;
};

class sinsp_counter_time: public sinsp_counter_percentile
{
public:
	sinsp_counter_time(const std::set<double>* percentiles = nullptr,
	                   const sinsp_counter_percentile *shared = nullptr);
	~sinsp_counter_time();

	sinsp_counter_time(const sinsp_counter_time& other);
	sinsp_counter_time& operator=(sinsp_counter_time &other);

	void add(uint32_t cnt_delta, uint64_t time_delta);
	void add(sinsp_counter_time* other);
	void add(sinsp_counter_time_bytes* other);
	void add(sinsp_counter_time_bidirectional* other);
	void subtract(uint32_t cnt_delta, uint64_t time_delta);
	void clear();
	void to_protobuf(draiosproto::counter_time* protobuf_msg, uint64_t tot_relevant_time_ns, uint32_t sampling_ratio);
	void coalesce_protobuf(draiosproto::counter_time* protobuf_msg,
			       uint64_t tot_relevant_time_ns,
			       uint64_t& denominator,
			       const uint32_t sampling_ratio);

	uint32_t m_count;
	uint64_t m_time_ns;
};

//
// A bidirectional time counter
//
class sinsp_counter_time_bidirectional: public sinsp_counter_percentile_in_out
{
public:
	sinsp_counter_time_bidirectional(const std::set<double>* percentiles = nullptr,
	                                 const sinsp_counter_percentile_in_out *shared = nullptr);
	~sinsp_counter_time_bidirectional();

	sinsp_counter_time_bidirectional(const sinsp_counter_time_bidirectional& other);
	sinsp_counter_time_bidirectional& operator=(sinsp_counter_time_bidirectional &other);

	void add_in(uint32_t cnt_delta, uint64_t time_delta);
	void add_out(uint32_t cnt_delta, uint64_t time_delta);
	void add_other(uint32_t cnt_delta, uint64_t time_delta);
	void add(sinsp_counter_time_bidirectional* other);
	void clear();
	void to_protobuf(draiosproto::counter_time_bidirectional* protobuf_msg, uint32_t sampling_ratio) const;
	void coalesce_protobuf_add(draiosproto::counter_time_bidirectional* protobuf_msg,
				   uint32_t sampling_ratio) const;
	void coalesce_protobuf_max(draiosproto::counter_time_bidirectional* protobuf_msg,
			       uint32_t sampling_ratio) const;
	uint32_t get_tot_count() const;

	uint32_t m_count_in;
	uint32_t m_count_out;
	uint32_t m_count_other;
	uint64_t m_time_ns_in;
	uint64_t m_time_ns_out;
	uint64_t m_time_ns_other;
};

//
// A basic counter: bytes + count
//
class sinsp_counter_bytes
{
public:
	sinsp_counter_bytes();
	void add_in(uint32_t cnt_delta, uint32_t bytes_delta);
	void add_out(uint32_t cnt_delta, uint32_t bytes_delta);
	void add(sinsp_counter_bytes* other);
	void clear();
	void to_protobuf(draiosproto::counter_bytes* protobuf_msg, uint32_t sampling_ratio) const;

	uint32_t m_count_in;
	uint32_t m_count_out;
	uint32_t m_bytes_in;
	uint32_t m_bytes_out;
};

//
// A time + size in bytes counter, useful for I/O metrics
//
class sinsp_counter_time_bytes: public sinsp_counter_percentile_in_out
{
public:
	sinsp_counter_time_bytes(const std::set<double>* percentiles = nullptr,
	                         const sinsp_counter_percentile_in_out *shared = nullptr);
	~sinsp_counter_time_bytes();

	sinsp_counter_time_bytes(const sinsp_counter_time_bytes& other);
	sinsp_counter_time_bytes& operator=(sinsp_counter_time_bytes &other);

	void add_in(uint32_t cnt_delta, uint64_t time_delta, uint32_t bytes_delta);
	void add_out(uint32_t cnt_delta, uint64_t time_delta, uint32_t bytes_delta);
	void add_other(uint32_t cnt_delta, uint64_t time_delta, uint32_t bytes_delta);
	void add(sinsp_counter_time_bytes* other);
	void add(sinsp_counter_time* other);
	void add(sinsp_counter_time_bidirectional* other, bool add_count);
	void clear();
	void to_protobuf(draiosproto::counter_time_bytes* protobuf_msg,
			 uint64_t tot_relevant_time_ns,
			 uint32_t sampling_ratio);
	void coalesce_protobuf(draiosproto::counter_time_bytes* protobuf_msg,
			       uint64_t tot_relevant_time_ns,
			       const uint32_t sampling_ratio);
	uint64_t get_tot_bytes() const;

	uint32_t m_count_in;
	uint32_t m_count_out;
	uint32_t m_count_other;
	uint64_t m_time_ns_in;
	uint64_t m_time_ns_out;
	uint64_t m_time_ns_other;
	uint32_t m_bytes_in;
	uint32_t m_bytes_out;
	uint32_t m_bytes_other;
};

//
// A collection of counters for basic operation of a process or machine
//
class sinsp_counters
{
public:
	sinsp_counter_time m_unknown;
	sinsp_counter_time m_other;
	sinsp_counter_time m_file;
	sinsp_counter_time m_net;
	sinsp_counter_time m_ipc;
	sinsp_counter_time m_memory;
	sinsp_counter_time m_process;
	sinsp_counter_time m_sleep;
	sinsp_counter_time m_system;
	sinsp_counter_time m_signal;
	sinsp_counter_time m_user;
	sinsp_counter_time m_time;
	sinsp_counter_time_bytes m_io_file;
	sinsp_counter_time_bytes m_io_net;
	sinsp_counter_time_bytes m_io_other;
	sinsp_counter_time_bidirectional m_wait_file;
	sinsp_counter_time_bidirectional m_wait_net;
	sinsp_counter_time_bidirectional m_wait_ipc;
	sinsp_counter_time m_wait_other;
	sinsp_counter_time m_processing;

	sinsp_counters();

	void clear();
	void set_percentiles(const std::set<double>& percentiles,
	                     const sinsp_counters *shared = nullptr);
	void set_serialize_pctl_data(bool val);
	void add(sinsp_counters* other);
	void get_total(sinsp_counter_time* tot);
	void calculate_totals();
	void to_protobuf(draiosproto::time_categories* protobuf_msg, uint32_t sampling_ratio);
	void coalesce_protobuf(draiosproto::time_categories* protobuf_msg,
			       const uint32_t sampling_ratio,
			       uint64_t& other_denom,
			       uint64_t& processing_denom);
	void to_reqprotobuf(draiosproto::transaction_breakdown_categories* protobuf_msg, uint32_t sampling_ratio);
	void coalesce_reqprotobuf(draiosproto::transaction_breakdown_categories* protobuf_msg,
				  uint32_t sampling_ratio,
				  uint64_t& other_denom,
				  uint64_t& processing_denom);

	uint64_t get_total_other_time();
	uint64_t get_total_wait_time();
	uint64_t get_total_file_time();
	uint64_t get_total_net_time();
	uint64_t get_total_ipc_time();

	double get_processing_percentage();
	double get_other_percentage();
	double get_file_percentage();
	double get_net_percentage();

	sinsp_counter_time m_tot_other;
	sinsp_counter_time m_tot_wait;
	sinsp_counter_time_bytes m_tot_io_file;
	sinsp_counter_time_bytes m_tot_io_net;
	sinsp_counter_time m_tot_ipc;
	sinsp_counter_time m_tot_relevant;

	std::set<double> m_percentiles;
};

//
// Connection counters
//
class sinsp_connection_counters
{
public:
	sinsp_counter_bytes m_server;
	sinsp_counter_bytes m_client;

	void clear();
	void to_protobuf(draiosproto::connection_categories* protobuf_msg, uint32_t sampling_ratio) const;
	void add(sinsp_connection_counters* other);
};

//
// Transaction counters (for processes, connections, etc)
//
class sinsp_transaction_counters
{
public:
	sinsp_transaction_counters(const std::set<double>* percentiles = nullptr,
	                           const sinsp_transaction_counters *shared = nullptr);
	void set_percentiles(const std::set<double>& percentiles,
	                     const sinsp_transaction_counters *shared = nullptr);
	void set_serialize_pctl_data(bool val);
	void clear();
	void to_protobuf(draiosproto::counter_time_bidirectional* protobuf_msg,
		draiosproto::counter_time_bidirectional* max_protobuf_msg, 
		uint32_t sampling_ratio) const;
	void coalesce_protobuf(draiosproto::counter_time_bidirectional* protobuf_msg,
			       draiosproto::counter_time_bidirectional* max_protobuf_msg, 
			       uint32_t sampling_ratio) const;
	void add(sinsp_transaction_counters* other);
	void add_in(uint32_t cnt_delta, uint64_t time_delta);
	void add_out(uint32_t cnt_delta, uint64_t time_delta);
	const sinsp_counter_time_bidirectional* get_counter();
	const sinsp_counter_time_bidirectional* get_max_counter();

	bool has_percentiles() const;
private:
	sinsp_counter_time_bidirectional m_counter;
	sinsp_counter_time_bidirectional m_max_counter;
	bool m_has_percentiles = false;
};

inline bool sinsp_transaction_counters::has_percentiles() const
{
	return m_has_percentiles;
}

//
// Error counters (for host, processes, etc)
//
class sinsp_error_counters
{
public:
//	unordered_map<int32_t, sinsp_counter_cnt> m_table;
	uint32_t m_count; // Syscall errors count
    uint32_t m_count_file;	// Number of file errors
    uint32_t m_count_file_open;	// Number of file open errors
    uint32_t m_count_net;	// Number of network errors

	void clear();
	inline void add(sinsp_evt* evt)
	{
		m_count++;

		sinsp_fdinfo_t* fdinfo = evt->get_fd_info();

		if(fdinfo != NULL)
		{
			scap_fd_type fdtype = fdinfo->m_type;

			if(fdtype == SCAP_FD_FILE || fdtype == SCAP_FD_FILE_V2)
			{
				m_count_file++;
			}
			else if(fdtype == SCAP_FD_IPV4_SOCK || fdtype == SCAP_FD_IPV6_SOCK)
			{
				m_count_net++;
			}
		}
		else
		{
			uint16_t etype = evt->get_type();

			if(etype == PPME_SYSCALL_OPEN_X ||
				etype == PPME_SYSCALL_CREAT_X ||
				etype == PPME_SYSCALL_OPENAT_X ||
				etype == PPME_SYSCALL_OPENAT_2_X)
			{
				m_count_file_open++;
				m_count_file++;
			}
			else if(etype == PPME_SOCKET_ACCEPT_X ||
				etype == PPME_SOCKET_ACCEPT4_X ||
				etype == PPME_SOCKET_ACCEPT_5_X ||
				etype == PPME_SOCKET_ACCEPT4_5_X ||
				etype == PPME_SOCKET_CONNECT_X ||
				etype == PPME_SOCKET_BIND_X)
			{
				m_count_file_open++;
				m_count_file++;
			}
		}
	}
	void add(sinsp_error_counters* other);
	void to_protobuf(draiosproto::counter_syscall_errors* protobuf_msg, uint32_t sampling_ratio) const;
	void coalesce_protobuf(draiosproto::counter_syscall_errors* protobuf_msg, 
			       uint32_t sampling_ratio) const;
};

//
// Count of all syscalls that have been processed
//
class sinsp_syscall_counters
{
public:
	void add(uint16_t type)
	{
		if (type >= PPM_EVENT_MAX)
		{
			ASSERT(false);
			return;
		}

		m_calls[type/2]++;
		m_total_calls++;
	}
	void clear();
	// Map from num calls to event type
	std::map<uint64_t, uint16_t> top_calls(uint16_t count) const;
	uint64_t total_calls() const { return m_total_calls; }

private:
	// Put enter+exit events in the same bucket
	std::array<uint64_t, PPM_EVENT_MAX/2> m_calls = {};
	uint64_t m_total_calls = 0;
};

//
// Various metrics coming from processes, aggregated at the host level
//
class SINSP_PUBLIC sinsp_host_metrics
{
public:
	sinsp_host_metrics();
	~sinsp_host_metrics();
	void clear();
	void add(sinsp_procinfo* pinfo);
	void add_capacity_score(float capacity_score,
		float stolen_capacity_score,
		uint32_t n_server_transactions);
	double get_capacity_score() const;
	double get_stolen_score() const;
	void set_percentiles(const std::set<double>& percentiles);
	void set_serialize_pctl_data(bool val);

	sinsp_counters m_metrics; 
	uint32_t m_connection_queue_usage_pct;
	uint32_t m_fd_usage_pct;
	sinsp_syscall_counters m_syscall_count;
	sinsp_error_counters m_syscall_errors;
	uint64_t m_pfmajor;
	uint64_t m_pfminor;
	sinsp_protostate* m_protostate;
	uint32_t m_fd_count; // Number of FDs
	int64_t m_res_memory_used_kb;
	int64_t m_res_memory_free_kb;
	int64_t m_res_memory_avail_kb;
	int64_t m_swap_memory_used_kb;
	int64_t m_swap_memory_total_kb;
	int64_t m_swap_memory_avail_kb;
	double m_cpuload; // for containers
	unsigned m_threads_count = 0;

	int get_process_count() const;
	int get_process_start_count() const;

private:
	double m_tot_capacity_score;
	double m_tot_stolen_capacity_score;
	uint32_t m_tot_server_transactions;
	int m_proc_count = 0;
	int m_proc_start_count = 0;

	friend class test_helper;
};

inline int sinsp_host_metrics::get_process_count() const
{
	return m_proc_count;
}

inline int sinsp_host_metrics::get_process_start_count() const
{
	return m_proc_start_count;
}

#endif // HAS_ANALYZER
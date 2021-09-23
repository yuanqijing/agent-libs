#pragma once

#include <memory>
#include <string>
#include <vector>
#include <map>

#include "agent-prom.grpc.pb.h"
#include "agent-prom.pb.h"
#include "draios.pb.h"
#include "promscrape_conf.h"
#include "limits/metric_limits.h"
#include "interval_runner.h"
#include "prom_grpc_iface.h"
#include <thread_safe_container/blocking_queue.h>
#include <mutex>
#include <json/json.h>

class prom_infra_iface;
class promscrape;

class promscrape_stats {
public:
	promscrape_stats(const promscrape_conf &prom_conf, promscrape *ps);

	void set_stats(std::string url,
		int raw_scraped, int raw_job_filter_dropped,
		int raw_over_job_limit, int raw_global_filter_dropped,
		int calc_scraped, int calc_job_filter_dropped,
		int calc_over_job_limit, int calc_global_filter_dropped);
	void add_stats(std::string url, int over_global_limit,
		int raw_sent, int calc_sent);
	void periodic_log_summary();

	void process_metadata();
	void process_scrape(std::string instance, std::shared_ptr<agent_promscrape::ScrapeResult> scrape);

	bool gather_stats_enabled();
	void enable_gather_stats(bool enable = true);
	void gather_target_stats();
	void periodic_gather_stats();

	typedef struct {
		int raw_scraped;
		int raw_job_filter_dropped;
		int raw_over_job_limit;
		int raw_global_filter_dropped;
		int raw_sent;
		int calc_scraped;
		int calc_job_filter_dropped;
		int calc_over_job_limit;
		int calc_global_filter_dropped;
		int calc_sent;
		int over_global_limit;
	} metric_stats;

	typedef struct {
		std::string type;
		std::string help;
		std::string unit;
		int timeseries;
	} metric_metadata;

	typedef std::map<std::string, metric_metadata> metric_metadata_map_t;
	typedef std::map<std::string, metric_stats> stats_map_t;

private:
	void log_summary();
	void clear();
	void init_command_line();

	std::mutex m_mutex;
	// Map from URL to stats
	std::map<std::string, metric_stats> m_stats_map;
	// Map from instance to map from metric name to metadata
	std::map<std::string, std::map<std::string, metric_metadata>> m_metadata_map;

	interval_runner m_log_interval;
	promscrape_conf m_scrape_conf;

	interval_runner m_gather_interval;
	bool m_gather_stats = false;
	int m_gather_stats_count = 0;

	std::mutex m_json_mutex;
	Json::Value m_local_targets;
	Json::Value m_local_targets_metadata;
	Json::Value m_cluster_targets;
	Json::Value m_cluster_targets_metadata;

	Json::Reader m_json_reader;

	promscrape *m_promscrape;
};

class promscrape {
public:
	typedef std::map<std::string, std::string> tag_map_t;
	typedef std::unordered_map<std::string, std::string> tag_umap_t;
	typedef struct {
		int pid;
		std::string url;
		std::string container_id;
		uint64_t config_ts;
		uint64_t data_ts;
		uint64_t last_total_samples;
		tag_map_t add_tags;
		bool bypass_limits;
		bool stale;
		bool omit_source;		// Don't send source_metadata
	} prom_job_config;

	// Map from process-id to job-ids
	typedef std::map<int, std::list<int64_t>> prom_pid_map_t;
	// Map from job_id to job config
	typedef std::map<int64_t, prom_job_config> prom_jobid_map_t;
	// Map from job_id to scrape results
	typedef std::map<int64_t, std::shared_ptr<agent_promscrape::ScrapeResult>> prom_metric_map_t;
	// Map from url+job_name to job_id for Promscrape V2
	typedef std::map<std::pair<std::string, std::string>, int64_t> prom_joburl_map_t;

	// There are a few hacks in here related to 10s flush. Hopefully those can go away if/when
	// we get support for a callback that lets promscrape override the outgoing protobuf
	// Hack to get dynamic interval from dragent without adding dependency
	typedef std::function<int()> interval_cb_t;

	// Other hack to let analyzer flush loop know if it can populate the prometheus metric
	// counters (otherwise promscrape will be managing them instead)
	bool emit_counters() const;

	// jobs that haven't been used for this long will be pruned.
	const int job_prune_time_s = 15;

	const prom_jobid_map_t& job_map() { return m_jobs; }

	explicit promscrape(metric_limits::sptr_t ml, const promscrape_conf &prom_conf, bool threaded, interval_cb_t interval_cb,
		std::unique_ptr<prom_unarygrpc_iface> grpc_applyconfig, std::unique_ptr<prom_streamgrpc_iface> grpc_start);

	// next() needs to be called from the main thread on a regular basis.
	// With threading enabled it just updates the current timestamp.
	// Without threading it will also call into next_th()
	void next(uint64_t ts);
	// next_th() manages the GRPC connections and processes the queues.
	// Only needs to be called explicitly if threading is enabled, on its own thread.
	void next_th();

	// sendconfig() queues up scrape target configs. Without threadig the configs will get sent
	// immediately. With threading they will get sent during a call to next_th()
	void sendconfig(const std::vector<prom_process> &prom_procs);

	// pid_has_jobs returns whether or not scrape jobs exist for the given pid.
	bool pid_has_jobs(int pid);

	// pid_has_metrics returns whether or not metrics exist for the given pid.
	bool pid_has_metrics(int pid);

	// pid_to_protobuf() packs prometheus metrics for the given pid into
	// the protobuf "proto" by calling job_to_protobuf() for every job.
	// "limit" indicates the limit of metrics that can still be added to the protobuf
	// The number of metrics added is deducted from "limit" and returned.
	// "filtered" and "total" will be set to the number of metrics that passed
	// the metric filter and the total number before filtering.
	// metric is either an draiosproto::app_metric or prometheus_metric
	template<typename metric>
	unsigned int pid_to_protobuf(int pid, metric *proto,
		unsigned int &limit, unsigned int max_limit,
		unsigned int *filtered, unsigned int *total, bool callback = false);

	template<typename metric>
	unsigned int job_to_protobuf(int64_t job_id, metric *proto,
		unsigned int &limit, unsigned int max_limit,
		unsigned int *filtered, unsigned int *total);

private:
	unsigned int result_to_protobuf(int64_t job_id,
		std::shared_ptr<agent_promscrape::ScrapeResult> res,
		prom_job_config *job_config, draiosproto::prom_metrics *pb, bool enforce_limits,
		unsigned int &limit, unsigned int max_limit,
		unsigned int *filtered, unsigned int *total);

public:
	// Some scrape jobs can be set up to bypass limits and filters and will export their
	// metrics through a separate standalone protobuf message (raw_prometheus_metrics)
	// set_raw_bypass_callback() can be used to specify a callback that will be called whenever
	// scrape results for one such job are received.
	// The callback will be called on the promscrape thread
	//
	// Instead of sending results whenever they are received from promscrape the collector
	// may actually prefer to receive all bypass results once per interval. TBD
	typedef std::function<void(std::shared_ptr<draiosproto::raw_prometheus_metrics> msg)> raw_bypass_cb_t;
	void set_raw_bypass_callback(raw_bypass_cb_t cb) { m_bypass_cb = cb; }

	// create_bypass_protobuf() will create a raw_prometheus_metrics message containing
	// the results from either the given job_id or all bypass jobs if (job_id < 0).
	std::shared_ptr<draiosproto::raw_prometheus_metrics> create_bypass_protobuf(int64_t job_id);

	void set_allow_bypass(bool allow) { m_allow_bypass = allow; }
	bool allow_bypass();

	std::shared_ptr<draiosproto::metrics> metrics_request_callback();

	// Fastproto has been supported for a while, this is here in case we don't want
	// the backend to try enabling it.
	static bool support_fastproto() { return true; }

	void periodic_log_summary() { m_stats.periodic_log_summary(); }
	void periodic_gather_stats() { m_stats.periodic_gather_stats(); }

	// With Promscrape V2 the agent will no longer find endpoints through the
	// process_filter or remote_services rules.
	// Promscrape will be doing service discovery instead
	bool is_promscrape_v2() { return m_scrape_conf.prom_sd(); }

	void set_infra_state(prom_infra_iface *is) { m_infra_state = is; }
private:
	void sendconfig_th(const std::vector<prom_process> &prom_procs);

	bool started();
	void try_start();
	void reset();
	void start();
	int64_t job_url_to_job_id(const std::string &url, const std::string &jobname);
	int64_t assign_job_id(int pid, const std::string &url,
		const std::string &container_id, const tag_map_t &tags, uint64_t ts);
	void addscrapeconfig(int pid, const std::string &url,
		const std::string &container_id, const std::map<std::string, std::string> &options,
		const std::string &path, uint16_t port, const tag_map_t &tags,
		const tag_umap_t &infra_tags, uint64_t ts);
	void settargetauth(agent_promscrape::Target *target,
		const std::map<std::string, std::string> &options);
	void applyconfig();
	void handle_result(agent_promscrape::ScrapeResult &result);
	void prune_jobs(uint64_t ts);
	void delete_job(int64_t job_id);

	std::shared_ptr<agent_promscrape::ScrapeResult> get_job_result_ptr(uint64_t job_id,
		prom_job_config *config_copy);

	// Mutex to protect all 5 maps, might want finer granularity some day
	std::mutex m_map_mutex;
	prom_metric_map_t m_metrics;
	prom_jobid_map_t m_jobs;
	prom_pid_map_t m_pids;
	prom_joburl_map_t m_joburls;

	std::string m_sock;
	std::shared_ptr<agent_promscrape::ScrapeService::Stub> m_start_conn;
	std::shared_ptr<agent_promscrape::ScrapeService::Stub> m_config_conn;

	std::unique_ptr<prom_streamgrpc_iface> m_grpc_start;
	std::unique_ptr<prom_unarygrpc_iface> m_grpc_applyconfig;

	interval_runner m_start_interval;
	uint64_t m_boot_ts = 0;

	std::atomic<uint64_t> m_next_ts;
	uint64_t m_last_config_ts = 0;
	uint64_t m_last_ts = 0;
	bool m_start_failed = false;

	metric_limits::sptr_t m_metric_limits;
	bool m_threaded;
	promscrape_conf m_scrape_conf;

	thread_safe_container::blocking_queue<std::vector<prom_process>> m_config_queue;
	std::vector<prom_process> m_last_prom_procs;
	std::shared_ptr<agent_promscrape::Config> m_config;
	bool m_resend_config;
	interval_cb_t m_interval_cb;
	uint64_t m_last_proto_ts = 0;
	uint64_t m_last_prune_ts = 0;

	// Mutex to protect m_export_pids
	std::mutex m_export_pids_mutex;
	std::set<int> m_export_pids;	// Populated by pid_to_protobuf for 10s flush callback.

	bool m_emit_counters = true;

	promscrape_stats m_stats;
	prom_infra_iface *m_infra_state = nullptr;

	raw_bypass_cb_t m_bypass_cb;
	bool m_allow_bypass = false;

	friend class test_helper;
};

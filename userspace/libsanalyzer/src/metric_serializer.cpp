/**
 * @file
 *
 * Implementation of metric_serializer -- an abstract base class for analyzer
 * metric serialization.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "metric_serializer.h"
#include "config.h"
#include "internal_metrics.h"
#include "sinsp.h"

namespace libsanalyzer
{

const uint64_t metric_serializer::NO_EVENT_NUMBER =
		std::numeric_limits<uint64_t>::max();

metric_serializer::data::data(const uint64_t evt_num,
                              const uint64_t ts,
                              const uint32_t sampling_ratio,
                              const double prev_flush_cpu_pct,
                              const uint64_t prev_flushes_duration_ns,
                              std::atomic<bool>& metrics_sent,
                              const double my_cpuload,
                              const bool extra_internal_metrics,
                              const draiosproto::metrics& metrics):
	m_evt_num(evt_num),
	m_ts(ts),
	m_sampling_ratio(sampling_ratio),
	m_prev_flush_cpu_pct(prev_flush_cpu_pct),
	m_prev_flushes_duration_ns(prev_flushes_duration_ns),
	m_metrics_sent(metrics_sent),
	m_my_cpuload(my_cpuload),
	m_extra_internal_metrics(extra_internal_metrics),
	m_metrics(std::make_shared<draiosproto::metrics>(metrics))
{ }

metric_serializer::metric_serializer(const internal_metrics::sptr_t& internal_metrics,
                                     const sinsp_configuration* const configuration):
	m_mutex(),
	m_internal_metrics(internal_metrics),
	m_configuration(configuration),
	m_sample_callback(nullptr)
{ }

bool metric_serializer::get_emit_metrics_to_file() const
{
	std::unique_lock<std::mutex> lock(m_mutex);

	return m_configuration->get_emit_metrics_to_file();
}

const std::string& metric_serializer::get_metrics_directory() const
{
	std::unique_lock<std::mutex> lock(m_mutex);

	return m_configuration->get_metrics_directory();
}

void metric_serializer::update_configuration(const sinsp_configuration* const configuration)
{
	std::unique_lock<std::mutex> lock(m_mutex);

	m_configuration = configuration;
}

void metric_serializer::set_internal_metrics(const internal_metrics::sptr_t im)
{
	std::unique_lock<std::mutex> lock(m_mutex);

	m_internal_metrics = im;
}

const internal_metrics::sptr_t& metric_serializer::get_internal_metrics() const
{
	std::unique_lock<std::mutex> lock(m_mutex);

	return m_internal_metrics;
}

void metric_serializer::set_sample_callback(analyzer_callback_interface* const cb)
{
	std::unique_lock<std::mutex> lock(m_mutex);

	m_sample_callback = cb;
}

analyzer_callback_interface* metric_serializer::get_sample_callback() const
{
	std::unique_lock<std::mutex> lock(m_mutex);

	return m_sample_callback;
}

} // end namespace libsanalyzer
#include "dumper_worker.h"

#include "logger.h"

const string dumper_worker::m_name = "dumper_worker";

dumper_worker::dumper_worker(dragent_queue* queue, dragent_configuration* configuration, 
	uint64_t duration_ns, const string& filter):
	
	m_queue(queue),
	m_configuration(configuration),
	m_duration_ms(duration_ns / 1000000),
	m_filter(filter)
{
}

void dumper_worker::run()
{
	//
	// A quick hack to automatically delete this object
	//
	SharedPtr<dumper_worker> ptr(this);

	g_log->information(m_name + ": Starting");
		
	if(m_configuration->m_dump_in_progress)
	{
		string error = "Another capture is already in progress";
		send_error(error);
		return;
	}

	g_log->information(m_name + ": Running for " + NumberFormatter::format(m_duration_ms) + " ms");
	dragent_configuration::m_dump_enabled = true;

	int64_t sleep_time_ms = m_duration_ms;
	while(sleep_time_ms > 0 && !dragent_configuration::m_terminate)
	{
		Thread::sleep(100);
		sleep_time_ms -= 100;
	}

	if(!dragent_configuration::m_terminate)
	{
		dragent_configuration::m_dump_enabled = false;
	
		if(m_configuration->m_dump_completed.tryWait(60000))
		{
			g_log->information(m_name + ": Capture completed, sending file");
			send_file();
		}
		else
		{
			string error = "Timeout waiting for capture completed event";
			send_error(error);
		}
	}

	g_log->information(m_name + ": Terminating");
}

void dumper_worker::send_error(const string& error)
{
	g_log->error(error);
	draiosproto::dump_response response;
	prepare_response(&response);
	response.set_error(error);
	queue_response(response);	
}

void dumper_worker::send_file()
{
	FileInputStream file(m_configuration->m_dump_file);
	string sfile;

	uint32_t nread = copy_file(&file, &sfile);
	
	g_log->information(m_name + ": File size: " + NumberFormatter::format(nread));

	draiosproto::dump_response response;
	prepare_response(&response);
	response.set_content(sfile);
	queue_response(response);
}

void dumper_worker::prepare_response(draiosproto::dump_response* response)
{
	response->set_timestamp_ns(dragent_configuration::get_current_time_ns());
	response->set_customer_id(m_configuration->m_customer_id);
	response->set_machine_id(m_configuration->m_machine_id);
}

void dumper_worker::queue_response(const draiosproto::dump_response& response)
{
	SharedPtr<dragent_queue_item> buffer = dragent_protocol::message_to_buffer(
		dragent_protocol::PROTOCOL_MESSAGE_TYPE_DUMP_RESPONSE, 
		response, 
		m_configuration->m_compression_enabled);

	if(buffer.isNull())
	{
		g_log->error("NULL converting message to buffer");
		return;
	}

	while(!m_queue->put(buffer))
	{
		g_log->error(m_name + ": Queue full, waiting");
		Thread::sleep(1000);

		if(dragent_configuration::m_terminate)
		{
			break;
		}
	}
}

std::streamsize dumper_worker::copy_file(FileInputStream* istr, std::string* str)
{
	Buffer<char> buffer(8192);
	std::streamsize len = 0;
	
	istr->read(buffer.begin(), buffer.size());
	std::streamsize n = istr->gcount();

	while(n > 0)
	{
		len += n;
		str->append(buffer.begin(), static_cast<std::string::size_type>(n));

		if(len > MAX_SERIALIZATION_BUF_SIZE_BYTES * 0.9)
		{
			g_log->information("File too big, truncating to " + NumberFormatter::format(len));
			break;
		}

		if(istr)
		{
			istr->read(buffer.begin(), buffer.size());
			n = istr->gcount();
		}
		else 
		{
			n = 0;
		}
	}

	return len;
}

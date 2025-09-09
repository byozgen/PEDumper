#pragma once
#include "queue.hpp"
#include <thread>
#include "hdatabasePE.hpp"
#include "n0xDumper.hpp"
#include "windows.h"

class close_watcher
{
	databasePE* _clean_db;
	PD_OPTIONS* _options;

	Queue<n0xDumper*> _work_queue;

	thread* _monitoring_thread;
	bool _monitor_request_stop;

	void _monitor_dump_on_close();
	void _dump_process_worker_and_close();

public:
	close_watcher(databasePE* clean_db, PD_OPTIONS* options);
	bool start_monitor();
	bool stop_monitor();
	~close_watcher();
};


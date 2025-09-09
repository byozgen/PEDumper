#include "watchercloser.hpp"


close_watcher::close_watcher(databasePE* clean_db, PD_OPTIONS* options)
{
	_clean_db = clean_db;
	_options = options;
	_monitoring_thread = NULL;
	_monitor_request_stop = false;
}

bool close_watcher::start_monitor()
{
	if (_monitoring_thread == NULL)
	{
		_monitor_request_stop = false;
		_monitoring_thread = new thread(&close_watcher::_monitor_dump_on_close, this);

		printf("Started monitoring for process closes.\r\n");
	}
	return true;
}

bool close_watcher::stop_monitor()
{
	if (_monitoring_thread != NULL)
	{
		_monitor_request_stop = true;
		_monitoring_thread->join();

		delete _monitoring_thread;
		_monitoring_thread = NULL;

		printf("Stopped monitoring for process closes.\r\n");
	}

	return true;
}


void close_watcher::_monitor_dump_on_close()
{
	unordered_set<DWORD> hooked_pids;
	unordered_map<DWORD, n0xDumper*> hooked_processes;

	thread** threads = new thread*[_options->NumberOfThreads];

	for (int i = 0; i < _options->NumberOfThreads; i++)
	{
		threads[i] = new thread(&close_watcher::_dump_process_worker_and_close, this);
	}

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	DWORD myPid = GetCurrentProcessId();

	while (!_monitor_request_stop)
	{
		snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (snapshot != INVALID_HANDLE_VALUE)
		{
			if (Process32First(snapshot, &entry) == TRUE)
			{
				while (Process32Next(snapshot, &entry) == TRUE)
				{
					if (myPid != entry.th32ProcessID && hooked_pids.count(entry.th32ProcessID) == 0)
					{
						if (_wcsicmp(entry.szExeFile, L"csrss.exe") != 0) //  CRASHING CSRSS.EXE
						{
							// Test code to only hook notepad.exe
							//if (_wcsicmp(entry.szExeFile, L"notepad.exe") == 0)
							//{

							n0xDumper* dumper = new n0xDumper(entry.th32ProcessID, _clean_db, _options, true);
							if (dumper->monitor_close_start())
							{
								printf("...hooked close of: pid 0x%x,%S\r\n", entry.th32ProcessID, entry.szExeFile);
								hooked_processes.insert(std::pair<DWORD, n0xDumper*>(dumper->get_pid(), dumper));
								hooked_pids.insert(dumper->get_pid());
							}
							else
								delete dumper;
							//}
						}
					}
				}
			}
			CloseHandle(snapshot);
		}

		for (unordered_map<DWORD, n0xDumper*>::iterator it = hooked_processes.begin(); it != hooked_processes.end(); )
		{
			if (it->second->monitor_close_is_waiting())
			{

				char name[0x200];
				it->second->get_process_name(name, sizeof(name));
				printf("Process %s requesting to close, we are dumping it...\r\n", name);
				_work_queue.push(it->second);

				it = hooked_processes.erase(it);
			}
			else
			{
				it++;
			}
		}

		Sleep(10);
	}

	while (!_work_queue.empty())
	{
		printf("waiting for dump commands to be pulled from work queue...\r\n");
		Sleep(200);
	}

	for (int i = 0; i < _options->NumberOfThreads; i++)
	{
		threads[i]->join();
		delete threads[i];
		threads[i] = NULL;
	}
	delete[]threads;

	for (unordered_map<DWORD, n0xDumper*>::iterator it = hooked_processes.begin(); it != hooked_processes.end(); ++it)
	{
		delete it->second;
	}
}


void close_watcher::_dump_process_worker_and_close()
{
	unordered_set<unsigned __int64> new_hashes;
	while (!_monitor_request_stop || !_work_queue.empty())
	{
		n0xDumper* entry;
		if (_work_queue.pop(entry))
		{
			entry->monitor_close_dump_and_resume();

			delete entry;
		}

		Sleep(10);
	}
}


close_watcher::~close_watcher()
{
	stop_monitor();
}

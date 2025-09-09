#include "windows.h"
#include "headerPE.hpp"
#include <tlhelp32.h>
#include <cstdio>
#include "hdatabasePE.hpp"
#include "n0xDumper.hpp"
#include "simp.hpp"
#include "queue.hpp"
#include <thread>
#include "watchercloser.hpp"
#include "tchar.h"

//check this
BOOL is_win64()
{
#if defined(_WIN64)
	return TRUE;  // 64-bit programs run only on Win64
#elif defined(_WIN32)
	// 32-bit programs run on both 32-bit and 64-bit Windows
	// so must sniff
	BOOL f64 = FALSE;
	return IsWow64Process(GetCurrentProcess(), &f64) && f64;
#else
	return FALSE; // Win64 does not support Win16
#endif
}

bool is_elevated(HANDLE h_Process)
{
	HANDLE h_Token;
	TOKEN_ELEVATION t_TokenElevation;
	TOKEN_ELEVATION_TYPE e_ElevationType;
	DWORD dw_TokenLength;

	if (OpenProcessToken(h_Process, TOKEN_READ | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &h_Token))
	{
		if (GetTokenInformation(h_Token, TokenElevation, &t_TokenElevation, sizeof(t_TokenElevation), &dw_TokenLength))
		{
			if (t_TokenElevation.TokenIsElevated != 0)
			{
				if (GetTokenInformation(h_Token, TokenElevationType, &e_ElevationType, sizeof(e_ElevationType), &dw_TokenLength))
				{
					if (e_ElevationType == TokenElevationTypeFull || e_ElevationType == TokenElevationTypeDefault)
					{
						return true;
					}
				}
			}
		}
	}

	return false;
}


bool get_privileges(HANDLE h_Process)
{
	HANDLE h_Token;
	DWORD dw_TokenLength;
	if (OpenProcessToken(h_Process, TOKEN_READ | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &h_Token))
	{
	
		TOKEN_PRIVILEGES* privilages = new TOKEN_PRIVILEGES[100];
		if (GetTokenInformation(h_Token, TokenPrivileges, privilages, sizeof(TOKEN_PRIVILEGES) * 100, &dw_TokenLength))
		{
			for (int i = 0; i < privilages->PrivilegeCount; i++)
			{
				privilages->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
			}

			if (AdjustTokenPrivileges(h_Token, false, privilages, sizeof(TOKEN_PRIVILEGES) * 100, NULL, NULL))
			{
				delete[] privilages;
				return true;
			}
		}
		delete[] privilages;
	}
	return false;
}

bool ConsoleRequestingClose = false;
BOOL WINAPI ConsoleHandler(DWORD CEvent)
{
	char mesg[128];

	switch (CEvent)
	{
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:

		printf("Close request received.\r\n");
		ConsoleRequestingClose = true;
		break;
	case CTRL_CLOSE_EVENT:
	case CTRL_LOGOFF_EVENT:
	case CTRL_SHUTDOWN_EVENT:
		printf("Terminate request received.\r\n");
		ConsoleRequestingClose = true;
		Sleep(30000);
		break;
	}
	return TRUE;
}

void add_process_hashes(DWORD pid, databasePE* db, PD_OPTIONS* options)
{
	unordered_set<unsigned __int64> new_hashes;

	n0xDumper* dumper = new n0xDumper(pid, db, options, true);
	dumper->get_all_hashes(&new_hashes);
	delete dumper;

	db->add_hashes(new_hashes);
}

void add_process_hashes_worker(Queue<PROCESSENTRY32>* work_queue, databasePE* db, PD_OPTIONS* options)
{
	while (!work_queue->empty())
	{
		PROCESSENTRY32 entry;
		if (work_queue->pop(entry))
		{
			add_process_hashes(entry.th32ProcessID, db, options);
		}
	}
}


void add_system_hashes(databasePE* db, PD_OPTIONS* options)
{

	options->ImportRec = false; 

	Queue<PROCESSENTRY32> work_queue;
	int total_work_count = 0;

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (snapshot != INVALID_HANDLE_VALUE)
	{
		if (Process32First(snapshot, &entry) == TRUE)
		{
			while (Process32Next(snapshot, &entry) == TRUE)
			{
				printf("...adding process to work queue: pid 0x%x,%S\r\n", entry.th32ProcessID, entry.szExeFile);
				work_queue.push(entry);
				total_work_count++;
			}
		}
		CloseHandle(snapshot);
	}

	thread** threads = new thread*[options->NumberOfThreads];
	for (int i = 0; i < options->NumberOfThreads; i++)
	{
		threads[i] = new thread(add_process_hashes_worker, &work_queue, db, options);
	}

	int count = 0;
	bool still_working = false;
	int running_count = 1;
	while (!work_queue.empty() || running_count > 0)
	{
		running_count = 0;
		for (int i = 0; i < options->NumberOfThreads; i++)
		{
			if (WaitForSingleObject(threads[i]->native_handle(), 1) == WAIT_TIMEOUT)
				running_count++;
		}

		if (count % 10 == 0)
		{
			int waiting_count = work_queue.count();
			printf("Hash Queue -> Waiting: %i\tRunning: %i\tComplete: %i\r\n", waiting_count, running_count, total_work_count - (waiting_count + running_count));
		}

		Sleep(50);
		count++;
	}

	for (int i = 0; i < options->NumberOfThreads; i++)
	{
		threads[i]->join(); 
	}


	printf("...cleaning up system memory hashes factory\r\n");
	for (int i = 0; i < options->NumberOfThreads; i++)
	{
		delete threads[i];
	}
	delete[]threads;
}


void dump_process_worker(Queue<PROCESSENTRY32>* work_queue, databasePE* db, PD_OPTIONS* options)
{
	
	unordered_set<unsigned __int64> new_hashes;
	while (!work_queue->empty())
	{
		PROCESSENTRY32 entry;
		if (work_queue->pop(entry))
		{

			n0xDumper* dumper = new n0xDumper(entry.th32ProcessID, db, options, true);
			dumper->dump_all();

			dumper->get_all_hashes(&new_hashes);
			db->add_hashes(new_hashes);
			new_hashes.clear();

			delete dumper;
		}
	}
}


void dump_system(databasePE* db, PD_OPTIONS* options)
{
	Queue<PROCESSENTRY32> work_queue;
	unordered_set<DWORD> dumping_pids;

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	int total_work_count = 0;

	if (snapshot != INVALID_HANDLE_VALUE)
	{
		if (Process32First(snapshot, &entry) == TRUE)
		{
			while (Process32Next(snapshot, &entry) == TRUE)
			{
				printf("...adding process to work queue: pid 0x%x,%S\r\n", entry.th32ProcessID, entry.szExeFile);
				work_queue.push(entry);
				dumping_pids.insert(entry.th32ProcessID);
				total_work_count++;
			}
		}
		CloseHandle(snapshot);
	}

	thread** threads = new thread*[options->NumberOfThreads];
	for (int i = 0; i < options->NumberOfThreads; i++)
	{
		threads[i] = new thread(dump_process_worker, &work_queue, db, options);
	}

	int count = 0;
	bool still_working = false;
	int running_count = 1;
	bool added_new_processes = false;

	while (!work_queue.empty() || running_count > 0 || !added_new_processes)
	{
		running_count = 0;
		for (int i = 0; i < options->NumberOfThreads; i++)
		{
			if (WaitForSingleObject(threads[i]->native_handle(), 1) == WAIT_TIMEOUT)
				running_count++;
		}

		if (!added_new_processes && work_queue.empty() && running_count)
		{
			printf("...adding new processes since we started this job\r\n");
			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
			if (snapshot != INVALID_HANDLE_VALUE)
			{
				if (Process32First(snapshot, &entry) == TRUE)
				{
					while (Process32Next(snapshot, &entry) == TRUE)
					{
						if (dumping_pids.count(entry.th32ProcessID) == 0)
						{
							printf("...adding new process to work queue: pid 0x%x,%S\r\n", entry.th32ProcessID, entry.szExeFile);
							work_queue.push(entry);
							dumping_pids.insert(entry.th32ProcessID);
							total_work_count++;

							if (running_count < options->NumberOfThreads)
							{
								for (int i = 0; i < options->NumberOfThreads; i++)
								{
									if (WaitForSingleObject(threads[i]->native_handle(), 1) != WAIT_TIMEOUT)
									{
										threads[i]->join();
										delete threads[i];
										threads[i] = new thread(dump_process_worker, &work_queue, db, options);
										break;
									}
								}
							}
						}
					}
				}
				CloseHandle(snapshot);
			}
			added_new_processes = true;
		}

		if (count % 10 == 0)
		{
			int waiting_count = work_queue.count();
			printf("Dump Queue -> Waiting: %i\tRunning: %i\tComplete: %i\r\n", waiting_count, running_count, total_work_count - (waiting_count + running_count));
		}

		Sleep(50);
		count++;
	}

	for (int i = 0; i < options->NumberOfThreads; i++)
	{
		threads[i]->join();
	}

	printf("...cleaning up system dump factory\r\n");
	for (int i = 0; i < options->NumberOfThreads; i++)
	{
		delete threads[i];
	}
	delete[]threads;
}






bool global_flag_verbose = false;

int _tmain(int argc, _TCHAR* argv[])
{

	get_privileges(GetCurrentProcess());

	WCHAR* filter = NULL;
	char* processNameFilter = NULL;
	char* clean_database;
	string path = ExePath();
	clean_database = new char[path.length() + strlen("clean.hashes") + 2];
	sprintf(clean_database, "%s\\%s", path.c_str(), "clean.hashes");

	bool flagHelp = false;
	bool flagHeader = true;
	bool flagPidDump = false;
	bool flagProcessNameDump = false;
	bool flagSystemDump = false;
	bool flagAddressDump = false;
	bool flagDumpCloses = false;

	char* add_directory = NULL;
	bool flagDB_gen = false;
	bool flagDB_genQuick = false;
	bool flagDB_add = false;
	bool flagDB_clean = false;
	bool flagDB_ignore = false;
	bool flagDB_remove = false;
	bool flagRecursion = true;


	PD_OPTIONS options;
	options.ImportRec = true;
	options.ForceGenHeader = false;
	options.Verbose = false;
	options.EntryPointOverride = -1;
	options.ReconstructHeaderAsDll = false;
	options.DumpChunks = true;
	options.NumberOfThreads = 16; // Default 16 threads

	DWORD pid = -1;
	__int64 address = 0;

	if (argc <= 1)
		flagHelp = true;

	for (int i = 1; i < argc; i++)
	{
		if (lstrcmp(argv[i], L"-CXnh") == 0)
			flagHeader = false;
		else if (lstrcmp(argv[i], L"-CXnr") == 0)
			flagRecursion = false;
		else if (lstrcmp(argv[i], L"-CXni") == 0)
			options.ImportRec = false;
		else if (lstrcmp(argv[i], L"-CXnc") == 0)
			options.DumpChunks = false;
		else if (lstrcmp(argv[i], L"-CXnt") == 0)
			options.NumberOfThreads = 1;
		else if (lstrcmp(argv[i], L"-g") == 0) {
			options.ForceGenHeader = true;
		}
		else if (lstrcmp(argv[i], L"-pid") == 0)
		{
			if (i + 1 < argc)
			{
				filter = argv[i + 1];

				bool isHex = false;
				wchar_t* prefix = new wchar_t[3];
				memcpy(prefix, filter, 4);
				prefix[2] = 0;

				if (wcscmp(prefix, L"0x") == 0)
				{
					filter = &filter[2];
					isHex = true;
				}
				delete[] prefix;

			
				if ((isHex && swscanf(filter, L"%x", &pid) > 0) ||
					(!isHex && swscanf(filter, L"%i", &pid) > 0))
				{
					// Successfully parsed the PID
					flagPidDump = true;
				}
				else
				{
					fprintf(stderr, "Failed to parse -pid argument. It must be followed by a number:\r\n\teg. 'pd -pid 0x10A'\r\n");
					exit(0);
				}

				i++;
			}
			else
			{
				fprintf(stderr, "Failed to parse -pid argument. It must be followed by a number:\r\n\teg. 'pd -pid 0x10A'\r\n");
				exit(0);
			}
		}
		else if (lstrcmp(argv[i], L"-a") == 0)
		{
			if (i + 1 < argc)
			{
				filter = argv[i + 1];

				bool isHex = false;
				wchar_t* prefix = new wchar_t[3];
				memcpy(prefix, filter, 4);
				prefix[2] = 0;

				if (wcscmp(prefix, L"0x") == 0)
				{
					filter = &filter[2];
					isHex = true;
				}
				delete[] prefix;

				if ((isHex && swscanf(filter, L"%llx", &address) > 0) ||
					(!isHex && swscanf(filter, L"%llu", &address) > 0))
				{
					flagAddressDump = true;
				}
				else
				{
					fprintf(stderr, "Failed to parse -a address argument. It must be followed by a number:\r\n\teg. 'pd -a 0x401000 -pid 0x10A'\r\n");
					exit(0);
				}

				i++;
			}
			else
			{
				fprintf(stderr, "Failed to parse -pid argument. It must be followed by a number:\r\n\teg. 'pd -pid 0x10A'\r\n");
				exit(0);
			}
		}
		else if (lstrcmp(argv[i], L"-p") == 0)
		{
			if (i + 1 < argc)
			{
				processNameFilter = new char[wcslen(argv[i + 1]) + 1];
				sprintf(processNameFilter, "%S", argv[i + 1]);

				flagProcessNameDump = true;

				i++;
			}
			else
			{
				fprintf(stderr, "Failed to parse -p argument. It must be followed by a regex match statement:\r\n\teg. 'pd -p chrome.exe'\r\n");
				exit(0);
			}
		}
		else if (lstrcmp(argv[i], L"-t") == 0)
		{
			if (i + 1 < argc)
			{
				filter = argv[i + 1];

				bool isHex = false;
				wchar_t* prefix = new wchar_t[3];
				memcpy(prefix, filter, 4);
				prefix[2] = 0;

				if (wcscmp(prefix, L"0x") == 0)
				{
					filter = &filter[2];
					isHex = true;
				}
				delete[] prefix;

				if ((isHex && swscanf(filter, L"%x", &options.NumberOfThreads) > 0) ||
					(!isHex && swscanf(filter, L"%i", &options.NumberOfThreads) > 0))
				{
					if (options.NumberOfThreads < 1)
					{
						fprintf(stderr, "Failed to parse -t argument. It must be followed by a number 1 or larger:\r\n\teg. 'pd -system -t 10'\r\n");
						exit(0);
					}
					printf("Set number of threads to %i.\r\n", options.NumberOfThreads);
				}
				else
				{
					fprintf(stderr, "Failed to parse -t argument. It must be followed by a number:\r\n\teg. 'pd -system -t 10'\r\n");
					exit(0);
				}

				i++;
			}
			else
			{
				fprintf(stderr, "Failed to parse -t argument. It must be followed by a number:\r\n\teg. 'pd -system -t 10'\r\n");
				exit(0);
			}
		}
		else if (lstrcmp(argv[i], L"-c") == 0)
		{
			if (i + 1 < argc)
			{
				clean_database = new char[wcslen(argv[i + 1]) + 1];
				sprintf(clean_database, "%S", argv[i + 1]);
				printf("Set clean database filepath to %s.\r\n", clean_database);

				i++;
			}
			else
			{
				fprintf(stderr, "Failed to parse -c argument. It must be followed by a path to the clean file hash database to use.\r\n");
				exit(0);
			}
		}
		else if (lstrcmp(argv[i], L"-o") == 0)
		{
			if (i + 1 < argc)
			{
				char* output_path = new char[wcslen(argv[i + 1]) + 1];
				sprintf(output_path, "%S", argv[i + 1]);
				options.set_output_path(output_path);
				printf("Set output path to %s.\r\n", output_path);
				delete[] output_path;

				i++;
			}
			else
			{
				fprintf(stderr, "Failed to parse -c argument. It must be followed by a path to the clean file hash database to use.\r\n");
				exit(0);
			}
		}
		else if (lstrcmp(argv[i], L"-system") == 0)
			flagSystemDump = true;
		else {
			fprintf(stderr, "Failed to parse argument number %i, '%S'. Try 'pd --help' for usage instructions.\r\n", i, argv[i]);
			exit(0);
		}
	}

	if (flagHeader)
	{
		printf("n0xPE Dumper v1.0\r\n");
		printf("  Copyright © 2018, by n0x\r\n");
	}

	if ((int)flagPidDump + (int)flagProcessNameDump + (int)flagSystemDump +
		(int)flagDB_gen + (int)flagDB_genQuick + (int)flagDB_add + (int)flagDB_clean + (int)flagDumpCloses > 1)
	{
		fprintf(stderr, "Error. Only one process dump or hash database command should be issued per execution.\r\n");
		exit(0);
	}

	if (flagAddressDump && !flagPidDump)
	{
		fprintf(stderr, "Error. Dumping a specific address only works with the -pid flag to specify the process.\r\n");
		exit(0);
	}

	HANDLE h_Process = GetCurrentProcess();
	if (!is_elevated(h_Process))
	{
		printf("WARNING: This tool should be run with administrator rights for best results.\r\n\r\n");
	}

	if (!get_privileges(h_Process))
	{
		printf("WARNING: Failed to adjust token privileges. This may result in not being able to access some processes due to insufficient privileges.\r\n\r\n");
	}

	if (is_win64() && sizeof(void*) == 4)
	{
		printf("WARNING: To properly access all processes on a 64 bit Windows version, the 64 bit version of this tool should be used. Currently Process Dump is running as a 32bit process under a 64bit operating system.\r\n\r\n");
	}



	databasePE* db = new databasePE(clean_database);


	if (flagDB_clean)
	{
		db->clear_database();
		printf("Cleared the clean hash database.\r\n");
		db->save();
	}
	else if (flagDB_add)
	{
		if (flagRecursion)
			printf("Adding all files in folder '%s' recursively to clean hash database...\r\n", add_directory);
		else
			printf("Adding all files in folder '%s' to clean hash database...\r\n", add_directory);

		int count_before = db->count();
		db->add_folder(add_directory, L"*", flagRecursion);
		printf("Added %i new hashes to the database. It now has %i hashes.\r\n", db->count() - count_before, db->count());
		db->save();
	}
	else if (flagDB_remove)
	{
		if (flagRecursion)
			printf("Removing all files in folder '%s' recursively from the clean hash database...\r\n", add_directory);
		else
			printf("Removing all files in folder '%s' from the clean hash database...\r\n", add_directory);

		int count_before = db->count();
		db->remove_folder(add_directory, L"*", flagRecursion);
		printf("Removed %i hashes from the database. It now has %i hashes.\r\n", count_before - db->count(), db->count());
		db->save();
	}
	else if (flagDB_gen)
	{
		printf("Generating full clean database. This can take up to 30 minutes depending on the system.\r\n");

		int count_before = db->count();
		printf("Adding modules from all running processes to clean hash database...\r\n");
		add_system_hashes(db, &options);
		printf("...added %i new hashes from running processes.\r\n", db->count() - count_before);
		db->save();

		count_before = db->count();
		printf("Adding files in %%WINDIR%% to clean hash database...\r\n");
		db->add_folder("%WINDIR%", L"*", true);
		printf("...added %i new hashes from %%WINDIR%%.\r\n", db->count() - count_before);
		db->save();

		count_before = db->count();
		printf("Adding files in %%USERPROFILE%% to clean hash database...\r\n");
		db->add_folder("%USERPROFILE%", L"*", true);
		printf("...added %i new hashes from %%USERPROFILE%%.\r\n", db->count() - count_before);
		db->save();

		count_before = db->count();
		printf("Adding files in 'C:\\Program Files\\' to clean hash database...\r\n");
		db->add_folder("C:\\Program Files\\", L"*", true);
		printf("...added %i new hashes from 'C:\\Program Files\\'.\r\n", db->count() - count_before);
		db->save();

		count_before = db->count();
		printf("Adding files in C:\\Program Files (x86)\\ to clean hash database...\r\n");
		db->add_folder("C:\\Program Files (x86)\\", L"*", true);
		printf("...added %i new hashes from 'C:\\Program Files (x86)\\'.\r\n", db->count() - count_before);
		db->save();

		printf("\r\nFinished. The clean hash  database now has %i hashes.\r\n", db->count());
	}
	else if (flagDB_genQuick)
	{
		int count_before = db->count();
		printf("Adding modules from all running processes to clean hash database...\r\n");
		add_system_hashes(db, &options);
		printf("...added %i new hashes from running processes.\r\n", db->count() - count_before);
		db->save();

		printf("\r\nFinished. The clean hash database now has %i hashes.\r\n", db->count());
	}

	if (flagDB_ignore)
	{
		db->clear_database();
		printf("Ignoring the clean hash database for this execution.\r\n");
	}

	if (flagPidDump)
	{
		n0xDumper* dumper = new n0xDumper(pid, db, &options, false);

		if (flagAddressDump)
		{
			dumper->dump_region(address);
		}
		else
		{
			dumper->dump_all();
		}
		delete dumper;
	}
	else if (flagProcessNameDump)
	{

		DynArray<process_description*> matches;
		int count = process_find(processNameFilter, &matches);

		if (count > 1)
		{
			printf("\r\n\r\nPID\tProcess Name\r\n");
			for (int i = 0; i < count; i++)
			{
				printf("0x%x\t%s\r\n", matches[i]->pid, matches[i]->process_name);
			}

			printf("\r\n\r\nAre you sure all of these processes should be dumped? (y/n): ");

			char* answer = new char[10];
			fgets(answer, 10, stdin);
			if (answer[0] != 'y')
			{
				delete[] answer;
				exit(0);
			}
			delete[] answer;
		}

		unordered_set<unsigned __int64> new_hashes;
		for (int i = 0; i < count; i++)
		{
			n0xDumper* dumper = new n0xDumper(matches[i]->pid, db, &options, false);

			dumper->dump_all();

			dumper->get_all_hashes(&new_hashes);
			db->add_hashes(new_hashes);
			new_hashes.clear();

			delete dumper;
		}
	}
	else if (flagSystemDump)
	{
		dump_system(db, &options);
	}
	else if (flagPidDump)
	{
		n0xDumper* dumper = new n0xDumper(pid, db, &options, false);
		dumper->dump_all();
		delete dumper;
	}
	else if (flagDumpCloses)
	{

		if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler, TRUE) == FALSE)
		{

			printf("WARNING: Unable to install keyboard handler. This means that process dump will not be able to close or cleanup properly.\r\n");
		}

		close_watcher* watcher = new close_watcher(db, &options);
		watcher->start_monitor();

		printf("------> Note: You may cleanly quit at any time by pressing CTRL-C. <------\r\n");

		while (!ConsoleRequestingClose)
		{
			Sleep(100);
		}

		printf("Cleaning up process terminate hooks cleanly...\r\n");
		watcher->stop_monitor();
		delete watcher;
	}

	printf("Finished running.\r\n");

	return 0;
}



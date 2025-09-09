# PEDumper


PE Dumper is a windows reverse-engineering command-line tool to dump some memory components back to disk for analysis. Some software, both benign and malicious, is often packaged and hidden before execution to evade AV scanners. However, when these files are executed, they often extract or inject a clean version of the malware code into memory. Software researchers often use this method when analyzing malware, or when identifying protected software whose contents are unclear or whose purpose is unclear, to transfer the extracted code from memory to disk and scan it or analyze it with static analysis tools like IDA.

Works for Windows 32 & 64 bit operating systems and can dump memory components from specific processes or from all processes currently running. Of course it doesn't work at the protected kernel level so it's a useful tool for ring3.

I remember rewriting this tool about 7-8 years ago, inspired by a similar tool. It worked great on x86 back then, and I recently added x64 support. It still works, but of course, it needs some tweaking as new methods and protections have become available.

Process dump can be used to dump all unknown code from memory ('-system' flag), dump specific processes.

# Usage
Example: dumper -pid 12440 -a 0x1060000 -o c:\dumps\ -CXni

**General Dumping Options**

| Option | Description |
|--------|-------------|
| -system | Dumps all modules not matching the clean hash database from all accessible processes into the working directory. |
| -pid \<pid\> | Dumps all modules not matching the clean hash database from the specified PID into the current working directory. Use a '0x' prefix to specify a hex PID. |
| -p \<regex process name\> | Dumps all modules not matching the clean hash database from the process name found to match the filter into specified PID into the current working directory. |
| -a \<module base address\> | Dumps a module at the specified base address from the process. |
| -o \<path\> | Sets the default output root folder for dumped components. |


**Advanced Options**

| Option | Description |
|--------|-------------|
| -g | Forces generation of PE headers from scratch, ignoring existing headers. |
| -CXni | Disable import reconstruction. |
| -CXnc | Disable dumping of loose code regions. |
| -CXnt | Disable multithreading. |
| -CXnh | No header is printed in the output. |
| -CXnr | Disable recursion on hash database directory add or remove commands. |
| -t \<thread count\> | Sets the number of threads to use (default 16). |


NOTE: I may have removed some things and left it as experimental, sorry about that. You can ignore them or continue developing.
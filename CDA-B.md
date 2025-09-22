## CDA BASIC NOTES
### IMPORTANT INFORMATION TO CONSIDER
- The 10.0.0.0/8 subnet is used for range management and configuration.
- WARNING: Do not interact with this subnet or it may cause an error in the range.There are several files, directories, and processes that are related to normal range operation.
- These items are off-limits and should not be interfered with. If uncovered within the context of an investigation, these items can be safely ignored, as they are not relevant to the investigation.
- systeminit.exe and all files related to this binaryjava.exe listening on port 49999 and 49998
- java.exe communicating over port 5762, 15672, & 27017
- Advanced Message Queuing Protocol (AMQP) listening on port 5672
- Software or files located in C:\Program Files (x86)\Lincoln\
- Software or files located in C:\ProgramData\staging\
- Software or files located in C:\Program Files\Puppet Labs\
- Software or files located in C:\ProgramData\PuppetLabs\
- Software or files located in C:\Program Files (x86)\SimSpace\
- ruby.exe on Windows and ruby on Linux

### OS ARCHITECTURE

<img width="283" height="250" alt="image" src="https://github.com/user-attachments/assets/9e5b1702-5d41-4fa9-8d48-eff0fac7a49a" />

- User Mode vs Kernel Mode
  - User mode
    - Code being executed can only run limited set of safe instructions, cannot directoly access any system hardware
  - Kernel mode
    - code being executed by CPU has unrestricted access to all system hardware
    - includes ability to execute any CPU instruction and access and memory address.
    - Can be dangerous if misused and can cause total system haoult.

- System Calls
  - program running in user mode needs to access system's hardware in order to function, but not allowed to do so
  - Allows user mode application to be temporarily granted high-priv access available to kernel mode.
  - implemented by OS in safe and controlled manner, barring critical software bug in system call code.

- Library calls
  - _Library_ is a software module that implements functionality and makes functionality available to other programs by exposing it through interface.
  - application would call some sort of _create()_ function within library to create network connection, and _send()_ function to send data over connection
  - Main difference is _system calls_ are specifically used to ask OS to perform an action requiring kernel mode execution, while _library calls_ do not perform any actions within kernel mode, and instead abstract away implementation of a task

- Protection Rings
  <img width="555" height="400" alt="image" src="https://github.com/user-attachments/assets/1f6715e6-d686-4b74-ba9a-5d94cedb423f" />
  - Navigating Protection Rings
    - lower-priv rings must use system calls, library calls, or similar mechanisms to access higher-priv resources.
    - device driver running higher-priv ring than application that called it is responsible for safely implementing instructions that allow system to communicate with peripheral device.
    - drivers may need to execute their own calls, some of which may be system calls to move to higher-priv rings and fully perfomr intended function.

### THE KERNEL
- Most modern OSs provide the following capabilities within their kernels:
  - Process managementMemory management
  - File management
  - Peripheral and Input/Output (I/O) device management
  - Security management

### PROCESS MANAGEMENT
- Programs, Executables, processes and Threads
  - _Program_: set of human-readable instructions intended rfor eventual execution on a computer. Referred to as source code
  - _Executable_: known as an _image_ type of file that contains machine instructions that CPU can execute.
    - written in low-level machine language.
    - Process of _compiling_ a program involves translation of human-readable program source code into corresponding machine instructions, saved as executable file.
  - _Process_: instance of a running executable kernel has loaded into memory and started executing.

- Process Structure in Memory
  - During process creation, OS allocates block of memory to be used by that process.
  - All of process's execution of code ops occurs within memory block, divided into 5 main parts: _text, data, Block Started by Symbol (BSS), heap and stack_
    - _Text_: Contains machine instructions loaded from executable. Actual set of instructions executed
    - _Data_: Stores any variables that were _initalized_ by the programmer or compiler.
      - initilization process requires compiler to know how much memory is needed to store variable, as well as initial, non-zero value of varable.
    - _BSS_: Used so store variables that have been _instantiated_ but not initialized.
      - Compiler is able to determine how much memory is needed to store a variable, but program hs not set its value or set it to zero.
    - _Heap_: Used to dynamically allocate memory for variables whose sizes cannot be known until runtime.
    - _Stack_: LIFO data structure used to store stack frames, which contain info about current execution state of the proess.
      - If process has multiple threads, each thread is given own stack.
  <img width="500" height="475" alt="image" src="https://github.com/user-attachments/assets/c5f02a8b-aed0-4917-906c-8d5ee9c7fb58" />

### Lifecycle of a Process
- 5 main states that a process can be in:
  - _Created/New_: Waiting to be loaded into main memory (RAM). OS has not yet allocated resources to the process or beginning to allocate resources
  - _Ready/Waiting_: Fully loaded and is waiting to be scheduled for execution.
  - _Running_: Currently running on one of the CPU's hardware cores, in either kernel mode or user mode.
  - _Blocked_: waiting for an event that is outside of its control to occur.
  - _Terminated/Killed_: Completed its execution, or was keilled by another process or system action.

- Process Termination Complications
  - _Zombie Process_: Until parent reads chold's exit status, child process continues to exist in Terminated state.
  - _Orphaned Process_: child process whose parent process has terminated before it. Can be _adopted_ by new parent process, but not always. Must be specified.

- Process Identifiers
  - When a process is created or _spawning_ OS assigns a PID.
  - PID's are unique only for currently executing processes within a single system.

- Process Trees
  <img width="900" height="500" alt="image" src="https://github.com/user-attachments/assets/b58bcea1-6830-4319-9042-fbf36d457f1e" />
  - Within an OS, processes are never created out of thin air.
  - Daemon Processes
    - Root process is responsible for loading every other process necessary for system to function.
    - Delegates some of these responsibilities by spawning otehr processes known as _daemon processes_, which manage certain componenets across the entire OS.
    - On Windows, Daemons are referred to as _services_





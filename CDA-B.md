# CDA BASIC NOTES
## IMPORTANT INFORMATION TO CONSIDER
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
- Binary paths are **C:\...\.exe**
- TESTING PASSWORD: GreenBayPackers!@#321

# MODULE 1
## OS ARCHITECTURE

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

### Windows Process Genealogy
<img width="600" height="450" alt="image" src="https://github.com/user-attachments/assets/b5c39508-d189-4521-b904-2812acef0ef6" />

### Core Processes | Linux
- Daemon Process in Linux
  - Init and Systemd
    - In Linux systems built on top of System V archtecture, the _init_ process is the root process that initializes the rest of the OS.
    - Typically assigned a PID of 1, but it has been deprecated in favor of _systemd_ process on most modern Linux distributions.
    - Runlevels
      - In legacy systems that use init, _runlevels_ are used to define desired state.
      - Standard runlevels are defined between 0-6, each number defines a different state for the system. (level 6 is reboot)

### Memory Management
- Virtual Memory
  - memory management technique used in order to more effectively manage and secure key system resource
  - During process creation, program and any system libraries it relies on are loaded into virtual memory.
  - When process lter needs to access or change data held in virtual memory, it does so via _virtual memory address_
  - Dedicated MMU translates these into _physical memory addresses_
  <img width="900" height="700" alt="image" src="https://github.com/user-attachments/assets/2d8acd16-092b-400e-8cc4-2e281b37c0dc" />

- Memory Paging
  - In order to accomplish this, the OS must take over managing memory for a process, which offers the following advantages:
    - Memory can be utilized more efficiently across the entire system
    - System security is increased since applications can usually only access their own virtual memory
    - Applications do not need to contain extra code to manage memory themselves
    - Applications can use more memory than the system hardware actually has available
  - Page Files and Swap Files
    - Windows stores all inactive memory pages inside a page file named _pagefile.sys_ located in _C:\pagefile.sys_
    - Linux uses _swap space_ to refer to locations on the disk where inactive memory pages are stored.
    - Two separate spaces exist
      - _swap partition_: special location for swapping operations that is reserved directly by the filesystem
      - Generic Swap files within accessible portions of the filesystem created by system admin to allow for more swap space.

### File Management
- Filesystem internals
  <img width="621" height="286" alt="image" src="https://github.com/user-attachments/assets/7c1074de-b119-4015-9a38-377c70ae8c92" />
  - When the kernel receives a request to access a file, it searches through the filesystem’s directory for the appropriately named file, using the directory to determine the location of that file’s associated record in a record list
- Metadata in Filesystems
  - Stored within a file's record.
  - May include file's physical location on disk, size, any associated permissions, and set of timestamps.
- Virtual Filesystems
  - VFS is abstract layer that lies between client appllications and concrete filesystem.
  - Implemented as a kernel module within OS kernel, and defines common language that client applications and filesystems can use to comm, regardless of specifics of underlying filesystems.

### Types of Filesystems
- File Allocation Table (FAT)

- New Technology File System (NTFS)

- Resilient File System (ReFS)

### Linux Filesystems
- Extended Filesystem (ext)

- XFS

- ZFS

- Index Nodes

- Hard Links

- Symbolic Links

### Network Management
- _Network devices/interfaces_ are specialized hardware peripherals that enable transmission of data btwn 2+ systems.
- In modern systems, basic net interfaces are build directly into system's hardware.
- Sockets
  - Virtual construct that acts as endpoint for comm link on the system.
  - Many sockets can be open at a given time
  - Client application that is running on the system can request socket from kernel, and use system calls to read/write data to socket.

- Socket System Calls (syscalls)
  - _bind_: app requests kernel to bind a previously instantiated socket to a _network port_ or to a local file.
    - Used for communication within local system only
    - must be used if socket intends to listen for incoming connections, and does not need to be used otherwise
  - _listen_: Application puts socket into listening state, meaning client app using socket is actively ready to handle incoming connections.
    - Application must choose to accept connection or terminate it
  - _accept_: App accepts incoming connection to listening socket.
    - does not affect listening socket.
    - mainly used by listening socket wishing to establish a TCP connection, not for UDP.
  - _connect_: Uses socket to establish connection with different listening socket, which may be on local system or on external net.
    - to connect over net to a socket present on external system, socket must reference external system's address, and net port that listening socket is bound ti.
    - Mainly used by connecting socket wishing to make TCP connection to a listening socket, not for UDP
  - _recv or recvfrom_: App reads data from soccket; can be used as shortcut by certain apps that already establieshed connection wht another socket
  - _send or sendto_: App sends data over the socket, which is transmitted to corresponding socket on other end of connection.
  - _close_: closes socket

### Additional Kernel Capabilities
- Peripheral and I/O Device Management
  - modern computers support keyboards, mice, speakers, etc.
  - Generally known as I/O Devices, since they ultimately provide input or output streams.
  - A _Device Driver_ nneds to be installed for each device
  - A process wishing to comm with a peripheral device must use the system's kernel as an interface between the process and peripheral device.
- Security Management
  - Handled by a kernel component known as _security subsystem or security kernel_
  - Can be a portion of the kernel implements basic security procedures within the system.
  - Frequently involved in many other operations that kernel performs.
- Kernel Drivers
  - minimum capability required for a kernel to operate is the ability to facilitate the execution of software instructions on the system’s hardware

### Windows and Linux Architecture
<img width="900" height="425" alt="image" src="https://github.com/user-attachments/assets/07c655dc-0252-477a-b18f-909dc3b2ec76" />

- Windows Architecture
<img width="700" height="900" alt="image" src="https://github.com/user-attachments/assets/e5a449d7-f19a-4089-93c3-019f5216eb11" />

  - User Mode
    - consists of OS-integral subsystems and several environment subsystems designed to support different application environments
  - Kernel Mode
    - Kernel mode has complete access to the system's hardware resources.
    - It is made up of the Executive, the microkernel, any kernel mode drivers, and the Hardware Abstraction Layer (HAL).
    - In Windows, core kernel functions such as multiprocessor synchronization and initializing the system during boot time are contained within the microkernel, which only performs this small set of functions.
    - Additional functionality is implemented into the kernel via the installation and loading of various kernel drivers, several of which come pre-installed with the OS.
    - HAL is used as an interface between the kernel and the actual system hardware.
   
- Linux Architecture
  <img width="711" height="671" alt="image" src="https://github.com/user-attachments/assets/2568a1d1-9d87-4ba6-b233-c8d78e02033c" />

  - Everything is a file
    - many system resources are exposed to the system’s applications via file descriptors.
    - These file descriptors allow other applications to interact with a large variety of different resources
   
### Windows Registry
- Windows OSs make use of a construct called the registry to store system and user configuration information.
- _registry_ hierarchical database that stores information in key:value pairs, persists through system reboots by being saved to the system’s hard disk, quickly referenced by both user mode and kernel mode processes running on the system.
- Information contained in the registry can be secured with a standard set of permissions; create, read, update, and delete permissions can be assigned by the owner of a particular registry key in order to limit others' access to the key.


### Forensic Principals

- Stages of Digital Forensics
  - **Identification** of evidence sources
  - **Preservation** of evidence sources
  - **Acquisition** of data from evidence sources
  - **Analysis** and interpretation of the acquired data
  - **Presentation** of the analysis results

- Chain of Custody
  - strict set of procedures that document all the actions that have been taken involving a particular evidence source during and after its retrieval from a crime scene
  - crucial in order to prove that evidence being presented in court has not been altered or tampered with in any way.
  - Failure to follow chain of custody could entirely invalidate the results of an investigation and subsequent trial, and may lead to the unsuccessful prosecution of an otherwise guilty offender
  - investigators must use a tool called a write blocker to prevent any modifications to the data contained on an original evidence source such as a hard drive or thumb drive.

- File Carving
  -  process of reconstructing files by scanning the raw bytes of a disk, and attempting to piece together the files without the metadata information normally tracked by the filesystem.
  -  requires determining the type of filesystem represented by the data on the disk, then using this knowledge to locate and reconstruct the directory and record list held within the filesystem

### Metadata
- Most common types are:
  - Creation date and time
  - Program or processes used to create the data
  - Data creator or author
  - Technical standards used Location on a device where the data was created
  - File size
  - Data source Data quality
  - File modifications or programs used to modify

- For Windows in NTFS, three Metadata pieces are accessible from _Properties_ tab:
  - **File Created**: The date on which the file was first created on the filesystem.
  - **File Accessed**: The most recent time the file was accessed. Anti-virus scanners and Windows system processes, which frequently interact with files across the entire system, can also trigger this timestamp to update.
  - **File Modified**: The most recent time that the file’s contents were modified.
  - **MFT Last Written**: The most recent time that the file’s record within the MFT was updated. Not included within the standard Windows interface, and necessitates direct inspection of the MFT record, usually via a forensics tool.
 
- Exchangeable Image File Format Data
  - EXIF data can be extemely useful, and can include the below info:
    - Camera make and model used to take the picture
    - Geographical coordinates of where the picture was taken
    - Editing software used to manipulate the picture
    - Image dimensions

- Linux stat command
  - Gives the following Metatdata Information:
    - **Access**: The most recent time the file’s contents were accessed
    - **Modify**: The most recent time the file’s contents were modified
    - **Change**: The most recent time the file’s record was changed within the filesystem
    - **Birth**: The original time the file was created

### File Headers
- Chosen Location, found at beginning of a file, used to store metadata specific to a given file format..
- Portable Executable Format
  - common file format across many types of executable files on Windows systems.
  - The PE format contains a compiled executable program, along with instructions for how the OS should load that program into memory.
  - The most common file types that make use of the PE format are:
    - Stand-alone executables (.exe)
    - Dynamic-link libraries (.dll)
    - Device driver files (.sys)
    - Control panel items (.cpl)
  - PE Structure
    - PE files bgin with following three sections:
      - **DOS Header**: precurso to Windows OS.
      - **DOS Stub**: small program or piece of code executed by default when app execution begins. "This cannot be run in DOS mode"
      - **PE File Header**: contains actual start of PE file, which begins telling OS how to load rest of executable code into memory.

## SCRIPTING PRIMER
- Scrpting Languages Used in this course:
  - **Windows batch files**: usable on all modern versions of Windows. can be a bit limited and awkward from a modern scripting perspective. Used for legacy reasons or for simple tasks.
  - **PowerShell**: .NET-based, cross-platform scripting solution that has native support for remote execution and is deployed by default on modern versions of Windows, and versions of which are deployable on Unix-like platforms
  - **Bash**:  used on Unix-like systems,  can be deployed to Windows systems through Windows Subsystem for Linux (WSL), Cygwin, or other similar tools
  - **Python**: cross-platform, and often installed on Unix-like operating systems as well as being deployed on Windows workstations and servers where it is a dependency.

- Script Editing
  - Below are different edition features to make scripting easier:
    - **Syntax Highlighting**: Changes the color of text to indicate the category of item that is represented by that text.
    - **Autocompletion**: Allows the editor to provide probable completions to the text currently being entered (based upon the syntax of the scripting language in use), which can speed up development.
    - **Debugging**: Allows the pausing of execution of a script or program to view the current state of the environment or manually direct program flow.
    - **Script Execution via Hotkey**: Executes the script being edited via selecting a button or hotkey, allowing for more rapid execution and development.

   - Below are different editors that can be used along with their features:
    - **Notepad**: A simple text editor included in Windows by default; only supports editing.
    - **Gedit**: default editor for Gnome; included by default on some Linux distributions. Supports editing and syntax highlighting for any included languages.
    - **Nano/Pico**: A simple, easy to use command line text editor, commonly available or able to be installed on Unix-like machines. Only supports basic editing, however it may support some syntax highlighting.
    - **PowerShell ISE**: Integrated into some versions of PowerShell; supports all these features and many more, such as block code execution and help files for PowerShell features.
    - **Sublime Text**: supports syntax highlighting for some scripting languages, and limited autocompletion.
    - **Notepad++**: open-source text editor with many features similar to Sublime Text. Supports highlighting for some languages, and supports additional languages via plugins or editing the configuration.
    - **Visual Studio Code**: This editor behaves as a full-blown Integrated Development Environment (IDE) for many languages. It supports many features to assist development, such as syntax highlighting, autocompletion, debugger support, and many hotkeys and configurations to assist development.
    - **Vi/Vim**: While this command line text editor has rich configuration support, if used during this course, it is generally used as a basic text editor.
 
- Execution History
  - Bash's history file is located in `<userhome>/.bash_history`
  - PowerShell — since 5.0 — has a default location at `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
  - PowerShell default location can be changed using `Set-PSReadLineOption` with `-HistorySavepath` option, and location can be displayed using `Get-PSReadLineOption`

### SCript Creation
- When creating or prototyping a script, there are methods to determin best path forward:
  - State the problem clearly. This step is vital to ensure that the correct solution is sought out.
  - Determine a big picture solution to the problem.
  - Break the solution down into individual steps. If unable to do so, reconsider the solution or research as necessary.
  - Determine how to perform each step in the target language, adjusting flow or structure as required based upon feedback here. For steps with many or complex parts, this may require following this process starting back at the beginning for that particular step.
  - Test and deploy the script.
  - Clean up and/or revise as necessary.
- When creating scripts, _pseudocode_ is importatnt to understand what you are doing. This code is a plain text description of each step.

- Common Language Features
  - Data Types:
    - String: This data type consists of individual characters, often laid out sequentially in memory
    - Integer: Whole numbers only
    - Array: Also known as lists in a scripting context,
    - Float: Numbers with decimal points
    - Boolean: True or False
  - Variables:
    - Allows storage of a value, and then overwrites value if needed.
  - Input/Output
    - Console: The console can often be read from or written to.
    - File: Scripting languages can often read from or write to files.
    - Registry: Scripting languages on Windows may be able to read or write to the registry.
    - Databases: Some scripting languages support reading or writing to or from databases, or external binaries may be usable to perform the same operations.
    - Command Line Arguments: Many scripting languages allow command line arguments to be read, and command line arguments can be supplied to other scripts or applications.
    - Network: Scripting languages can allow a script to connect to other machines via networking to send or receive data. This can take the form of Hypertext Transfer Protocol (HTTP) requests, Transmission Control Protocol (TCP) connections, or other lower-level connections. This is useful for downloading software to deploy. Threat actors may also use this functionality to establish remote shells by connecting to a remote machine that issues commands.
  - Loops/Iterations
    - For loop: iterates a specific number of times
    - While/Do Loop: iterates while a specified condition is met. Can be written as do..until
  - Branching Logic
    - If/Else: performs the else statement if the "if" statement is not met.


## NETWORKING REVIEW

### OSI Model Layers and Devices

<img width="576" height="1000" alt="image" src="https://github.com/user-attachments/assets/85f86019-a378-459a-b6a5-86f6757661e4" />
  
  - **OSI Model**: describes and standardizes functions and characteristics of communications across various devices, media, and abstractly between applications.

- Implementations use encapsulation to wrap higher-level layers in order to transmit over physical medium.
- Concepts of OSI model are helpful for breaking down how comms should happen, but don't always translate into implementation solutions that are as clearly defined.
- `Data Link Layer`: handles frame addressing and the transmission/receiving of bits across the medium.

  <img width="587" height="273" alt="image" src="https://github.com/user-attachments/assets/2b4c0548-a8c5-4b81-b455-528b57d0cf24" />

- OSI Layer 2 Devices
  - Devices that operate on layer 2 stack, perform switching ops on frames.
  - Each frame contains addressing associated with a hardware NIC (DMAC and SMAC), an indicator of the next protocol, and data being sent.
  - Most standards include a preamble and checksum (FCS) to detect errors that may have been introduced during transmission of the frame.
  - Most common devices at this layer are **Switches**, and **Bridges**
  - Both of these devices include a MAC address table, known as a Content Addressable Memory (CAM) table, that tracks which MAC addresses are associated with each port on the switch
  - Layer 2 devices rely on broadcasts and the SMAC from transmitted frames to build the MAC address table.
  - **Bridges** operate in the same manner as **switches**, but are used to connect **two or more different transmission medium**, linking them together into an aggregate network.
  - A **WAP** that has a **hard-wired connection** as well as **wireless** is usually operating as a bridge as well — linking the Radio Frequency (RF) medium with the electrical or optical medium other devices may operate on.
 
#### MAC ADDRESS TABLE EXAMPLE
<img width="363" height="268" alt="image" src="https://github.com/user-attachments/assets/b5b5c6b6-6d29-48fd-8a3f-e2f252400bf4" />

  - When a frame reaches a switch, if the DMAC does not match a known MAC address in the CAM table, the switch forwards a copy to all ports/paths to attempt to reach the addressed device.
  - Layer 2 devices separate _collision domains_. **Collision domains** can be compared to communications with a two-way radio where only one person can talk at a time.
  - If more than one person — or device on the physical medium — tries to talk at the same time, the communications collide and is lost for all parties.
  - A DMAC of FFFF:FFFF:FFFF (Layer 2 BROADCAST ADDRESS) is forwarded to all ports/paths by all layer 2 devices, except the port it was received on. `_Do not confuse this with Layer 3 Broadcast address._`

- Spanning Tree
  - Multiple layer 2 devices may be connected together in such a manner that loops could be created.
  - To prevent an overwhelming amount of transmitted frames — also known as a **broadcast storm** — most layer 2 devices use a protocol like **STP** to identify themselves to the other devices they may be connected to.
  - Layer 2 protocols do not have a TTL value to indicate when a frame should no longer be forwarded
  - Through the use of STP, certain ports that are redundant or cause loops may be put into a **blocking state** to prevent loops and broadcast storms.
  - This blocking port prevents the switch from forwarding out broadcasts on that port.
  - STP has an election process where one device is designated as the **Root Bridge**. The lowest cost — or shortest path — to the Root Bridge determines if a port is designated as **forwarding** or **blocking**. There are additional states like **Listening** and **Learning** to allow for faster topology changes and to update MAC address tables. The lowest cost path from a switch’s port to the **Root Bridge** is designated to be a **Root Port**.
  - A **designated port** is a port on a switch with the lowest cost on a specific LAN segment to the root bridge.
  - Each vendor has their own implementation of the standard, which operates slightly differently, but the end result is to create a logical layer 2 topology that prevents switch loops and duplicate frames.
  - STP introduces a large amount of extra traffic on network segments as it has a very frequent update interval to check/verify if any loops still exist so it can make the appropriate changes to both allow traffic and prevent loops.
 
### Layer 3 Devices
- Devices that operate on layer 3 operate on packets.
  <img width="706" height="631" alt="image" src="https://github.com/user-attachments/assets/1810b5cd-eb4c-4eeb-a54b-59fec4e061c2" />

- IP Network Components
  - IP Networks have several components and terms:
    - **Network Identifier** (ID) (also sometimes known as subnet ID): # of bits of an IP address that designates the network on which a host resides — also the base IP address in a network
    - **Host ID**: # of bits of an IP address that designates the host within its network
    - **Subnet mask**: Mask that specifies which bits are network (binary one) and which bits are host (binary zero)
    - **Broadcast address**: Last IP address within a network that is reserved to address all hosts in the same network
    - **Gateway** (also known as next-hop): IP address assigned to a layer 3 device — router — that connects multiple networks together and can route packets between them
    - **Default gateway**: Layer 3 device used for routing when there is not a more specific gateway specified in the routing table
  - Configured gateway is not required for a host to comm won local net, but is required to comm with other networks.

  - Public and Private IP Addresses
    - **IANA** is responsible for defining and apportioning IP addresses
    - IANA apportioned large blocks of IP addresses to Regional Internet Registries (RIR) who then assign IP address ranges to large organizations.
    - Typically these are registered to very large organizations, governments, and ISP. The owners of the IP address ranges use them as needed for their networks.
    - Due to the shortage of public IPv4 addresses, IANA reserved several network ranges and designated them for private use, and use NAT to communicate with public addresses.
    - This allows a network to have virtually unlimited private hosts and translate them to a much smaller range of public IP addresses for use on the internet.

<img width="963" height="1034" alt="image" src="https://github.com/user-attachments/assets/d6595ddc-ee04-46d8-85b0-013fd37a3319" /> 

### DHCP
- IP addresses can be assigned statically or requested dynamically.
- DHCP (UDP 67 for servers and 68 for clients)
- DHCP ops fall into four stages: (DORA)
  - DHCP server Discovery
    - When client needs IP address and is configured to use DHCP, it broadcasts discovery request using destination IP `255.255.255.255` and DMAC `FFFF.FFFF.FFFF.FFFF`
  - IP address lease Offer
    - When the server receives a discovery request, it reserves an IP address out of its pool of addresses and makes a lease offer to the client.
    - The offer is sent unicast, directly to the client’s MAC address and includes the offered IP address as the destination IP address.
    - The DHCP message includes the client's MAC address, the IP address the server is offering, the subnet mask, the lease duration, and the IP address of the DHCP server.
  - IP address lease Request
    - Once the client has received the offer from the DHCP server, the client again sends a broadcast packet to actually request the IP address offered.
    - The client request also includes any options — or additional configuration settings — the server may be able to provide, including default gateway, DNS servers, and Network Time Protocol (NTP) servers.
  - IP address lease Acknowledgement
    - DHCP server sends an acknowledgment directly to the client with the full details of the lease


### Subnet Review

- IPV4
  - Classless inter-Domain Routing (CIDR)
    <img width="962" height="522" alt="image" src="https://github.com/user-attachments/assets/d21e3830-196d-4639-9aba-a6268689ab39" />
    
    <img width="963" height="1895" alt="image" src="https://github.com/user-attachments/assets/f8eafdee-905a-4d4c-8910-8bfe45fb01ea" />

  - Run the following commands to see CIDR and IP range:
    - Network ID and CIDR for specified IP: `netmask 199.63.64.51/255.255.255.0`
    - range of IP addresses for a network: `netmask -r 199.63.64.51/24`
   
- IPv6
  - IPv6 uses 128-bit addresses, represented in hexadecimal notation.
    
    <img width="305" height="162" alt="image" src="https://github.com/user-attachments/assets/559c8eec-b7e8-4504-bafc-3e4418a39cb7" />

  - Can be shortened in certain circumstances for clarity and readability:
    - One or more leading zeros from a group of hexadecimal digits can be removed (e.g., :0042: is shortened to :42:)
    - Consecutive sections of zeros are replaced by two colons (e.g., 2001:0db8:0000:0000:0000:ff00:0042:8329 is shortened to 2001:0db8::ff00:0042:8329)
    - With both rules in place, 2001:0db8:0000:0000:0000:ff00:0042:8329 is shortened to 2001:db8::ff00:42:8329.
   
### NAT/PAT REVIEW
- Allows networks to use limited number of public IP addresses to isolate and translate between private IP addressing space and public IP addresses to comm with hosts on internet.
- NAT is intended as 1-for-1 priv-to-public address translation.
- PAT uses combo of inside IP address and inside source port to build translation table.
  
  <img width="719" height="223" alt="image" src="https://github.com/user-attachments/assets/8c1286f1-e0c2-4c6d-a094-0b421eddb5a4" />

  <img width="671" height="338" alt="image" src="https://github.com/user-attachments/assets/d2c92317-72bd-4d2f-9c5f-c5ac19f5a516" />


### VLAN

<img width="1500" height="591" alt="image" src="https://github.com/user-attachments/assets/36ef1ba9-17cd-423f-ae9e-776d2d89f116" />

- VLANs have several advantages over traditional network configurations, including: performance, reduced administrative burden, reduced cost, security, and logical workgroups.
- Multiple traditional networks can exist on a single switch, which reduces the number of devices an admin group has to manage and purchase.
- Switches can perform VLAN switching at a higher speed than a router since they do not have to read as much of the frame/packet in order to make a decision about where to send the data.
- A common use for VLANs is to segregate the management protocols that network devices use for dynamic switching and routing updates from the rest of the user data that traverses a network.
- VLANs are a way to separate hosts on the same physical network — layer 2 — into two or more logical networks.
- Each VLAN has its own broadcast domain and communication between two VLANs require a router that is connected to both networks.
- Specific ports on a switch can be designated to a specific VLAN, known as **VLAN tagging**.
- VLANs are described by multiple standards, primarily based on IEEE standard 802.1Q.

# MODULE 2

## Operations Process
### Policies, Procedures, and Regulations
  - Title 10: outlines the role of the armed forces and military operations. It provides the legal basis for the roles, missions, and organization of each of the services as well as the DoD
  - Title 50: outlines the role of war and national defense.
    - Title 50 governs many different activities in support of national defense, however in regard to CPT operations it provides guidance as to the manner in which intelligence gathering efforts may be carried out
  - Title 32: outline the role of reserve force military ops.
<img width="1590" height="366" alt="image" src="https://github.com/user-attachments/assets/b1046e91-df58-4774-99a0-58cd2ad499e6" />

### Operations Process

<img width="1564" height="982" alt="image" src="https://github.com/user-attachments/assets/f59208c4-aaa9-4246-9f55-5430ee438fe4" />

- Step 1: Objectives, Effects, and Guidance
  - Genereates high-level obj. that the CPT attempts to achieve in course of thier mission.
  - CWP States:
    - The first step of the OP is Objectives, Effects, and Guidance. When conditions or requirements trigger a CPT mission, the operational planning section determines the appropriate CPT functions and capabilities before developing preliminary objectives, intended effects, and commander’s guidance. The operational planning section is also responsible for assessing existing command relationships and making recommendations for potential additions or changes to facilitate and enable the CPT mission.
  - These details are communicated in a Planning Order (**PLANORD**) followed closely by a Tasking Order (**TASKORD**). That **TASKORD** should clearly communicate intent and requirements to ensure the operational level planning element, CPT, and supported command have necessary information to drive accurate and effective CPT mission planning.

<img width="1564" height="586" alt="image" src="https://github.com/user-attachments/assets/1d2fa077-3e87-4a8e-9e59-015b39537366" />

  - Three triggers for CPT operations:
    -  Threat Intelligence: A Threat Intelligence report or warning may trigger CPT hunt, clear, enable hardening, and assessment functions.
    -  Campaign Plan: CPT employment, in support of Combatant Command (CCMD) campaign plans, increases critical asset protection prior to operational need.
    -  Detect (MCA): Whether discovered by local network protection assets, network owners, or indicated by threat intelligence reporting, CPT hunting and clearing entails conducting recon/counter-recon on supported commanders’ networks or systems to gain and maintain contact with an adversary, or further develop a situation.
   
-  Step 2: Terrain ID and Prioritization:
  - Identifies key network terrain and determines which areas should be prioritized.
  - CWP States:
    - Terrain Identification and Prioritization defines mission scope as it pertains to initial objectives, intended effects, and commander guidance. Analysis of the supported organization’s mission and resources during Mission Analysis (MA) will result in validation and assessment of Mission Relevant Terrain in Cyberspace (MRT-C), and assessment of the local network or system security. MRT-C assessments are based on, and conducted in conjunction with, the mission owner’s detailed understanding of their network terrain. Although not a standalone CPT function, a prerequisite to successful CPT missions is the ability to validate or verify mission owners’ identification, enumeration, and characterization of the protected networks, systems, or assets to ensure an accurate common operating picture and identify specific terrain in cyberspace.

<img width="1564" height="750" alt="image" src="https://github.com/user-attachments/assets/65f38c36-3053-4c95-91c8-ae3db93a0989" />

  - Actions taken during this step include CPT receipt and analysis of the supported organization’s network diagrams, terrain information, and configuration documents as per the TASKORD. If these documents do not exist, gather basic network maps and terrain information in conjunction with the mission partner during the following activities:

- Mission Analysis
  - CPT plays important role in MA process.
  - During MA, CPt conducts technical survery, site survey, terrain mapping and analysis, and adversary analysis.
    - Technical Survey
      - purpose of the survey is to identify MRT-C.
      - This identification process assists leaders in understanding how the supported commander’s organization relies on cyberspace.
      - The outputs of MA determine which areas of the network are mission essential.
      - MA also aids in understanding which parts of the supported commander’s network, if disrupted, seized, or lost, risks operational culmination or mission failure (CWP 3-33.4).
    - Site Survey
      - The CPT conducts a site survey with a focus on understanding the supported organization’s mission statement, mission essential functions and priorities, and meeting with key leadership (CWP 3-33.4). The site survey includes a leader’s reconnaissance by the CPT, mission element, or crew lead, or other designated CPT leader, to secure necessary information, assess requirements and challenges, and broker relationships prior to the operation (CWP 3-33.4).
    - Terrain Mapping and Analysis
      - The mission partner and the CPT work together to conduct terrain mapping and analysis.
      - Appendix B of CWP 3-33.4 states, A detailed logical network map is the CPT’s foundational visualization tool, must scale appropriately to the situation, and will guide CPT internal planning and mission conduct (CWP 3-33.4).
      
      <img width="1224" height="1508" alt="image" src="https://github.com/user-attachments/assets/692e7929-9db8-42ec-b695-cbe7036b35e0" />

    - Adersary Analysis
      - Adversarial analysis is used to determine adversarial intent relative to specific terrain by evaluating the adversary’s capabilities and limitations, current situation, patterns of operation, and observed Tactics, Techniques, and Procedures (TTP) (CWP 3-33.4).
      - The construction of a model portraying how the adversary normally executes operations, or how the adversary previously reacted to specific situations in the past helps guide the development of indicators and analytics based on anticipated or expected adversary courses of action (CWP 3-33.4).

        <img width="1530" height="808" alt="image" src="https://github.com/user-attachments/assets/09392251-a9c6-4989-978e-9421d1258f26" />

- Step 3: Capability Analysis and Force Allocation
  - Outlines the capability analysis and force allocation of activities internal and external to the CPT.
  - CWP States:
    - The CPT analyzes the PLANORD or TASKORD, MA results, MRT- C, and the supported commander’s existing risk management, mission defense, and incident response plan(s), if available. Using the PLANORD or TASKORD, the CPT develops a tactical mission statement and end state, defines initial tactical objectives, and determines initial capabilities for the mission. The CPT coordinates with the Operational Planning section and supports the commander’s staff to coordinate mission rules of engagement (ROE) informed by the initial capabilities analysis. ROE in the context of CPT operations refers to the constraints and limitations under which the CPT hunts and/or clears when MCA is encountered as agreed on by the supported network owner and the supporting commander. For example, the CPT needs to know if they are allowed to employ agent-based solutions, deploy compiled code to hosts, or interrupt service(s) during mission conduct. CPT leadership also conducts a troops-to-task assessment to determine personnel requirements based on mission scope and scale.

<img width="1490" height="1140" alt="image" src="https://github.com/user-attachments/assets/9ff068a8-5961-4b32-9593-c0bfe1e8c492" />

  - Force Availability, Selection, Preparation
    - Once CPT MA is completed, CPT forces are examined to determine mission accopmlishemnt capability.
    - The scope of the proposed mission and other on-going CPT requirements factor into mission element and crew selection.
      - Specifically, CPT leadership examines the team members’ experience, proficiency, and training levels, as well as administrative readiness status against the number of personnel required to complete the mission as determined during CPT MA.
    - The scope of the terrain and operational-level mission completion date drive the number of personnel required. Once selected, personnel prepare for mission execution.
    - The CPT also analyzes available equipment based on locally protected network or system configurations to determine necessary hardware and applications.
    - This step also includes assessing the potential for on-site or remote operations, and selecting equipment and hardware to enable mission conduct across multiple domains or classification levels.

- Step 4: Orders Production and Dissemination
  - defines the order production process and provides the manner in which orders are disseminated.
  - CWP States:
    - During the Orders Production and Dissemination, the operational-level orders production team receives the final outputs from the capability analysis and force allocation. Outputs are developed into a formal operations order or TASKORD (or service specific mission type order). The Operational Control (OPCON) headquarters’ **Operational Planning section** maintains the responsibility to develop and publish orders (including coordinating or special instructions, or similar guidance) to direct and guide CPT operations. Once produced, the final order and special instructions are published and disseminated to the CPT for action; to the supported commander if a formal command relationship exists; or as a courtesy copy to the supported commander if a formal command relationship does not exist.
  - Once the order is pubhishedl, OP section retains responsibility for coordinating logistics, systems access, CPT workspace, power for CPT equipment, and administrative-level credentials to MRT-C with the supported commander
  - Due to the lengthy process associated with coordinating system access and logistics, this action is initiated in this stage of the CPT operations process to mitigate, prevent, or minimize delays to CPT mission execution.
  - Organizations to whom CPTs are OPCON with no operational or tasking control authority over the supported commander or organization must communicate with the relevant authority to coordinate, synchronize, and deconflict required support or actions required by the supported organization to enable CPT mission execution.
  - Coordination and deconfliction may be required with one or more operational-level planning elements.

- Step 5: Tactical Planning and Mission Execution
<img width="1496" height="1004" alt="image" src="https://github.com/user-attachments/assets/fc054938-1fc3-48c8-8733-f853f6c1385f" />

  - outlines the contents of a tactical mission plan and directs members through the mission execution phase
  - CWP States:
    - Tactical Planning and Mission Execution is largely the responsibility of and conducted by the CPT. Depending on operational-level requirements and internal CPT process, the CPT may generate a Tactical Mission Plan document. This document takes the form of an informational briefing or report for CPT operators or the mission partner. This tactical plan may be shared with the Operational Planning section.
  - CPT tactical mission plan normally:
    - Articulates tactical objectives and tasks
    - Pairs capabilities to tactical tasks
    - Finalizes sensor placement schemes
    - Establishes a data collection and sensor management plan
    - Establishes (tactical) mission phases
    - Develops contingencies
    - Develop tactical assessments
    - Establishes contracts
    - Establishes the communications plan.
  - Coordination with the mission partner is common during planning and leading up to execution depending on the mission tasking and ROEs
  - During this step, the supported commander and local network protection personnel provide the CPT access to their terrain in cyberspace
  - The OP section must verify CPT access to the supported organization’s protected network(s) or system(s) directed (or required) in the PLANORD or TASKORD published in the Objectives, Effects, and Guidance step, and the order published in the Orders Production and Dissemination step.
  - Following the completion of tactical planning, the CPT executes the mission plan.
  - CPTs may conduct daily briefs or huddles prior to operational commencement, and may conclude daily operations with a debrief.
  - Duration of the mission tasking, new Fragmentary Orders (FRAGORD) from the OP section, entering a new phase or contingency operation, or new intelligence may drive the CPT to conduct further mission planning during mission execution.

- Mission Execution Outputs
  - CPT may generate routine Situation Reports (SITREP) during mission execution.
  - additional reports may be required or generated by the CPT during the mission or at mission conclusion.
  - Daily, weekly, per-phase, or other reports may be generated when requested or as required.
  - Upon completion of a mission phase, or at mission conclusion, the CPT conducts assessment of tactical objectives and tasks.
  - Tactical Measures of Effectiveness (MOE) and Measures of Performance (MOP), as well as collected data requested by the operational-level collection plan, are submitted to the OP section in preparation for the next phase, or to enable operational assessments by the OP section.
  - If tasked, the CPT develops a Risk Mitigation Plan (RMP) following mission execution and submits it to the OP section.
    - The RMP is also furnished to the supported commander at mission conclusion.

- Step 6: Assessment
<img width="1134" height="1040" alt="image" src="https://github.com/user-attachments/assets/50a5b62a-1623-4f7c-b75b-4309eb9f1705" />

  - OP section assessment team analyzes MOPs to determine whether operational tasks were satisfied to create desired effects, and analyzes MOEs to determine whether creation of desired effects achieved operational objectives
  - OP section assessment team reviews data and information reported by the CPT in accordance with the operational assessment plan
  - Additional inputs from the CPT, the supported organization, and potentially the intelligence community may be used to facilitate accurate operational assessments.
  - As a result of operational assessments, the OP section may make recommendations for future actions.
  - These actions may include, but are not limited to
    - additional hardening of the supported commander’s networks and systems
    - recapitalization or redesigning part or all of MRT-C
    - deployment of the CPT to other portions of a supported commander’s network, system, or asset not covered in the current mission
    - CPT redeployment based on other priorities, contingencies, or crises.
  - When permissible, and where feasible, products developed during all steps should be added to the Joint Lessons Learned System (JLLS) to enable future assessments and planning.

## CAPABILITY ANALYSIS

### Capability Analysis Overview
- CPT Capability Analysis and Force Allocation step involves determining the mission capabilities of each element.
- The elements included in this process are the **CPT**, **mission partners**, and the **operational planning section**.
- This consists of the following stages:
  - Capability planning
  - Force availability, selection, preparation
  - Force presentation and available effects
  - Objectives, effects, and guidance refinement
  - Course of action development
  - CPT Rules of Engagement (ROE) development
  - Assessment plan
  - Service interruption coordination
  - Operational Impact Validation (OIV)

- Capability Planning
  - CWP 3-33.4, Appendix A:
    - CPTs must analyze the following:
      -  Planning Order (PLANORD)
      -  Tasking Order (TASKORD)
      -  Mission Analysis (MA) Results
      -  Mission Relevant Terrain in Cyberspace (MRT-C)
      -  Supported commander’s risk management, mission defense, and incident response plans (if applicable)
  - Using the PLANORD or TASKORD, the CPT develops a tactical mission statement and a projected end state, defines initial tactical objectives, and determines initial capabilities for the mission
  - The CPT will coordinate with the operational planning section and support the commander's staff to coordinate mission rules of engagement (ROE) informed by the initial capabilities analysis.
  - ROE in the context of CPT operations refers to the constraints and limitations under which the CPT will hunt and/or clear when MCA is encountered as agreed on by the supported network owner and the supporting commander.
  - By adding enriching data and graphical control measures to **network maps** produced during the previous step, the CPT further improves terrain visualization during planning and operations to enable a **common operating picture** to emerge, and create shared situational awareness between the CPT, the supported commander, and local network protection assets.
  - The **network map** forms the basis of the CPT’s visualization tools and must scale appropriately to the situation.
  - As a critical input, the **network map** forms the foundation on which courses of action are developed based on the operational approach and analytic scheme of maneuver employed by the CPT.

- Force Availability, Selection, and Preparation
  - Once MA is completed, available CPt forces are examined to determine mission accomplishment capability.
  - The scope of the proposed mission and other on-going CPT requirements factor into mission element and crew selection
  - CPT leadership examines the team members’ experience, proficiency, and training levels, as well as administrative readiness status against the number of personnel required to complete the mission as determined during CPT MA
  - The **scope of the terrain** and **operational-level mission completion date** drive the **number of personnel required**
  - The CPT also analyzes available equipment based on locally-protected network or system configurations to determine necessary hardware and applications.
  - This step also includes assessing the potential for on-site or remote operations, and selecting equipment and hardware to enable mission conduct across multiple domains or classification levels.

- Force Presentation and Available Effects
  - Once ME crews and required equipment are determined, CPT leadership presents options to **operational planning section** including:
    - Tradecraft needs, constraints, or limitations
    - Desired noise levels
    - Accessing or forwarding logs
    - Use of native tool sets during the mission
    - Inclusion of local network protection personnel during the mission

- Objectives, Effects, and Guidance Refinement
  - If MA by the operational planning section or CPT determines the CPT is unable to achieve all objectives or create all desired effects as articulated in the PLANORD, the operational planning section is responsible for refining objectives and desired effects in coordination with the supported commander and CPT.
  - Changes to or evolution of mission terrain during planning also necessitates adjustment of objectives and desired effects based on available personnel and equipment.
  - Finally, commander’s guidance may require adjusting or refining if changes to objectives, tasks, or desired effects change.

- COA Development
  - COAs describe operational approaches and provide options to achieve the mission end state
  - COA describes who takes action, what type of action occurs, how the action occurs, when and where the action takes place, and why the action is required
  - Products from COA development present alternatives including sketches allowing COA visualization by higher ranking and supported headquarters’ commanders and planners.
  - COAs should envision the employment of all participants and take into account operational limitations, logistical considerations, and conclusions drawn by local or regional network protectors or CSSPs
  - Critical to this step is considering potential or expected adversary COAs likely to affect achieving objectives and desired end states.
  - transition from MA to COA development should identify decision points, the person responsible for making the decision, and measures available to provide leaders with additional time before making a decision.
  - Decision points may be based on the analytics implementation, sensor placement, the establishment of Named Areas of Interest (NAI) or engagement areas, or additional Priority Intelligence Requirements (PIR).
  - A well-developed COA provides identity points in time when options, or the COA itself, is no longer viable based on predetermined criteria or conditions.
 
- ROE Development
  - operational planning section and supported commander, advised by the CPT, develop the CPT mission ROE, constraints, and restraints
  - Effects from CPT hunt and clear operations may potentially disrupt or degrade MRT-C performance
  - critical the CPT continually advises all parties involved regarding capabilities to be employed, and possible unintended or cascading effects
  - Actions CPTs can or cannot take should also be defined in the ROE
  - During hunt, clear, and enable hardening missions it is often difficult, or sometimes impossible, to clear MCA or harden terrain without some degree of service interruption.
 
- Assessment Plan
  - responsibility of the **operational planning section** to effectively assess the CPT mission
  - validates the CPT plan by outlining Measures of Performance (MOP) for operational tasks and Measures of Effectiveness (MOE) for operational objectives and desired effects, and can also prove the engagement area in a deliberate defense
  - outlines information collection requirements to enable reporting, and must include external assessment information collection requirements
  - disseminated to the CPT and supported by the commander during the final order published during the next step of the CPT operations tasking process.
  - Operational-level assessment is not performed by the CPT
 
- Service Interruption Coordination
  - necessary for the deployment of passive network taps as well as any in-line, network-based capabilities, such as intrusion prevention or encrypted traffic decryption capabilities
  - Additional service interruptions may be coordinated for configuration changes within the MRT-C to enable CPT operations, such as:
    - deployment of agent-based capabilities
    - whitelisting CPT applications and scripts
    - modifying Group Policy Objects (GPO) to enable remote access for CPTs
    - enabling event log forwarding
    - modifying network configurations
      - assigning IP space to the CPT
      - modifying routes
      - creating span ports
      - adding Media Access Control [MAC] addresses to port security configurations
    - turning on NetFlow
  - Service interruptions required to deploy CPT capabilities are planned and scheduled by the operational planning section in coordination with the supported commander and the CPT.
 
- Operational Impact Validation
  - OIV verifies:
    - impact of bservice interruptions to the supported commander’s protected networks or systems
    - validates CPT capabilities creating desired effects on mission partner systems from unintended or cascading effects
    - captures representative data sets enabling follow-on tactical planning
  - Critical to OIV conduct is the CPT’s knowledge and understanding of the supported commander’s protected networks as a result of MA and Terrain Mapping and Analysis outputs.
 
### Mission Capabilities and Requirements
  - CPTs provide commanders with three Capabilities:
    - Discovery and Counter Infiltration (D&CI)
      - detection, illumination, and defeat of known or unknown threats within a secured network or system
      - To be successful with missions involving D&CI capabilities, CPTs should have clear PIR and supporting Essential Elements of Information (EEI) to drive collection requirements and efforts.
    - Cyber Threat Emulation (CTE)
      -  process of using known adversary TTP to replicate real-world threats to train and measure the effectiveness of cybersecurity defenses
      -  This capability is primarily associated with DoD red teams to highlight vulnerabilities and demonstrate operational impact for the purpose of improving cybersecurity postures.
      -  In contrast, CPTs typically employ CTE to validate defensive postures rather than to find vulnerabilities.
    - Threat Mitigation
      - CPT provides a comprehensive review of the mission partner’s MRT-C with a focus on threat TTPs
      - CPTs assess secured network cybersecurity posture and processes to identify specific threats in vulnerable areas and to provide mitigative measures.
      - CPTs then provide a Risk Management Plan (RMP), which documents recommendations for internal and external mitigative actions to supported mission partners.
     
### Data Collection Plans
- Gathering Collection Requirements
  - Before data can be collected, CPt must know what data collection requirements are.
  - This is mission-dependent and can vary across different mission sets
  - Defining data collection requirements requires:
    - the ability to identify gaps in currently collected data
    - determine what data needs to be collected
    - and know where that data can be found.
  - Data can be collected from several locations including:
    - endpoints
    - networks
    - databases
    - open-source data
  - This knowledge is valuable for defining and scoping collection efforts.
 
- Data Collection
  - Data can be collected actively, passively, or from open-source information
  - Active data collection involves generating new data that does not already exist (I.E running a port scan)
    - Examples of tools used for Active data collection:
      - **Kali Linux**: An open-source, Debian-based Linux distribution aimed at advanced penetration testing and security auditing.
        - It comes with several active scanning utilities pre-installed.
      - **Nmap**: A free and open-source utility for network discovery and security auditing. Nmap also comes installed by default on Kali Linux.
      - **RedSeal**: A security solution that provides risk assessment, compliance auditing, and network visualization of both private network resources and resources located in the cloud.
  - Passive data collection data that is automatically generated or collected without user intervention, though it may require some initial configuration to set up passive data streams
    - Examples of data that is passively collected include:
    - log entries
    - net flow data
    - packet captures
  - **Network sensors** are especially essential for passive data collection
  - CDAs can determine whether there is sufficient data collection coverage within a network by using **DeTT&CT**, a knowledge base created for network defenders to score and compare data log source quality, visibility coverage, and detection coverage against known threat actor behaviors.
  - Open-source data is data that is publicly available
    - A good open-source resource for adversary TTPs is MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK), which is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.
    - DeTT&CT maps detection capabilities to MITRE ATT&CK techniques.

# MODULE 3
## HUNT

### CWP and CPT Threat Hunting
- Threat hunting is one of the four core functions of a CPT.
- Chapter 3 section 2 of the CWP defines hunting as `the process of proactively and iteratively searching through networks to detect evidence of Malicious Cyberspace Activity (MCA) to gain and maintain contact with an adversary and develop the situation.`
- Important quotes from CWP:
  - Where traditional cybersecurity is passive or reactive, CPT hunt operations take the fight to the enemy by proactively searching out, identifying, disrupting, and defeating threats resident in networks and systems. (2.a.1)
  - Knowledge of adversary presence is not a prerequisite for the conduct of CPT hunt operations. (2.a.4)
  - Hunting is an operation to find, fix, and track MCA, and is often driven by data analysis, threat identification, or other anomalous activity.
    - CPTs, in contrast to local defenders, focus on those threat subsets with Tactic, Technique and Procedure (TTP)-specific capability, perceived intent, and opportunity to bypass security layers emplaced by Cybersecurity Service Providers (CSSP) and local network defenders.
    - CPT hunt operations are predicated on the assumption [that] threats already reside within networks. (2.a.5)
  - The absence of security alerts does not indicate an absence of threats, and may instead indicate security mechanisms did not detect a threat or intrusion. ... Passive incident detection and threat hunting operations can, and should, be conducted simultaneously. (2.a.7)
  - CPT hunt operations focus on narrowing MCA tactics to characterize the threat, and determine the threat's technical capability. (2.a.6)Successful hunt operations may require the CPT to establish a deliberate defense posture to further develop and coordinate detailed plans based on the adversary or MCA. (2.a.8)
- A CPT analyst performing a threat hunting operation should proactively and iteratively seek evidence of MCA within an environment
- CPT analysts should focus on hunting a subset of threats, specifically those with advanced TTP-specific capabilities, and should expect that these threats likely have the capability to avoid security controls that may already be in-place on a network
-  If, and when, a CPT analyst discovers evidence of MCA during hunting operations, they should gather additional data in order to determine the threat's technical capability
  - this data is used to help the CPT and local network defenders determine the actions that should be performed in response to the threat, which may include:
    - immediate clear operations
    - the creation of a deliberate defense posture
    - or other actions established via planning with local defenders and network owners
- Threat hunting activities can, and should be, done alongside passive incident detection activities to increase the security posture of a network.

### CPT Hunting Operations
- Triggers
  - Three Triggers that initiate CPT OP:
    - **Threat Intelligence**: Threat intelligence can trigger a hunt operation by warning of an imminent or already-realized cyber attack, or by reporting on new indicators or adversaries that were recently seen in the wild.
      - For example, intelligence about an adversary beginning to actively target the energy sector may trigger a CPT to perform hunts that look for evidence of that adversary on energy sector networks.
      - Threat intelligence can also inform the Tactical Planning and Mission Execution phase of a hunting operation, by allowing a threat hunter to develop more informed or more targeted hunting hypotheses. The creation of hunt hypotheses is discussed later in this lesson.
    - **Campaign Plan**: CPT employment in support of Combatant Command (CCMD) campaign plans is intended to increase critical asset protection prior to operational need.
      - Hunting for evidence of MCA on an asset prior to that asset's use can prevent an adversary's ability to monitor, control, or render that asset unusable during critical phases of CCMD's campaign plans.
    - **MCA Detection**: Detection of MCA within a network may prompt further hunting operations.
      - These operations may be employed in an attempt to discover additional MCA which has evaded detection, or to maintain further contact with an adversary that has already been discovered.

- Planning
  - the planning phases of teh CPT OP take place after CPT threat hunting Op has been triggered.
  - These steps include:
    - determining the objectives and scope of the operation
    - terrain mapping
    - determining the Mission Relevant Terrain in Cyberspace (MRT-C) and Key Terrain in Cyberspace (KT-C)
    - documenting Rules of Engagement (ROE) for the CPT
    - beginning to coordinate system access for the CPT
    - publishing and disseminating orders, and other actions.
  - Additionally, information gathered during Terrain Mapping and Analysis can inform a CPT about the evidence sources that are currently available in an environment, and which of those evidence sources is most fruitful to hunt within.
  - Lastly, knowledge about the MRT-C and KT-C within an environment can help a CPT focus its hunting efforts on the most relevant terrain in an environment.
  - After the completion of the planning phases of the CPT OP, a CPT should be able to answer the following questions as they relate to the hunting operation:
    - What is the scope and purpose of the hunting operation? — What triggered the operation? How long does the operation last? What is the intent and desired end state of the operation?
    - What does the environment look like? — Has a network diagram been created that accurately documents the network? What applications, Operating Systems (OS), and hardware are in use in the environment? What security controls are already in place and potentially related to the operation?
    - What evidence sources are available for a CPT to utilize during the hunt? — Is it necessary for a CPT to acquire evidence for itself, or can this be furnished by local defenders? Are there any visibility gaps that must be accounted for during evidence collection or investigation tasks? If the CPT requires access to additional data, what is the procedure to acquire this access?
    - What are the ROEs that a CPT must adhere to within the environment? — Are there any actions that a CPT has been forbidden from taking? Are there any network segments, machines, or applications that are off-limits to the CPT? What actions are taken by the CPT if, and when, MCA is discovered?
    - Who are the people that the CPT must keep involved during this operation? — Who are the Points of Contact (POC) that a CPT might need to reach out to? When should a CPT reach out to one or more of these POCs? What CPT actions need approval, and which POC can give this approval? How and when does the CPT share their results with appropriate POCs?
  - This wealth of information is utilized by a CPT during the Tactical Planning and Mission Execution phase of a hunting operation.
 
### Tactical Planning for Hunt Operations
- A CPT that has completed the planning phases of the CPT OP is ready to begin the Tactical Planning and Mission Execution of the hunt operation. At this point, a CPT should understand the goals of their mission, the environment/network they are operating within, the individuals and groups that they need to communicate with during the operation, and any limitations, ROEs, or contingencies that exist or need to be planned for.
- Creating a Tactical Plan
  - **Appendix C** of the CWP contains a Tactical Hunt Planning Guide that CPTs can reference when creating a tactical plan for a hunt operation.
  -  **section b.1.a** of the guide outlines **Network Topology**, and lists the following items that should be documented in the tactical plan:
    - Physical layout
    - Logical layout
    - External connections (if applicable)
    - Critical systems (i.e., MRT-C, or KT-C, if identified)
    - Services and applications
  - Each of these important sections is detailed as follows:
    #### Section b.1.d: Network Environment — Threat/Adversary Model
      - This section of the tactical plan should contain information surrounding specific adversaries being targeted during the hunt, including those adversaries' TTPs, objectives, and other detailed intelligence about the adversary.
      - For hunting operations, this section should be as thorough as possible, and might even include information on adversaries that are theorized to be targeting the mission partner's network, even if no tangible intelligence has been gathered to support this.
      - Having this information allows a CPT to better focus their hunting efforts, and more accurately assess any suspicious indicators that arise over the course of the operation.
      - Threat modeling is especially important for CPT hunting operations.
      - Threat modeling performed by intelligence operators can serve as a Campaign Plan trigger — a threat model suggesting an adversary targeting a particular environment can trigger a proactive hunting operation within that environment.
      - Additionally, threat modeling is an important step for a CPT to perform during operations that were triggered via active MCA in an environment, as the adversary responsible for that MCA very likely still poses an active risk to that environment.
      - Hunting for TTPs and other indicators belonging to that adversary are key steps in determining the full scope of a compromise.
    #### Section c.1: Execution — Network/System Owner's Intent
      - This section should clearly state the desired goals of the hunt operation, as determined by the network/system owner.
      - A CPT should develop key tasks performed in order to achieve these desired goals.
      - Many of the key tasks for a hunting operation should include high-level hunting topics; a CPT hunting operation likely consists of multiple individual hunts, each of which is aligned to a topic described in a key task.
    #### Section c.12: Execution — Collection Plan
      - This section documents the plan to collect data from the environment.
      - This data can either be used to answer questions that arose during earlier planning steps, or can be used directly during the execution of an individual hunt.
      - This section should also document any analytics present in the environment, such as any pre-existing automated detection/alerting platforms, and outline a plan for developing suspicious hunt findings into actionable analytics.
      - Lastly, this section should establish a plan for the consolidation and analysis of the data a CPT needs access to in order to conduct the hunting operation.
    #### Section c.13: Execution — Analysis Plan
      - This section combines and further develops the items documented in Section C of the Tactical Hunt Planning Guide.
      - At this point, a CPT should be developing the key tasks they have identified into individual hunts via the creation of hunt hypotheses, which are discussed later in this lesson.
      - The plan for each hunt should include details on what a CPT is hunting for and which data sources are required to do so.
      - This section should also document an overarching information sharing plan for any new adversary indicators or TTPs that are uncovered during the course of a hunt.
    #### Section c.14: Execution — Response/Incident Response
      - This section details what actions are taken if, and when, MCA has been identified in an environment.
      - This information is extremely important, as it fully details the scope of the operation and further defines the ROEs that a CPT must abide by.
      - For example, a CPT may be tasked with passing potential MCA findings to the local defender's Incident Response (IR) team for further investigation and confirmation that the finding represents an actual threat.
      - In this case, the IR section of the tactical plan should detail the necessary requirements needed to engage the IR team, and how the details of the identified MCA are communicated between the CPT and the IR team.

### Identifying and Collecting Data for Hunting
- During the creation of the tactical plan, a CPT identifies the key tasks that need to be performed in order to meet the goals of the operation as determined by the network/system owner.
- For hunting operations, these key tasks include high-level hunt topics that can be further broken down into individual hunts.
- For each hunt, a CPT must identify relevant data that exists within the environment, and develop a plan for acquiring access to this data or otherwise collecting it for themselves, if allowed.
- In terms of collecting data from these data sources, a CPT must be prepared to adapt to a wide array of situations — due to the variety of data sources available, as well as differences between networks, no set plan can be established for collecting data from an environment
- In general, a CPT should have knowledge of the different types of security-related data that can exist within an environment.
- This knowledge lets a CPT make informed decisions about which data sources are the most valuable during a hunt.
- Additionally, a CPT may be able to make additional requests of local network owners and operators in order to acquire access to other data sources.

- Host Logs
  - Host logs are generated by the OS installed on an individual host or endpoint.
  - A wide array of host logs are available, but not all are usable for security-focused investigation activities.
  - Additionally, different OSs contain vastly different types of host logs — cybersecurity analysts performing a host log investigation must learn to cope with many different sources, types, and qualities of logs generated across each investigated OS.
  - host logs contain granular information about events that occur on a host.
  - The following events are a very small sample of the host logs that might be generated on an endpoint:
    - A process was started or stopped
    - A network connection was attempted
    - A user logged in to or logged out of the machine
    - A new device was plugged into the machine
  - Examples of data sources that hold these types of logs include:
  - the Windows event log (on Windows systems)
  - or the System Log (syslog) and System Daemon (systemd) logs on Unix systems.

- Network Logs
  - Network logs are generated by applications or devices that handle network connections in some fashion, and contain information about a connection such as its source, destination, associated ports, and amount of data being transferred.
  - More advanced network logs may include additional details about each connection — for example, network logs from HTTP traffic usually include the type of HTTP request that is being made and the HTTP response code returned by the server handling the request.
  - Some network logs are generated as part of normal OS activity, and may be accessed in the same ways that an analyst might access host logs.
  - Other network logs are generated by specific devices or networking appliances such as routers, firewalls, or proxy devices

- Security Appliance Logs
  - Security appliance logs are logs generated by a security appliance, an antivirus log indicating that potential malware was identified and removed, or an IDS identifying network traffic containing potential attack patterns.
  - As the goal of many security appliances is to prevent or detect MCA, these logs are usually directly related to potential MCA.

- Application Logs
  - This broad category of logs simply means any logs generated by an individual application
  - Not all applications generate logs, and just because a log exists does not mean it is useful to a security investigation
  - if an analyst needs additional information surrounding an attacker's direct interactions with an application, or when an attack vector is performed through exploiting a specific application, application logs may provide crucial insight into the attacker’s activity.
  - Application logs can also be utilized for security investigations as a backup source of evidence to fill potential visibility gaps or provide more context to an investigation
  - In actuality, the categories suggested above are rough approximations of various data sources that are likely to be present in an IT environment.
  - Specific knowledge of the system or application that is generating a log is usually required in order to utilize the log to its full potential.

### Executing a Hunt
- During the creating of teh tactical plan, CPT breaks operation's _key tasks_ into high-level hunt topics, which can be broken down int oindibidual hunts.
- After this, and collecting dat arelevant to each hunt, CPT is ready to perform data analysis and investigative tasks required to execute a hunt.
- Threat Hunting Loop
  <img width="1126" height="706" alt="image" src="https://github.com/user-attachments/assets/2b7cfa1f-ddc9-4c14-b3af-0100a3e6ff93" />
  - Presented as a way to tactically implement a hunt, consisiting of four stages that guide an anlyst or team of analysts through execution of a hunt.

- Create Hypotheses
  - Each hunt poses a single hypothesis, then uses evidence gathered from the network to prove or disprove that hypothesis.
  - Creating a hypothesis is the first stage of the Threat Hunting Loop because a hypothesis is the foundation on which a hunt is built
  - A hunt starts with creating a hypothesis, or an educated guess, about some type of activity that might be going on in your IT environment.
  - Hypotheses are typically formulated by analysts based on any number of factors, including friendly intelligence and threat intelligence, as well as past experiences.
    
- Investigate Via Tools and Techniques
  - During this stage, an analyst actually begins performing an investigation
  - A CPT should also have knowledge of the tools available within their mission kit that can be used to investigate these evidence sources.
  - This phase also makes reference to techniques — more specifically, this refers to **hunting techniques**. **Hunting techniques** are data analysis techniques that are used to investigate a set of data during a hunt.
  - These can range from very basic techniques like running simple searches against a dataset, to incredibly complex techniques such as machine learning or advanced statistical analysis.
 
- Unconver New Patterns and TTPs
  - Once suspicious activity has been identified, an analyst must determine if the activity can truly be traced back to an attacker.
  - This may be immediately evident upon initial discovery of a suspicious pattern, or may require a deeper investigation.
  - This phase can also include further refinement of the hunting techniques used to initially identify the activity.
  - This step often allows an analyst to refocus or reword the initial hypothesis, and may even generate new hunting hypotheses.
  - An analyst should document these hypothesis ideas as they come up — investigating a second or third hypothesis may reveal instances of suspicious activity that the first hypothesis did not.

- Inform and Enrich Analytics
  - Don’t waste your team’s time doing the same hunts over and over. If you find an indicator or pattern that could recur in your environment, automate its detection so that your team can continue to focus on the next new hunt.
  - During this step, a CPT should document the suspicious pattern that was identified, the associated analysis techniques used to detect the pattern, and any analytics that were developed around this pattern, such as detection rules, searches, and code used for data analysis
  - It is not possible, or advised, to try to fully automate every hunt result.
  - In certain environments, automated detection may not be feasible, or even possible.
  - However, the investigative and analysis steps taken during each hunt should be well-documented, so that the hunt can be more easily repeated later.
  - Any automated analytics or hunt documentation created during this step should be placed within an appropriate knowledge management solution to help improve the operations of other CPTs.
  - A version of this documentation can also be provided to local defenders and local network operators in order to help improve the network’s security posture.
  - **Friendly intelligence** — information about the normal operations of the environment that the hunt is being conducted within — can also be created during this step.
  - **Friendly intelligence** can include:
    - a software inventory
    - a catalogue of important server locations
    - and other details about the environment.
  - Documenting friendly intelligence can be especially important during a long-term hunting operation, as it allows a CDA to more quickly recognize what normal looks like in a given environment.

### Creating a Password Guessing Hunt Hypothesis
- A good hypothesis might accomplish any or all of the following:
  - Direct analysts towards potential analysis methods
  - Propose what attacker activity might look when found
  - Identify likely sources of evidence to hunt within
  - Provide a path for analysts to follow in order to prove or disprove the hypothesis
- Password Guessing Attack Overview (MITRE T1110.001)
  - A password guessing attack is exactly as it sounds — if an attacker knows the username of an account, they can try to guess the password for that account.
  - Successfully guessing the password should allow the attacker to log in as that user account.
  - This attack can be performed against as many accounts as the attacker wishes to run it against, but is usually performed against a specific target account.
  - Usually, password guessing attacks are performed via an automated tool, which can guess many different passwords in a short amount of time
  - In practice, attackers often try to limit the number of passwords they need to guess by choosing passwords from a password list, which contains hundreds or thousands of commonly-compromised passwords that have been extracted from breach reports


## CLEAR

### Introduction to Clearing
- Clearing is an operation to target and engage MCA to eliminate or neutralize it from a network or system.
- Cyber Warfare Publication (CWP) 3-33.4:
  - Clear is normally used relative to the removal of barriers or obstacles in mobility operations or the deconfliction of targets for engagement. In the context of CPT operations, clear is defined as an operation to target and engage MCA in order to eliminate or neutralize it from a network or system, and may include actions to interdict, contain, disrupt, or degrade MCA. The CPT clear function occurs when the supported or supporting commander directs the CPT to eliminate or neutralize the identified threat on the network or system. CPTs may also be directed to take other actions against identified threats rather than clearing them.
- The process of conducting a clearing operation through mission partner networks and systems occurs after a hunt operation or threat intelligence identifies MCA
- Prerequisite to conducting the clearing operation, a CPT should determine the full scope of the intrusion, both functionally and physically, so that the threat and damage is fully characterized prior to recommending that the clear operation proceed.
- According to National Institute of Standards and Technology (NIST) Special Publication (SP) 800.61r2, the IR lifecycle consists of four phases.
  - Preparation
  - Detection and Analysis
  - Containment, Eradication, and Recovery
  - Post-incident Activity
    
  <img width="608" height="304" alt="image" src="https://github.com/user-attachments/assets/b9eeced1-5880-477b-8ea1-11374d6658d5" />

- These steps correspond to the Preparation and Detection phases of an IR cycle:
  - Gain and maintain contact with the MCA
  - Consult with Subject Matter Experts (SME) to determine methods and intent behind MCA
  - Engage with mission partner Cybersecurity Service Providers (CSSP) to assist with an IR plan
  - Make a risk mitigation decision based on the benefits or consequences of continuing hunt operations versus initiating clear operations
- Once a clear operation is approved, a CPT performs the following, as directed or tasked:
  - Contain affected systems and networks simultaneously to prevent adversary repositioning.
  - Neutralize and eradicate adversary activities in each network or system
  - Observe and characterize adversary behavior and Tactics, Techniques, and Procedures (TTP) to enable follow-on operations (i.e., enable hardening)
  - Enable recovery or restoration of affected systems and networks

### Gain and Maintain Contact
- During the prerequisite phase of clearing operations, which corresponds to the Preparation and Detection steps of the IR lifecycle, Cyber Defense Analysts (CDA), in a **deliberate hunt operation** or after given **actionable threat intelligence**, use a working knowledge of normal operations and patterns in an organization to determine deviations from that baseline, and characterize those anomalies as incidents or not.
- A variety of tools and techniques are employed, such as:
  - monitoring software
  - log and error message aggregation
  - querying platforms
  - security systems (e.g., Network Security Monitors [NSM], firewalls, and Intrusion Detection Systems [IDS]).
- If an event appears to be an incident after identification and analysis, it is important to report it quickly and respond according to organizational procedures and standards. 

### Neutralization and Eradication of MCA from Affected Systems
- The objective of a clear operation is the **quarantine**, **withdrawal**, or **destruction of identified threats** from the network or system. This is the key phase in accomplishing that objective.
- After a system is contained, responders conduct the actual removal of compromised artifacts and any persistence that an attacker may have left behind
- This is also an exhaustive process and should never be done from memory or through pure intuition
- Use established organizational Standard Operating Procedures (SOP) and industry-proven checklists in investigating the system

## ENABLE HARDENING

### Enable Hardening - FOUO
- As described in Cyber Warfare Publication (CWP) 3-33.4:
  - “For Official Use Only (FOUO) Adversary exploitation will require technology or process updates to mission partner networks and systems to mitigate them. CPTs will maintain and update network or system hardening recommendations for the duration of hunting and clearing operations. Commanders will be notified when critical vulnerabilities arise, and whether those vulnerabilities will be mitigated in stride to increase network or system security and resilience. Pre-approved actions, and those actions requiring further approval(s), will be identified and presented during pre-mission planning. CPTs will recommend hardening actions and report on network or system hardening recommendations to mitigate threat-specific risks to supported commanders, CyberSecurity Service Providers (CSSP), and local network and system protectors upon conclusion of operations. Department of Defense Information Network Area of Operation (DoDIN AO) commanders and directors, local network owners, local network defenders, and CSSPs maintain the responsibility to determine available data, develop plans to mitigate gaps, and implement required updates or hardening measures recommended by CPTs. CPTs will advise and assist, but should not be the primary entity performing protection duties expected of DoDIN AO commanders and directors, local network owners, local network defenders, or CSSPs.”
- Mission Relevant Terrain in Cyberspace (MRT-C) and Key Terrain in Cyberspace (KT-C) are an especially important focus during the hardening phase. MRT-C and KT-C will be determined during mission planning.
- "(FOUO) The end state of the hardening function is to mitigate risk of adversary exploitation, or reduce it to levels acceptable to network or system owners." CWP 3.33-4

### Relevant Cybersecurity Principles
- A Cyber Defense Analyst (CDA) needs to be aware of specific general cybersecurity principles and policies to be successful during the hardening function.
- Federal Information Systems Management Act (**FISMA**) requires every federal agency to develop, document, and implement a security policy for information and information system assets throughout the agency.
- **FISMA** outlines a risk management based process for cost effective security.
- **Standards** are formal, mandatory requirements an organization must meet for actions, processes, or configurations.
- A common collection of standards a CDA may encounter is the Federal Information Processing Standard (**FIPS**), which was developed by the National Institute of Standards and Technology (**NIST**) in response to FISMA
- It defines the standards for non-national security systems.
  - An example of a standard is the Secure Hash Standard (part of FIPS), that specifies which hashing algorithms organizations are allowed to use to generate message digests.
- **Baselines** define minimum levels of security that every system within an organization must meet
- The Defense Information Systems Agency (**DISA**) has several Security Technical Implementation Guides (**STIGs**) that Department of Defense (**DoD**) systems must comply with, which provide security baselines for Operating Systems (OS) and software
- The **STIG Viewer tool** allows analysts to view STIGs that are applicable to specific systems running specific software. It is available on Windows, Linux, and MacOS.
- **Guidelines** are recommendations on a course of action to best meet specified requirements.
- NIST has developed several guidelines in their Special Publications (SP), which lay out best practices for several processes
- There are several SPs that a CDA may find useful while hardening within the SP 800 series including, but not limited to:
  - **SP 800-53**: Catalog of security and privacy controls for federal information systems
  - **SP 800-40**: Relates to patch management
  - **SP 800-41**: Relates to firewall configuration
  - **SP 800-123**: Relates to central server security

<img width="1944" height="1246" alt="image" src="https://github.com/user-attachments/assets/60a74721-7488-4425-a742-730838bd170e" />

- Defense-in-depth is a practical strategy developed by the National Security Agency (NSA) that employs a layered approach including:
  - people
  - technology
  - aoperational capabilities that establishes barriers to attacks to achieve information assurance.

<img width="1280" height="913" alt="image" src="https://github.com/user-attachments/assets/82f9c01a-0e88-49b4-ac77-523a9b73d7bb" />

### Assessing Security Posture and Making Recommendations
- Observe the documentation below, which provides context and situational awareness for the mission partner and enables the CPT to make hardening recommendations:
  - Supported Organization Mission and Resources help the CPT gain a Common Operating Picture (COP) of the mission partner’s current security posture.
  - This includes, but is not limited to, network and system logging, configuration, current security procedures, etc.
  - AO Logical Maps or Network Maps are the principal documents for terrain visualization of mission partner networks and systems (from CWP 3.33-4). Generally, this is a Microsoft Visio document or a Draw.io document.
  - Detailed Threat Assessment Reports cover the historical attacks against the mission partner, probable threat actors they would see in their AO, likelihood of threat activity/capability used against them, and the threat matrix (criteria/heat map) showing their ability to detect and counter them (from CWP 3.33-4).
- CPTs issue or provide input to the following reports after hardening a mission partner network (from CWP 3.33-4):
  - **Detailed Host Vulnerability Finding and Corrective Actions Report**: Covers patch management and outdated software vulnerabilities, services, and detailed vulnerability scanner results (e.g., results from Assured Compliance Assessment Solution [ACAS] and misconfigurations).
  - **Detailed Network Vulnerability Findings and Corrective Actions Report**: Covers at least the following elements, if applicable — proper sensor placement, signature management, firewall implementation, firmware vulnerabilities, ports/protocols, access control lists, or infrastructure configurations.
  - **Detailed Non-Technical Vulnerability Findings and Corrective Actions Report**: Covers policy assessment from NIST SP 800-53 and mission partners utilizing intelligence to inform DCO.
  - **Risk Mitigation Plan (RMP)**: Documents all vulnerabilities identified during threat mitigation. This document includes recommendations for internal and external mitigation actions to reduce the overall risk to the secured network. This is further discussed in upcoming lessons.

### Identifying Host and Network Areas for Hardening
- NIST SP800-53 provides an overarching checklist for high-level categories as mentioned previously.
- However, CDAs primarily evaluate these areas:
  - **Web-facing Assets/Infrastructure**: These devices contain resources that are accessible to an external and internal user.
    - This duality means that devices in this network are untrusted.
    - Internal users are allowed to connect in, but devices within the Demilitarized Zone (DMZ) are restricted from initiating connections into the private network.
  - **Network Boundary**: A network boundary is where one logical network meets another.
    - In the case of a private network and the open internet, this may be different organizational networks connecting, etc.
    - It is generally wise to deploy boundary defense mechanisms in this area such as firewalls, Network Intrusion Detection System (NIDS), or Network Intrusion Prevention System (NIPS).
  - **Network Segmentation**: In simple terms, network segmentation is grouping devices into zones, often by function or access requirements, and putting them in their own network.
    - Access controls are often applied between segments to restrict access into more sensitive segments.
  - **Inventory of Systems**: Organizations should have an inventory system to track their assets.
    - This includes devices such as phones and printers.
    - An accurate inventory is essential for implementing the correct security controls.
  - **Domain Architecture and Services**: In reference to Microsoft Active Directory (AD) service, AD hosts a number of Windows services facilitating centralized identity management, object access, and policy management across Microsoft AD trees and forests.
    - Because of their orchestrating role, protecting critical components of domains (e.g., enterprise and domain administrators and Domain Controllers [DC]) is crucial.
  - **User Rights Management**: Users should always be given the least amount of privilege necessary to complete their assigned work roles.
    - This is often achieved by assigning users into groups depending on their job duties.
  - **Endpoint Configuration**: Secure configurations on the endpoints rely on processes such as update and patch management, software management, etc.
    - A good practice for endpoint configuration is developing a common secure baseline image.
  - **Logging and Detections**: Audit policy is dependent on regulation and organizational requirements.
    - However, auditing is key in detecting incidents and determining the extent of damage. Without auditing, breaches would be excessively difficult, if not impossible, to assess.
- In Windows environments with DCs, host hardening is done centrally in AD by using GPOs
- GPOs govern access to services on the network, user rights management, endpoint configuration, firewall configurations, logging, and a plethora of other functionality
- Consult the NIST SP 800 series for guidelines and best practices for these devices as well as STIGs to ensure that systems and network devices meet security baselines.
- Once you understand the mission partner's operational cyberspace, recommend changes.
- The goal is to:
  - Propose network architecture changes to improve security and reduce risk
  - Ensure unnecessary services are disabled
  - Ensure latest patches are installed
  - Remediate insecure configurations
  - Audit installed software
  - Enforce an audit policy
  - Enhance security systems and logging

### Tools
- The categories covered are platforms, host utilities, vulnerability scanners, and Security Information Event Management (SIEM) solutions.
- Some specific cyber defense platforms that CDAs may encounter:
  - **Security Onion**: A free and open source platform for network security monitoring, threat hunting, enterprise security monitoring, and log management.
    - It comes with several tools mentioned in this lesson including Kibana, Zeek, Suricata, and other utilities.
  - **Response Operation Collection Kit Network Security Monitor (ROCK NSM)**: ROCK NSM provides a robust platform for passive data acquisition, transit, and data storage and indexing.
    - Like Security Onion, it comes with Kibana, Zeek, Suricata, and other utilities.
- Windows hosts make up a large portion of many DoDIN networks.
- These tools help with the hardening process:
  - **Sysinternals**: A suite of over 65 tools for troubleshooting Windows OS.
  - **Windows PowerShell**: Object-oriented scripting utility that is tightly integrated with the Windows OS and AD.
    - Windows PowerShell is an incredibly useful tool when enumerating Windows ADs and Windows hosts.
  - **Microsoft Baseline Security Analyzer**: A deprecated vulnerability scanner for Windows systems pre-Windows Server 2008 R2.
    - Its capabilities include ensuring security updates are up to date, checking for Structured Query Language (SQL) Server and Internet Information Services (IIS) administrative vulnerabilities, and verifying password complexity.
    - Its successor is the Windows Update service.
- Network Security Monitors (NSM) detect and often respond to network attacks. CDAs need familiarity with:
  - **Zeek**: Formerly known as Bro, Zeek is an open source network security monitor.
    - It sits on a sensor in the network that observes network traffic and generates robust logging that is forwarded to a SIEM like Splunk or Elasticsearch.
  - **Suricata**: A free and open source robust network threat detection engine.
    - It is capable of real time intrusion detection, in-line intrusion prevention, network security monitoring, and offline network capture processing.
- SIEMs play an essential role in the hardening function as they enable rapid detection of future incidents
  - **Splunk**: A proprietary software platform widely used for monitoring, searching, and data visualization especially in relation to logging data in real time.
  - **Kibana**: A data visualization tool generally deployed in a stack along with Elasticsearch and Logstash.
    - Elasticsearch is a free and open source databasing and visualization tool used in conjunction with Security Onion or ROCK NSM.
- CDAs need familiarity with the following vulnerability scanners:
  - **ACAS**: This is the mandated enterprise vulnerability scanning capability utilized for assessing DoDINs such as Non-classified Internet Protocol Router Network (NIPRNet) and Secret Internet Protocol Router Network (SIPRNet).
  - **RedSeal**: A security solution capable of assessing cloud environments as well as application-based policies and endpoints.
  - **Open Vulnerability Assessment System (OpenVAS)**: A successor to Nessus, OpenVAS is a robust open source vulnerability scanner that is part of the commercial Greenbone Security Manager.
    - Its capabilities include authenticated and unauthenticated testing, industrial and internet protocols testing, and an internal programming language for implementing any type of vulnerability scan.
- Firewall rules:
  - Rule 10 — Allows workstations to communicate with the CDA-SERVERs
  - Rule 20 — Prevents the Accounting (ACC) and Human Resources (HR) networks from communicating with each other
  - Rule 30 — Allows both devices to communicate with the logging host in the security network
  - Rule 40 — Allows all other types of traffic

## ASSESS

### Overview of the Assess Function - FOUO
- The Assess Phase
 - One of the core functions of a CPT is assessing the effectiveness of response actions against current and future risks to specified terrain in cyberspace
 - As per Cyber Warfare Publication (CWP) 3.33-4:
   - During operations, the CPT will simultaneously assess the effectiveness of clearing operations, hardening actions taken by local network defenders, and the overall network system security, and resilience.
 - As per CWP 3.33-4, the goal of assessing is to conduct Cyber Threat Emulation (CTE)
 - CTE assesses the current security posture by emulating known adversary Tactics, Techniques, and Procedures (TTP) to validate the current defensive measures
 - Assessment takes the products from a mission execution and uses them to determine if operational objectives were met. Assessment is centered around indicators to track progress towards mission accomplishment.
 - The indicators that the trainee is concerned with as per CWP 3-33.4 are
   - MOPs determine whether operational tasks were satisfied to create the desired effect.
   - MOEs determine whether the desired effect achieved operational objectives.
   - More concisely, MOPs track progress towards creating the desired effect, and MOEs evaluate if that desired effect achieved operational objectives.
   - MOEs can be considered as bullets and MOPs can be considered sub-bullets.
 - While the CPT OP focuses on mission at an operational level, CPTs do not function at an operational level during day-to-day tasks
 - When the Operational Control (OPCON) Headquarters (HQS) Operational Planning element provides operational level MOEs and MOPs, the CPT will use them by converting them into tactical level MOEs and MOPs
 - This involves turning operational level MOPs into tactical level MOEs, and developing new tactical MOPs that would correspond to the MOEs
 - The new tactical level MOEs and MOPs will be used by the CPT to conduct tactical assessments during and after the mission execution phase.
 - Tactical assessments can fulfill the objective of assessing the effectiveness of response actions, and therefore play a part during the assess function.

### MOEs and MOPs
<img width="1950" height="838" alt="image" src="https://github.com/user-attachments/assets/12a11e15-4c29-4440-b0ce-f00b2df7c0d5" />

- Since CPTs only function at tactical level, the MOPs become the new MOEs.
- CPTs decide how to accomplish MOEs by developing now MOPs
<img width="799" height="932" alt="image" src="https://github.com/user-attachments/assets/9dc1b847-e7f9-4a92-be92-bf6c9fb23bdd" />

- CPT continuously references MOEs and MOPs during mission execution, and post-mission execution to ensure effectively conducted operations and completed key tasks.

### Building a Timeline
- Examining external reporting and observing the Operation Notes (OPNOTE) of other analysts are critical tasks at this stage
- Focus on aggregating the output of various intelligence and tactical products to ensure that the mission objectives were met
- Consider tactical output from mission execution:
  - **Situational Reports (SITREP)**: SITREPs are routinely generated to provide updates to higher elements on a daily, weekly, per-phase, or on request.
  - **Tactical Assessments**: Tactical assessments are low-level assessments that often contain their own MOEs and MOPs
  - **OPNOTEs**: OPNOTEs are in-depth and technical about the events that occur during mission execution. However, OPNOTEs contain very specific timestamps and events rather than a high-level summary. When more detail than a high-level summary is needed, consult the OPNOTEs.
- In addition, OPNOTEs are helpful in developing a execution timeline including, but not limited to:
  - **Health and Status Reports**: US government agencies publish health and status reports on a regular basis to aid with situational awareness of current operational activities, which enables the capacity to build, defend, and operate in cyberspace.
    - These reports have a variety of functions, but they are useful in establishing past trends and assess their impact on the mission partner’s network.
  - **Cyber IR Reports**: DoD agencies must abide by the cyber incident handling program defined in the Chairman of the Joint Chiefs of Staff Manual (CJCSM) 6510.01B.
    - This document outlines a specific IR report template. The completed reports are stored in the Joint Incident Management System (JIMS) on Secret Internet Protocol Router Network (SIPRNet). Past incidents provide a historic picture of the network as well.

  <img width="755" height="382" alt="image" src="https://github.com/user-attachments/assets/cb972b1d-a613-41f0-b1d9-4dd4ce48901a" />


# MODULE 4

## Planning Lifecycle

### Planning Lifecycle Overview
- Three possible triggers initiate the CPT operations process:
  - Threat Intelligence
    - Threat intelligence reporting or warning intelligence may trigger hunt, clear, enable hardening, and assessment functions by the CPT.
  - Campaign Plan
    - CPT employment in support of Combatant Command (CCMD) campaign plans is intended to increase critical asset protection prior to operational need.
  - Malicious Cyberspace Activity (MCA) Detection
    - Whether discovered by local network protection assets, network owners, or indicated by threat intelligence reporting, CPT hunting and clearing entails conducting reconnaissance and counter-reconnaissance on supported commanders’ networks or systems to gain and maintain contact with an adversary or further develop a situation.
- The first step of the CPT OP is Objectives, Effects, and Guidance
- the operational planning section determines the appropriate CPT functions and capabilities before developing preliminary objectives, intended effects, and commander’s guidance
- The operational planning section is also responsible for assessing existing command relationships and making recommendations for potential additions or changes to facilitate and enable the CPT mission
- Once a trigger has been identified If a mission is required, a PLANORD and TASKORD is developed.
- Objectives, intended effects, and commander’s guidance are disseminated via a Planning Order (PLANORD) to the CPT, the supported commander, and the local network protectors
- PLANORDs are followed by a TASKORD
  -  According to DoD Joint Publication (JP) 1-02 a TASKORD is,
    - “A method used to task and to disseminate to components, subordinate units, and command and control agencies projected targets and specific missions. In addition, the tasking order provides specific instructions concerning the mission planning agent, targets, and other control agencies, as well as general instructions for accomplishment of the mission.”
- TASKORD documents the supported commander’s or organization’s requirement to collect initial network diagrams, terrain information, design documentation, previous operational and penetration test results, and configuration information for CPT use in the next step of the OP.

### TASKORD Overview
- The PLANORD and TASKORDs provide specific instructions concerning the
  - mission planning agent
  - targets
  - and control agencies, as well as general instructions for accomplishment of the operation.
- Using the provided information and their analysis of it, the CPT develops a tactical mission statement, end state, defines initial tactical objectives, and determines initial capabilities for the mission.
- CPT then coordinates with the operational planning section and supports the commander’s staff to coordinate mission Rules of Engagement (ROE) informed by the initial capabilities analysis
- **ROE** in the context of CPT operations refers to the `constraints and limitations under which the CPT hunts and/or clears when MCA is encountered as agreed on by the supported network owner and the supporting commander`
- CPT leadership also conducts a troops-to-task assessment to determine personnel requirements based on mission scope and scale.
- TASKORD Header
  - General Details pertaining to the Mission
    <img width="1174" height="1270" alt="image" src="https://github.com/user-attachments/assets/a1a5a624-264d-419f-9291-a0440b9b11ef" />

  - Portion outlined in green describes relevant genreal information that pertains to task.
  - Important items include:
    - **Subject (SUBJ)**: The name and goal of the TASKORD and mission
    - **Operation (OPER)**: The name of the mission

- TASKORD: SECTION 1
  <img width="1178" height="1430" alt="image" src="https://github.com/user-attachments/assets/ddefa049-7b03-4592-bceb-93fd98d07610" />

  - covers the situation of the task
  - provides the CPT with background and context for what and why the task is being issued.
  - CPTs can find a mission summary and the area of concern here
 
- TASKORD Section 2A
  <img width="1196" height="1128" alt="image" src="https://github.com/user-attachments/assets/d988fb17-1851-4e05-82f9-f083cb393f88" />

  - defines the intent, purpose, method, and end accomplishment(s) of the task
  - The Commander’s Intent is the overview of the mission and the applicable actions the CPT takes in the task.
  - The Purpose defines the goals and objectives of the task.
  - The Method defines how the task is executed.
  - The End State defines what constitutes completion of the task.
 
- TASKORD: Section 2B
  <img width="1098" height="1522" alt="image" src="https://github.com/user-attachments/assets/2b3c093c-edd5-4993-b586-2fadf760958b" />

  - provides a list of sub-tasks that are required in support of the overall goal of the TASKORD.
 
- TASKORD: Section 3
  <img width="1316" height="452" alt="image" src="https://github.com/user-attachments/assets/9229675c-9cf9-48f7-a117-435a77bb5294" />

  - Section 3 of the TASKORD defines administrative and logistical information.
  - Section 3 can include anything noteworthy pertaining to the specific site or mission funding.
 
- TASKORD: Section 4:
  <img width="1288" height="310" alt="image" src="https://github.com/user-attachments/assets/968e425d-5816-4a60-86a6-fc10fb412af0" />

  - Section 4 of the TASKORD defines the primary command and control for the mission.
 
- TASKORD: Section 5:
  <img width="1304" height="896" alt="image" src="https://github.com/user-attachments/assets/1b9e8c56-2c42-463f-b24c-781ecc09d598" />

  - Section 5 of the TASKORD defines the ROE.
  - The ROE are parameters that the CPT must follow, and includes parameters such as areas of the network that should not be accessed and tools that can/cannot be used on the network.
  - The CPT coordinates with the operational planning section and support commander’s staff to coordinate mission ROE informed by the initial capabilities analysis.
  - ROE in the context of CPT operations refers to the constraints and limitations under which the CPT hunts and/or clears when MCA is encountered as agreed upon by the supported network owner and the supporting commander.
  - For example, the CPT needs to know if they are allowed to employ agent-based solutions, deploy compiled code to hosts, or interrupt service(s) during mission conduct.
  - CPT leadership also conducts a troops-to-task assessment to determine personnel requirements based on mission scope and scale.
  - By adding enriching data and graphical control measures to network maps produced during the previous step, the CPT further improves terrain visualization during planning and operations to enable a common operating picture to emerge, and create shared situational awareness between the CPT, the supported commander, and local network protection assets.
  - The network map forms the basis of the CPT’s visualization tools and must scale appropriately to the situation. As a critical input, the network map forms the foundation on which courses of action are developed based on the operational approach and analytic scheme of maneuver employed by the CPT.	

### Data Collection
- The planning phase includes data collection of artifacts, such as:
  - Network Diagrams
    - visual representation of the systems and connections the CPT operates on during the mission
    -  streamline the mission by cutting out the time or effort to make assumptions about the network
  - Terrain Information
    - includes the logical and physical components
    - Defensive Cyberspace Operations (DCO) team members should use Key Terrain in Cyberspace (KT-C), MRT-C, Task Critical Asset (TCA), and Defense Critical Asset (DCA) to define terrain
    - Terrain analysis is the collection, analysis, evaluation, and interpretation of geographic (physical) and digital (virtual) information on the natural and man-made features of the terrain to predict the effect of the terrain on military operations.
    - Within DCO, it involves the study and interpretation of features of the terrain and their effects on military operations.
  - Configuration Information
    - Configuration information refers to the details and settings of the machines and devices used on the network
    - can refer to both physical and logical details and settings
    - Physical configuration information can include data points such as the location of servers, machines, or network devices and the type of hardware making the connection between machines
    -  Logical configuration information can include data points such as Operating Systems (OS), firmware and firewall versions, and Active Directory (AD) users and groups.
    -  Configuration information can also include data points containing the Points of Contact (POC) that are responsible for the configurations.

### RFI Overview
- An RFI is a document that an organization sends to customers to request specific information or clarification on information regarding the mission
- While not always necessary for every mission, an RFI provides clarity for the information in question that is both technical and/or non-technical
- During the planning lifecycle of the CPT OP, CPTs collect a vast amount of data points and information

- RFI Format
  - RFIs do not need to follow a specific format or template.
  - RFIs need to include requests for information that impacts how an operation is executed.
  - The information in the request can pertain to any of the topics covered in the TASKORD or in the operation as a whole, topics can include:
    - intent
    - purpose
    - end state
    - tasks
    - logistics
    - command, or control.
  - The RFI will include the contact information for the site personnel responsible with receiving and processing the RFI.
  - The personnel is typically the network or system owner, or directly connected to the owners, at the site of the operation.

## Terrain Identification

### Terrain Overview
- Terrain, which covers all of cyberspace, includes the logical and physical components
- When defining terrain DCO team members should use:
- **KT-C**
  - Any locality or area — physical or logical — where seizure, retention, or other specified degrees of control provide a marked advantage in cyberspace to any combatant. 
- Mission Relevant Terrain in Cyberspace (MRT-C)
  - Described as — but not limited to — all devices, internal/external links, Operating Systems (OS), services, applications, ports, protocols, hardware, and software on servers required to enable the function of a critical asset. 
- **Task Critical Asset (TCA)**
  - An asset that is of such extraordinary importance that its incapacitation or destruction would have a serious, debilitating effect on the ability of one or more Department of Defense (DoD) or Office of the Secretary of Defense (OSD) components to execute the capability or mission-essential task it supports. TCAs are used to identify DCAs.
- and **Defense Critical Asset (DCA)**
  - An asset of such extraordinary importance to operations in peace, crisis, and war that its incapacitation or destruction would have a very serious, debilitating effect on the ability of the DoD to fulfill its missions.
- as outlined in United States Cyber Command (USCC) Operational Guidance on Identification of Mission Relevant Terrain in Cyberspace.
- Once the CPT has an assigned terrain in which to hunt and operate, the threat hunter can filter through the terrain, based on the types of systems and data available
- Data requirements are tied to analytics that are then tied to Tactics, Techniques, and Procedures (TTP) used.
- Identifying terrain, in turn, reduces the number of analytics necessary for the team to execute.
- The threat hunter can also filter through the terrain on the identified MRT-C and KT-C to prioritize the required data collection.
  
### Terrain Analysis and Identification
- **Terrain analysis** is the collection, analysis, evaluation, and interpretation of geographic (physical) and digital (virtual) information on the natural and man-made features of the terrain to predict the effect of the terrain on military operations.
- Within DCO, it involves the study and interpretation of features of the terrain and their effects on military operations.
- Terrain Analysis and Site Survey
  - A site survey is the examination of a location in order to obtain data or information
  - The information obtained during a site survey helps determine the mission terrain, gathers critical data, and defines the network owner’s needs
  - Information that can be collected during a site survey includes
    - access to the site and necessary equipment
    - network topology
    - OSs
    - and critical on-site personnel to assist with the operation (such as security and information technology personnel).
  - During the site survey, a DCO team supporting threat hunting develops relationships with the network owner, finalizes the Operation Order (OPORD), develops the tactical plan, and collects the crucial mission data necessary to build a hunt plan
  -  It is during this time that a team arrives, requests a work location, gains access to personnel/systems, and integrates its equipment and tools into the network.
  - To develop the fundamental understanding of the terrain, a DCO team must collect data before the site survey occurs.
  - Data to collect prior to the site survey includes policy documents, briefings, log samples, network maps, or vulnerability scans

### Terrain-based Cyberspace Threat Hunting Methodologies
<img width="668" height="368" alt="image" src="https://github.com/user-attachments/assets/afe841b3-b82f-4791-a2f0-9f74dccaa2f3" />

- **Cyberspace Threat Hunting (CTH)** is the process of proactively and iteratively searching through networks to detect and isolate advanced threats that evade existing security solutions
- There are three unique core CTH methodologies driven by
  - analytics
    - Analytics — Driven methodology leverages data and analytics
    - utilizes complex queries and algorithms to apply to data sets
    - A key distinction with the Analytics methodology is no physical access to local machines, networks, or systems is required.
    - Data artifacts consisting of sensor alerts, system logs, and network traffic are vital to the Analytics — Driven Methodology.
    - CTH analysts combine knowledge of data artifacts with knowledge of automated analysis capabilities to develop a picture of the network terrain.
  - situational awareness
    - Situational Awareness — Driven methodology leverages an advanced understanding of a particular cyberspace terrain in order to detect anomalous activity.
    - Situational Awareness does not require physical access to local systems
    - Data artifacts pertaining to the operating environment are critical to this methodology.
    - CTH analysts examine data artifacts over time in order to understand system normality and detect outliers in behavior, which often lead to discovering potentially Malicious Cyberspace Activity (MCA).
  - and intelligence.
    - Intelligence — Driven methodology leverages timely, accurate, mature Cyberspace Threat Intelligence (CTI) to detect advanced cyberspace threats.
    - Intelligence — Driven methodology requires physical access to local systems.
   
### Defining an Operational Environment
- An **OE** is a composite of the **conditions**, **circumstances**, and **influences** that affect the employment of capabilities and bear on the decisions of the commander
- Components including the type of equipment, the size of the network, OSs, key personnel, and schedule of the location all play critical roles in decision making. These components help to define the OE.
- Defining the OE results in the identification of:
  - Significant characteristics that can affect friendly and threat operations
  - Gaps in current intelligence
- CTH analysts identify significant relevant characteristics related to the mission variables of the enemy and terrain
- The threat operator evaluates significant characteristics to identify gaps and initiate information collection.
- Failure to identify or misidentify the effect these variables may have on the mission at a given time and place can hinder decision-making and result in mission failure.  

### Layers of Cyberspace
- When defining the OE, start with the three layers of cyberspace:
  - Physical network
    - consists of the tactile Information Technology (IT) devices and infrastructure in the domains that provide storage, transport, and processing of information within cyberspace
    - The layer includes data repositories and the connections that transfer data between network components.
    - Physical network components include the hardware and infrastructure (e.g., computing devices, storage devices, network devices, and wired and wireless links).
    - These components require physical security measures to protect them from damage or unauthorized access, which may be leveraged to gain logical access.
    - Depicting the physical network layer within the OE allows analysts to inspect the layer as it relates to friendly and threat operations.
    - CTH analysts derive the physical network layer depiction from products developed by the network owner and through their own validation of the network.
    - When analyzing the physical network layer, identify:
      - Threat Command and Control (C2) systems  — physical devices adversaries use to leverage to execute their operations — that traverse the cyberspace domain
      - Critical nodes the threat can use as hop points in the OE
      - Physical network devices in the terrain (e.g., fiber optic cables, internet exchanges, and public access points)
      - Elements or entities — threat and non-threat — interested in and possessing the ability to access data and information residing on and moving through the network
      - Physical storage locations with the most critical information and accessibility to that information
      - Implemented measures that prevent threat actors from accessing the networks
  - Logical network
    - consists of all the data — whether resting, moving, or being used in the physical network layer
    - based on the programming or software that drives network communications, interactions, and connectivity
    - Individual links and nodes are represented in the logical network layer along with various distributed elements of cyberspace including data, applications, and network processes not tied to a single node.
    - Network maps often depict the logical network layer in relation to the physical network layer.
    - Reporting from many sources can provide information about the logical network layer of threat cyberspace, including — but not limited to — protocols, Internet Protocol (IP) address blocks, and OSs.
    - Network key systems can be assessed using the depiction on the logical network layer.
    - When analyzing the logical network layer, identify:  
      - Websites or web pages that influence or have a social impact on the network
      - Friendly logical network configurations and vulnerabilities and the friendly physical network configurations
      - Software that handles and shares friendly data
      - Virtual Private Networks (VPN) or subnets that cross physical boundaries
  - Cyber-Persona
    - view of cyberspace created by pulling artifacts and data from the logical network layer to describe actors and entities that utilize the network
    - consists of network or IT user accounts, whether human or automated, and their relationships to one another.
    - Cyber-personas may relate directly to an actual person or entity, incorporating some personal or organizational data (e.g., email and IP addresses, web pages, phone numbers, web forum logins, or financial account passwords).
    - includes employee permissions to access physical and logical aspects of the OE
    - When analyzing the cyber-persona layer, identify: 
      - Data and information consumers in the terrain
      - How local users interrelate with the physical network and logical network layers
      - Usernames, permission levels, email addresses, chat names, etc
- When evaluating the OE for a DCO mission, collaboration with the local network owner is essential.

### DMZ
- A DMZ is a perimeter network that protects an organization's internal Local Area Network (LAN). The DMZ protects the enterprise network by offering a layer of separation between internet-facing services and more sensitive internal-only subnets
- Additionally, the DMZ utilizes Dynamic Host Configuration Protocol (DHCP) via Internet Service Provider (ISP).
- DHCP via ISP is when a DHCP server assigns IPs by modem Media Access Control (MAC) address

### Domain Controllers
- AD is a database and set of services that connect users with the network
- The DC is the terminal that controls AD.
- The DC manages many of the services running on the network, tracks which users are active/inactive on the network, and controls access to critical information.

### ACAS Server
- ACAS is a suite of security software responsible for assessing the network and determining if it meets the defined security objectives
- ACAS utilizes Nessus to scan software to identify vulnerabilities and weak spots on the network.
- Nessus actively scans the network in an effort to detect defined vulnerabilities.
- ACAS also uses the Passive Vulnerability Scanner (PVS) to monitor network traffic at the packet level.
- PVS discovers new hosts added to a network, identifies ports that are passing traffic, and identifies when applications might be compromised.
- Administrators on the network are able to view the output from the ACAS server in a centralized software called Security Center (SC).
- Within SC, administrators make necessary adjustments and modifications to the ACAS and the network.
- The goal of the ACAS server is ultimately to make the environment as secure as possible

### VPN Server
- The VPN server acts as a secure tunnel connecting two networks.

## DETAILED THREAT ASSESSMENT REPORT

### Overview
- A detailed threat assessment report is a tool utilized by organizations to properly measure organizational readiness for probable threat actors, based on historical attacks
- Detailed threat assessments are granular and can be assembled in preparation of, or after, a security breach
- The goal of a detailed threat assessment report is to identify assets and information that might be affected during a cyber attack
- Included in the report is information regarding:
  - Threat actors
  - Events
  - Anomalies
  - Vulnerabilities
  - Assets of interest to be compromised

- Timeline of events
<img width="650" height="363" alt="image" src="https://github.com/user-attachments/assets/7d0f2153-b994-4196-bbd9-a0ffe1eb52a0" />

- Key Components Detailed Threat Assessment Report
  - A key function of a detailed threat assessment is the ability to determine the amount of risk an organization can expect to take on
  - A detailed threat assessment describes the risk through assessment of identified threats, vulnerabilities, and compensating controls to determine the likelihood a vulnerability could be exploited and the potential impact should the vulnerability be exploited
    <img width="1586" height="878" alt="image" src="https://github.com/user-attachments/assets/f65e8692-bd51-48a3-9c4a-704a20014a50" />

### Mapping Detailes Threat Assessment Report Info to Mitre ATTT&CK Framework
- MITRE ATT&CK is a curated knowledge base and model for cyber adversary behavior, reflecting the various phases of an adversary’s attack lifecycle and the platforms they are known to target
- At a high level, ATT&CK is a behavioral model that consists of the following core components:
  - **Tactics**: Denoting short-term, tactical adversary goals during an attack (the columns)
  - **Techniques**: Describing the means by which adversaries achieve tactical goals (the individual cells)
  - Documented adversary usage of techniques and other metadata (linked to techniques)

### Executive Summary
- The detailed threat assessment begins with a brief overview of the compromise or investigation.
- The overview includes the results of findings that occurred as part of a larger group of actions

### Key Findings
- Following the overview, the detailed threat assessment displays findings that support the overview.
- The findings provide more detail and artifacts that support the overall topic. 

- Included in the findings of a detailed threat assessment is a section devoted to the primary threat to the organization.


## MindMaps

### Overview of Mind Maps
  - Mind maps are visual diagrams utilizing two-dimensional structures with connecting lines to connect ideas and events
  - Connecting points to see how items relate to one another is an important benefit when dealing with elaborate information, such as during process planning, strategy development, and investigative events
  - An effective mind map shows the interconnectivity of individual points or events that assemble together to create a larger event or project
  - In cybersecurity, mind maps are effective for outlining and thinking through intricate events — often describing a breach or the investigative process that took place.
  - There are multiple relations and data points surrounding a single event within a cybersecurity breach or investigation. These events could be compromised user accounts, computers, or network equipment, all of which play a part in a chain of events
  - A cybersecurity mind map starts at the first sign of a breach and moves through the actions taken, how the actions  were linke d, and what the outcome was throughout the attack lifecycle.

### Mind Map Central Topic
- The mind map begins with a central topic or the basis of a compromise or investigation.
- The central topic is the desired unifying event that occurred as part of a larger group of actions.
- There is only one central topic conveyed in each mind map.

### Understanding Subtopics
- Subtopics are large steps or events taken during the breach or investigation
- Information in subtopics is more detailed than the central topic, however, they are still more general than an operational note
- In the cybersecurity context, the operational notes taken during an investigation would provide the information needed to populate subtopics
- Connecting each subtopic is the information related to the events.
- Related events share attributes and are the result of an action.
- They have a specific detail connecting them; these attributes would be granular-level details


# MODULE 5

## OPNOTES

### OPNOTES Overview
- OPNOTEs are important to the investigative and reporting lifecycle throughout the Cyberspace Operations (CO) process
- It is vital that each of the participating CDAs record standardized OPNOTEs.
- They must be clear and concise including, but not limited to, the following:
  - Time/date
  - Host name
  - Internet Protocol (IP) address
  - Description
- Taking detailed notes allows teams to work effectively, efficiently, and easily overcome issues with misleading and uncertain data.
- Creating detailed OPNOTEs provide both teams and system owners clarity on when and what was performed during the investigative process

### Structure of OPNOTEs
- The use of column headers is a common way of ensuring that OPNOTEs are consistent row to row and are easily consumed

- Date and Time
  - The Date and Time columns are based on the timeframe in which the action was performed or discovered
  - This is not the date and time in which an artifact was logged by a platform or tool
  - Log analysis date- and time-stamping is usually listed in a different column for timeline building later

- Subject
  - The Subject column header describes the subject of the findings or related artifacts
  - Commonly used attributes in this column include **IP address**, **Uniform Resource Locator (URL)**, **username**, **hostname**, **artifact**, **action**, or **indicator**

- Description
  - ﻿Always use concise, precise, and accurate information when describing the important action or artifact.
  - The Description column is the most critical column as it provides context and explanation for the occurrence

- Supporting Information
  - This column header refers to files of various types, which pertain to and support information listed in the Subject column.
  - Some examples of supporting information include **system logs**, **Security Information and Event Management (SIEM) events**, **tool output**, and **screenshots**

- Tags
  - The Tags column is used to electronically mark one or more notes with a single attribute.
  - This enables the user to search, filter, and group multiple related notes quickly and easily.

### Reccomendations
- Things you should do:
  - Create detailed digital OPNOTEs compiled with supporting information such as screenshots
  - Protect OPNOTEs and limit access to prevent unauthorized or undesired modification
  - Include physical notes taken when computing devices are not availableUse multiple platforms to take OPNOTEs, if necessary
  - Create opportunities for centralized logging of multiple participants
  - Backup OPNOTEs and supporting information
  - Follow all classification guidelines for proper handling and dissemination of information

- Things you should not do:
  - Save OPNOTEs to potentially infected hosts or networks Omit OPNOTEs because you are unsure or unfamiliar with the information
  - Stop recording out of laziness or assumption that someone else logged something
  - Omit notes because you made a mistakeLeave out information because it is sensitive in nature (however, follow classification guidelines)
  - Be afraid to use a mind map to convey complex relationships between log events
 

## Overview of the MITRE ATT&CK

### MITRE ATT&CK Framework
- MITRE’s ATT&CK is a framework for modeling cyber threat adversary behaviors in their varied complexity
- consists of a knowledge base of known behaviors, which characterizes those behaviors both at a high level for conceptual understanding and with the granular historical detail required to see how the model correctly fits actual attacks that have occurred.
- reflects the various phases of an adversary’s attack lifecycle and the platforms they are known to target, but is free from the rigidity of a linear attack chain.
- At a high level, ATT&CK is a behavioral model that consists of the following core components:
  - **Tactics**: Short-term, tactical adversary goals during an attack (the columns)
  - **Techniques**: The means by which adversaries achieve tactical goals (the individual cells)
  - **Documented adversary usage of techniques and other metadata** (linked to techniques). ATT&CK is not an exhaustive enumeration of attack vectors against software, but the documented operation can be used to contextualize the impact of an attack, the actors known to employ the technique, and other information.

- History of MITRE ATT&CK
  - The first ATT&CK model was created in September 2013, and focused primarily on the Windows enterprise environment
  - It was further refined in May 2015, with 96 techniques organized under nine tactics
  - Based on the methodology used to create the first ATT&CK model, a complementary knowledge base called PRE-ATT&CK was created to focus on left of exploit behaviors
  - As of 2021, ATT&CK includes techniques that cover:
    - **Enterprise platforms**: Windows, macOS, Linux, PRE, Azure Active Directory, Office 365, Google Workspace, Software as a Service (SaaS), Infrastructure as a Service (IaaS), Network, and Containers
    - **Mobile platforms**: Android and iOS
    - **Industrial Control Systems (ICS)**

- ATT&CK Matrix | Techniques
  - Below are the tactics included in the ATT&CK Matrix:
     1. Reconnaissance: Techniques that involve adversaries actively or passively gathering information that can be used to support targeting (e.g., staff/personnel, infrastructure, etc.).
     2. Resource Development: Techniques that involve adversaries creating, purchasing, or compromising/stealing resources that can be used to support targeting.
     3. Initial Access: Techniques that use various entry vectors to gain an initial foothold within a network (e.g., spearphishing link).
     4. Execution: Techniques that result in running attacker-controlled code on a local or remote system (e.g., PowerShell).
     5. Persistence: Techniques used to maintain persistent access to a system (e.g., logon scripts).
     6. Privilege Escalation: Techniques used to gain higher-level privileges on a system or network (e.g., process injection).
     7. Defense Evasion: Techniques used to avoid detection (e.g., Dynamic Linked Library [DLL] side-loading).
     8. Credential Access: Techniques for stealing credentials such as account names and passwords (e.g., Kerberoasting).
     9. Discovery: Techniques used to gain knowledge about the system and internal network (e.g., Network Sniffing).
     10. Lateral Movement: Techniques used to enter and control remote systems on a network from the already compromised host (e.g., Pass the Ticket). Attackers typically have to pivot through multiple machines — usually the weakest link in the chain of machines — to ultimately reach their end objective.
     11. Collection: Techniques used to gather information relevant to following through on the attacker’s objectives (e.g., input capture).
     12. Command and Control (C2): Techniques attackers may use to communicate with systems under their control; often disguised to look like normal Hypertext Transport Protocol (HTTP) traffic (e.g., domain fronting).
     13. Exfiltration: Techniques used to steal data from your network (e.g., exfiltration over web service).
     14. Impact: Techniques used to disrupt availability or compromise integrity by manipulating business and operational processes (e.g., firmware corruption). Impact is the result on your system after the attacker accomplishes their ultimate goal and is the most recently added tactic.

- The Cyber Kill Chain
  - The alternate Lockheed Martin Cyber Kill Chain® does an excellent job of adapting a centuries-old military model of targeting and affecting the object of an attack to the modern landscape of cyberspace
  - It also correctly captures what has been the general attack process of most early cyber attacks
  - The model also struggles to provide the granular detail that defenders in a world of rapidly changing technological landscapes require to implement effective mitigations and functional controls.
  - These details include **individual adversarial actions**, **connections between actions**, **relations between sequences of actions and tactical adversary objectives**, and **correlations with data sources**, **configurations**, and other countermeasures used for the security of a platform and domain

- The ATT&CK Framework
  - The ATT&CK framework is a dynamic model, evolving and updating to match the TTPs deployed by real-world threat actors
  - The TTPs in ATT&CK define adversarial behaviors within an attack lifecycle in a way that allows the behaviors to be more effectively mapped to corresponding defensive actions.
  - The ATT&CK model is also a useful construct to integrate threat intelligence and incident data together, in order to identify different threat actors and those actors' preferences for particular techniques
  - By maintaining such a dynamic model, ATT&CK struggles to provide a step-by-step blueprint for how attacks are conducted.

- Combining Models
  - ATT&CK and the Cyber Kill Chain can be complementary.
  - The detail that ATT&CK provides when combined with the ordered phases Cyber Kill Chain uses to describe high-level adversary objectives creates a powerful combination for learning how threat adversaries operate in cyberspace, but familiarity with a model eventually reveals how it can and should be broken.
  - The difference between these models is that ATT&CK is designed not to be broken, but rather adapted and updated.
 
### ATT&CK Navigator Overview
- The ATT&CK Navigator is a free and open-source tool provided by MITRE to visualize ATT&CK TTPs.
- It includes pre-loaded data for known attack group TTPs, as well as TTPs exploited by various pieces of malicious software
- Each cell in ATT&CK Navigator can be scored and colored, allowing ATT&CK Navigator to be used by defenders for multiple purposes including:
  - Visualizing sensor coverage and gaps by TTP
  - Visualizing TTPs used by threat actors
  - Comparing threat actor groups by TTPs
  - Visualizing an organization’s risk by applying scores for impact or likelihood to a TTP

- Attack navigator Controls
  - Selection Controls
    - Lock multi-tactic technique selection: Toggles whether selecting techniques also selects the same technique in other tactics
    - Search: Search for cells to be selected
    - Multi-select: Selects multiple techniques based on pre-loaded data like threat groups
    - Deselect: Deselects currently selected techniques
  - Layer Controls
    - Layer information: Contains the name and description of the layer, which can be edited by the user
    - Download layer as JSON: Downloads the current layer in JSON format
    - Export to Excel: Converts the current layer to Excel format and downloads it
    - Render layer to Scalable Vector Graphic (SVG): Generates an SVG image of the current layer
    - Filters: Presents options for filtering the displayed techniques
    - Sorting: Changes how techniques within each tactic are sorted
    - Color setup: Changes background colors for techniques based on user-assigned score
    - Show/hide disabled: Toggles whether or not disabled techniques are visible
    - Toggle view mode: Toggles between various view modes
  - Technique Controls
    - Toggle state: Disables or enables the selected technique
    - Background color: Sets a background color for the selected technique
    - Scoring: Specify a score for the selected technique
    - Comment: Sets a comment for the selected technique
    - Clear annotations: Clears any changes to the technique selected
   
### Practical Uses of ATT&CK
- Since the creation and adoption of the original ATT&CK framework, there have been new adaptations and tools developed.
- Each of these seeks to implement the framework into neighboring domains (such as cyberspace defense) or into practical spheres (such as security controls auditing or threat emulation).

- DeTT&CT
  - Detect Tactics, Techniques and Combat Threats (DeTT&CT) is a blue-team-focused adaptation of the ATT&CK framework.
  - It is designed specifically to enable defenders to assess their own data source quality, network and endpoint visibility, and detection coverage.
  - The tools provided by the product are used to score these areas, map coverage and likely threat actor behavior to an organization, and compare the areas to identify improvements and prioritize efforts.

- Atomic Red Team
  - Atomic Red Team is an automated adversary emulation framework used to test the effectiveness of security controls.
  - According to the creators, Atomic Red Team tests are small, highly-portable detection tests mapped to the MITRE ATT&CK Framework
 
- Mordor Project
  - The Mordor Project is a collection of pre-recorded datasets generated by simulating adversarial techniques to aid hunters in improving their detection abilities and decreases the number of false positives in an environment.
  - The data is categorized by platforms, adversary groups, tactics, and techniques defined in the MITRE ATT&CK Framework.
  - This data allows an organization to test a detection strategy or individual detection rule against simulated malicious events.

## Advanced Usage of MITRE ATT&CK

### Atomic Red Team Overview
- Background
  - Atomic Red Team is an open-source project maintained by Red Canary that contains a collection of tests.
  - Analysts use the tests to evaluate and detect certain TTPs mapped to ATT&CK techniques.
  - The tests are focused, have few dependencies, and are defined in a structured format that can be used by automation frameworks
  - Red Canary has also released an execution framework as a PowerShell module called `Invoke-AtomicRedTeam` that allows network defenders to run the tests.
  - The tests are small and enable highly portable detection.
  - Furthermore, the mapping to the MITRE framework provides network defenders with easily actionable tests to immediately evaluate their defenses against a broad spectrum of attacks.

- Key Beliefs of Atomic Red Team
  - Precision
    - Cyber defenders need to be able to test everything from specific technical controls to outcomes and should not operate with a hopes and prayers attitude toward detection.
    - Defenders need to know which of their controls a program can detect, and what it cannot.
    - Network defenders may not be able to detect every adversary, but they do need to know where their blind spots are to be able to implement the correct mitigating controls.
  - Speed
    - Most Atomic Red Team tests were written with the ability to be completed in less than five minutes.
    - Most security tests and automation tools take a tremendous amount of time to install, configure, and execute. Red Canary coined the term atomic tests to convey the fact that there was a simple way to decompose tests so most could be run in a few minutes.
  - Adaptability
    - Cyber defenders need to continuously learn and adapt to how adversaries operate.
    - Most network defenders do not have the ability to see a wide variety of adversary types and techniques crossing their networks.
    - Defenders only come across a fraction of the possible techniques being used, which makes collaboration within the cybersecurity community essential for seeing more adversarial TTPs.

      <img width="1504" height="1234" alt="image" src="https://github.com/user-attachments/assets/0e9160c3-d2dc-4999-962f-b018f53e9fb8" />

## Risk Mitigation Plan (RMP)

### Risk Mitigation | Strategies
- Risk mitigation options are based on both the probability of occurrence and the severity of consequences for an identified risk

  <img width="498" height="441" alt="image" src="https://github.com/user-attachments/assets/58c586d5-6ea3-4172-8ffe-70a81a7e6c8f" />

- Risk mitigation strategies include:
  - Assume/Accept
    - This risk mitigation strategy **acknowledges the existence of a particular risk**, and makes a **deliberate decision to accept it** without engaging in special efforts to control it
    - Approval by mission partners and/or network owners is required to implement this measure
    - In order to successfully mitigate risk in this manner, mission partners must collaborate with the operational users to create a collective understanding of risks and their implications.
    - Risks should be characterized as impacting traditional cost, schedule, and performance parameters and potentially degrading mission performance due to reduced technical performance or capability
    - Ensure that they understand the vulnerabilities affecting a risk, countermeasures that can be performed, and residual risk that may occur. 
  - Avoid
    - This risk mitigation strategy **adjusts operational requirements or constraints to eliminate or reduce the risk or adapt to the risk**
    - This adjustment could be accommodated by a change in funding, schedule, or technical requirements.
    - Providing stakeholders with projections of adjustments needed to reduce risk associated with technology maturity and identifying any impacts resulting from dependencies on other efforts increases stakeholder buy-in.
    - This information better enables mission partners and network owners to interpret the operational implications of an avoid option.
  - Control
    - This risk mitigation strategy **implements actions to minimize the impact or likelihood of the risk**
    - A mission partner successfully controls risks by performing analysis of various mitigation options.
    - In developing options for controlling risk in an operation, seek out potential solutions from similar risk situations of other partner organizations, industry, and academia
    - When considering a solution from another organization, take special care in assessing any **architectural changes** needed and their implications.
    - It is worth noting that when the severity of risk is high enough, controlling the risk is often the only appropriate strategy, as accepting or avoiding the risk results in unacceptable potential impact.
  - Transfer
    - In this strategy, **reassign organizational accountability**, **responsibility**, and **authority** to another stakeholder willing to accept the risk.
    - It may make sense when the risk involves a narrow, specialized area of expertise not normally found in mission partner organizations.
    - However, transferring a risk to another organization can result in dependencies and loss of control that may have their own complications. 
  - Watch/Monitor
    - This risk mitigation strategy requires **monitoring the environment for changes** that affect the nature and/or the impact of the risk, and is often employed in conjunction with other mitigation strategies.
    - mission partners should periodically reassess the basic assumptions associated with the risk
    - The environment should be routinely scanned to ascertain any changes that affect the nature or impact of the risk.
    - The risk may have sufficiently changed such that the current mitigation is ineffective, or it may have diminished to where the resources devoted to it may be redirected.
   
### Risk Mitigation | Techniques
- MITRE ATT&CK Enterprise Mitigations
  - After the appropriate strategy is selected to fit the mission partner constraints and the severity of risk, an effective mitigation technique must be identified to fulfill that strategy.
  - The following are standardized mitigations in response to known attack vectors

### Risk Assessment | The NIST Risk Assessment Process
- 
<img width="1504" height="1058" alt="image" src="https://github.com/user-attachments/assets/20f7b4ac-62b2-4f62-800a-5ae59617f5ea" />

- Identify Threat Sources and Events
  - CPTs must determine the types of threat sources, threat events, and level of detail to be considered during engagements that include a risk assessment.
  - The descriptions of threat events can likewise be expressed in highly-general terms (e.g., phishing, Distributed Denial-of-Service [DDoS]) or in highly-specific terms (e.g., the names of specific information systems, technologies, organizations, roles, or locations).
  - The **MITRE ATT&CK framework** is especially helpful in this threat framing and source description process.

- Identify vulnerabilities and predisposing COnditions
  - In this step, CPTs determine the types of vulnerabilities that are to be considered during risk assessments and the level of detail provided in the vulnerability descriptions.
  - The CPT and the supported organization discuss the supported organization’s vulnerability identification process.
  - Vulnerabilities can be associated with organizational information systems (e.g., hardware, software, firmware, internal controls, and security procedures) or the environments in which those systems operate (e.g., organizational governance, external relationships, mission/business processes, enterprise architectures, and information security architectures).
 
- Determine Likelihood of occurrence
  - During this step, CPTs determine the likelihood that an adversary exploits vulnerabilities discovered in the previous step.
  - NIST 800-30 describes this concept as follows:
    - The likelihood of occurrence is a weighted risk factor based on an analysis of the probability that a given threat is capable of exploiting a given vulnerability (or set of vulnerabilities).
    - The likelihood risk factor combines an estimate of the likelihood that the threat event will be initiated with an estimate of the likelihood of impact (i.e., the likelihood that the threat event results in adverse impacts).
    - For adversarial threats, an assessment of likelihood of occurrence is typically based on: (i) adversary intent; (ii) adversary capability; and (iii) adversary targeting.
    - For other than adversarial threat events, the likelihood of occurrence is estimated using historical evidence, empirical data, or other factors.
    - Note that the likelihood that a threat event will be initiated or will occur is assessed with respect to a specific time frame (e.g., the next six months, the next year, or the period until a specified milestone is reached).
 
- Determine Magniturde of Impact
  - CPTs assist network owners and commanders in determining potential adverse impacts to a mission partner in terms of operations (e.g., missions, functions, image, and reputation), organizational assets, individuals, other organizations, and the Nation.
  - They describe impact determinations and any assumptions related to the impact determination process, particularly addressing specific mission/business processes or information resources (e.g., information, personnel, equipment, funds, and IT).
  - They describe impact determinations and any assumptions related to the impact determination process, particularly addressing specific mission/business processes or information resources
 
- Determine Risk
  - Risk tolerance is determined as part of the organizational risk management strategy to ensure consistency across the organization
  - Organizations also provide guidance on how to identify reasons for uncertainty when risk factors are assessed, since uncertainty in one or more factors propagates to the resulting evaluation of level of risk, and how to compensate for incomplete, imperfect, or assumption-dependent estimates
  - Consideration of uncertainty is especially important when organizations consider Advanced Persistent Threats (APT) since assessments of the likelihood of threat event occurrence can have a great degree of uncertainty.
  - To compensate, organizations can take a variety of approaches to determine likelihood, ranging from assuming the worst-case likelihood (certain to happen in the foreseeable future) to assuming that if an event has not been observed, it is unlikely to happen.
  - Organizations also determine what levels of risk (combination of likelihood and impact) indicate that no further analysis of any risk factors is needed. NIST uses a nonnumerical qualitative description for how to assess the risk (e.g., very low, low, medium, high, and very high).

### Risk Assessment | The USCYBERCOM Risk Assessment Methodology
- Another way of assessing risk is by determining risk at the intersection of a threat and a vulnerability influenced by likelihood and impact.
- According to CWP 3-33.4:
  - United States Cyber Command (USCYBERCOM) and subordinate commanders use the criticality, threat, and vulnerability methodology to assess risk and identify priority for CPT task management.

- Criticality
  - This criterion derives from the DoD determination of which critical systems or assets would have a debilitating impact on security, public health, or safety if incapacitated or destroyed.
  - Refer to CWP 3-33.4 Chapter 3, Section 4.c.(7).(a) for more information.
  - NIST SP 800-60 defines criticality as:
    - A measure of the degree to which an organization depends on the information or information system for the success of a mission or of a business function.
   
- Threat
  - The threat methodology is a characterization of the possible threat sources and the threat events that are likely to be encountered during the protection of the mission partner network
  - These risk factors are derived from threat intelligence provided by the CPT All-Source Analyst cell, MITRE ATT&CK Navigator overlays of known threats (such as the overlays developed during M5L2 Overview of MITRE ATT&CK), or the results of a Threat Assessment or Events/Anomalies report developed earlier during CPT assess operations
  - CWP 3-33.4, Appendix D describes those sections of the RMP as follows:
    <img width="1506" height="200" alt="image" src="https://github.com/user-attachments/assets/b5c602de-66a0-4aa3-ae30-74b32ec04f1f" />

- Vulnerability
  - The vulnerability methodology is a characterization of actual avenues of attack available to potential threat actors for Malicious Cyberspace Activity (MCA)
  - These are either highly-technical true or false determinations of technological weakness, or programatic non-technical determinations of compliance with industry standard policies and procedures
  - CWP 3-33.4, Appendix D describes the vulnerability section of the RMP as follows:
    <img width="1506" height="157" alt="image" src="https://github.com/user-attachments/assets/52b393c5-d60c-4215-886c-e1060ff6c4c3" />

- Likelihood
  - This factor is a simple probability that the expected threat sources and events impact the mission partner network.
  - The development of that probability is more subjective and eased by experience, but can be aided by industry-standard tools, such as ACAS and MITRE ATT&CK Navigator, which simplifies the comparison of threats and vulnerabilities.

- Impact
  - This factor is heavily influenced by the mission partner’s own asset prioritization, key terrain analysis, and criticality assignment.
  - The higher value that a specified asset possesses, the higher the potential impact is of a vulnerability leading to harm on the asset.
  - CWP 3-33.4, Appendix D describes these sections of the RMP as follows:
    <img width="1506" height="437" alt="image" src="https://github.com/user-attachments/assets/9a8ad84d-e3d0-4956-b38d-5223b3065b99" />

<img width="1504" height="838" alt="image" src="https://github.com/user-attachments/assets/058a40f1-9713-4825-9655-f090689780d7" />


# MODULE 6

## Command Shell & Batch Files

### IOC's
<img width="1950" height="1630" alt="image" src="https://github.com/user-attachments/assets/081d663a-9a85-4170-92c4-ab9f37f4c229" />

### Windows CMD Shell
- CMD has several built-in commands, such as dir (lists the current directory), cd (changes directory), as well as the ability to run executable binaries
- The CMD CLI application provides an interface to the OS
- The processes ConHost.exe and CMD show as running processes; ConDrv.sys is the Windows kernel driver that provides the communication infrastructure between ConHost and one or more CLI applications.

### Batch Files
- Windows originally used batch files as a way to perform a set batch of saved commands
- These commands are executed non-interactively as a script that has some conditional flow control to branch which commands are executed under specific circumstances
- Batch files contain Windows commands along with some flow control and comparison operators that are saved in a text file with a .bat or .cmd extension
- The .cmd extension was introduced with the Windows NT family of OSs and were executed with CMD instead of the older COMMAND.COM.
- COMMAND.COM is no longer included on Windows OSs and CMD executes both .bat and .cmd files as batch scripts.
- Batch files are plain text files most commonly edited in notepad.exe.

### Variables
- Variables in batch files are case-sensitive and are assigned using the set command.
- Variables from an interactive CMD session are case-insensitive.
- Often localized variables in a batch file use lowercase variable names while system-wide environmental variables are uppercase
- The set command does not check to see if a variable already exists; it holds data
- Variables are read by surrounding the variable name with the % operator
- To set a variable, the set command is used, and using an environment variable involves surrounding it with % to indicate that it is a variable
- Generally, the setx command should only be used when permanently altering the environment variable is desired.
- The setx command operates off the current user, rather than system environment variables by default
  <img width="1950" height="1180" alt="image" src="https://github.com/user-attachments/assets/ea0d93bc-5676-4ba1-9b13-49cd7569c2d1" />

### Loops and Conditionals
- The basic structure of the if command is:
      ``if [NOT] condition (command) [else (command)]
        if [NOT] ERRORLEVEL number (command)
        if [NOT] string1==string2 (command)
        if [NOT] EXIST filename command
      ``
- not: Specifies that the command to be executed initiates if the condition is false.exist: Checks for the existence of a file or directory. In order to ensure the tested value is a directory and not a file, checking for a device file, such as NULL, may be used (e.g., exist “C:\NewFolder\NULL”)errorlevel: Compares the last returned errorlevel against a specified value. For example, errorlevel 0 checks for a return value of 0 (by convention, no error returned from the previous command). The error level may not be reset on some built-in commands if .bat files are used.string1==string2: Checks if the two string values are the same (e.g., %COMPUTERNAME%=="SYSTEM1” checks if the computer’s name is SYSTEM1).string1 OPERATOR string2: Compares the two values using the three letter operator:EQU: Equal toNEQ: Not equal toLSS: Less thanLEQ: Less than or equal toGTR: Greater thanGEQ: Greater than or equal to

- `if not exist "C:\NewFolder\NULL" mkdir "C:\NewFolder"`

### FOR Statement
- `for %variable IN (set) DO command [command-parameters]`
-  The for command is used to iterate each item in a set and perform some action/command.
-  The variable used as the iterator — %variable in the above command outline — is a single character in the range a-z or A-Z, and is referenced as %%a or %%Z (%%z and %%Z are different variables).
-  The use of the extra % operator is used in batch files and not from the CLI (where it is a single %).
-  The various types of iterations are based on the switches below:
  - /l: Series of values
  - /f: Series of files
  - /d: Series of directories
  - /r: Each item in a directory tree
- `for /l %%variable in (start,step,end) do (command)`
- `for /l %%A in (0,2,10) do echo %%A`
- two percent signs are used for BATCH FILES and single is used in CLI.
- Looping through directories, recursively: `for /r "%USERPROFILE%" %%D in (*) do echo %%D`
- Looping through directories for .bat files recursively: `for /r "%USERPROFILE%" %%D in (*.bat) do echo %%D`
- Parsing File Content and Output: `for /f ["options"] %%variable in (source) do (command)`
  - `@echo off
      for /f "tokens=1-4" %%A in (hosts.txt) do ( echo host: %%A IP Address: %%B Department: %%C Email: %%D)`

### GOTO Statements
- Batch files support labels and the goto operand for program flow
- Labels are specified by giving the label name preceded by :
- The goto command is followed by the label specifying a location in the batch file to start executing instructions from next, which is a way to control the order in which instructions are executed.
  ```
  @echo off
  if "%1"=="" (echo Error: No arguments) & (goto EXIT)
  if "%1"=="1" goto SUBROUTINE1
  if "%1"=="2" goto SUBROUTINE2
  if "%1"=="3" goto SUBROUTINE3
  goto EXIT
  
  :SUBROUTINE1
  echo This is subroutine 1
  goto EXIT
  
  :SUBROUTINE2
  echo This is subroutine 2
  goto EXIT
  
  :SUBROUTINE3
  echo this is subroutine 3
  goto EXIT
  
  :EXIT
  echo exiting...
  ```

### Powershell
- PowerShell is a CLI shell and scripting language designed specifically for system administration
- PowerShell has a rich expression parser and a fully developed scripting language
- The PowerShell Integrated Scripting Environment (ISE) is a host application for PowerShell
- In PowerShell ISE, you can run commands and write, test, and debug scripts in a single Windows-based GUI with multiline editing, tab completion, syntax coloring, selective execution, context-sensitive help, and support for right-to-left languages.
- PowerShell ISE allows users to utilize menu items and keyboard shortcuts to perform many of the same tasks that are executed in the Windows PowerShell console.
- to set a line breakpoint in a script, right-click the line of code, and select **Toggle Breakpoint**.
- Cmdlets are similar to Windows commands, but provide a more extensible scripting language
- Powershell Features
  - Cmdlets: Cmdlets perform common system administration tasks such as managing the registry, services, processes, event logs, and using Windows Management Instrumentation (WMI).
  - Task-oriented: PowerShell scripting language is task-based and provides support for existing scripts and CLI tools.
  - Consistent design: As cmdlets and system data stores use common syntax, and have common naming conventions, data sharing is easy. The output from one cmdlet can be pipelined to another cmdlet without manipulation.
  - Simple to use: Simplified, command-based navigation lets users navigate the registry and other data stores similar to the file system navigation.
  - Object-based: PowerShell possesses powerful object manipulation capabilities. Objects can be sent to other tools or databases directly.
  - Extensible interface: PowerShell is customizable as independent software vendors and enterprise developers can build custom tools and utilities using PowerShell to administer their software.
- Cmdlet vs Command
  - Cmdlets are .NET Framework class objects; not just stand-alone executables.
  - Cmdlets are easily constructed from as few as a dozen lines of code.
  - Parsing, error presentation, and output formatting are not handled by cmdlets. It is done by the PowerShell runtime.
  - Cmdlets process works on objects not on text stream, and objects can be passed as output for pipelining.
  - Cmdlets are record-based as they process a single object at a time.

#### SYNTAX
- Create a new Directory: `New-Item -Path 'C:\users\trainee\temp' -ItemType Directory`
- Copy a folder to a new folder: `Copy-Item 'C:\users\trainee\temp' 'C:\users\trainee\temp2'`
- Remove an Item: `Remove-Item 'C:\users\trainee\temp2'`
- Check for existance of a folder: `Test-Path 'C:\users\trainee\new_temp'

### Powershell Scripts
- PowerShell scripts are stored in .ps1 files
- A user can check this policy by running the Get-ExecutionPolicy command in PowerShell:
- The Get-ExecutionPolicy command returns one of the following values:
  - **Restricted**: No scripts are allowed (individual commands are still permitted). This is the default setting for workstations and client systems; it appears the first time the command is executed.
  - **AllSigned**: Run scripts signed by a trusted developer. With this setting in place, before executing, a script confirms that you want to run it.
  - **RemoteSigned**: Run your own scripts or scripts signed by a trusted developer. This is the default policy for servers. Scripts running remotely or those downloaded from the internet still must be signed by a trusted publisher.
  - **Unrestricted**: Run any script you want.
- Cmdlet Format
  - A cmdlet always consists of a **verb** (or a word that functions as a verb) and a **noun**, separated with a hyphen (the verb-noun rule).
  - Some of the most common verbs include:
    - **Get**: To get something
    - **Set**: To define something
    - **Start**: To run something
    - **Stop**: To stop something that is running
    - **Out**: To output something
    - **New**: To create something (new is not a verb, of course, but it functions as one)
  <img width="680" height="295" alt="image" src="https://github.com/user-attachments/assets/24006f88-8304-4c51-94ab-18a9929104e9" />


## BASH

### Intro to Bash
- Bash is an interpreter that executes commands from an interactive interface, from standard input, or from a file
- Bash is also known as the GNU (GNU not Unix) Bourne-Again Shell as it is fully compatible with the previous standard Bourne shell sh.
- Bash provides a standard environment to execute built-in commands or other commands provided by the OS on which it is running
- Not every system has a Graphical User Interface (GUI) so it is important that analysts and defenders have the ability to efficiently navigate and use text-based terminal shells
- Remote access and configuration is also often done over a text-based terminal through a secure terminal session via programs like Secure Shell (SSH).
- The ability to link commands and run them in scripts make shells like Bash extremely useful in sifting through large amounts of data and pulling out the pieces that are important to the analyst or defender.
- Since Bash is interpreted, the same commands run interactively from a command prompt can be saved into a file as a script to be run at a later date, or perform automated or complex operations repeatedly
- Unix/Linux OSs typically employ a shell for users as their login environment and to interact with the system.
- Bash is also invoked to execute commands non-interactively, or as a subshell of Bash or another shell.
- When a user logs into a Linux system that has the user’s login shell set to Bash, one of the system processes starts Bash in the context of the user’s profile, which includes user system accesses and security permissions
- There are also files that are read/executed when the shell exits normally.
- This is useful to set things like the default PATH variable for login shells.
- **Inserting commands or scripts into these files is one of the ways Malicious Cyberspace Activities (MCA) execute files in the context of another user, maintain persistence, or harvest credentials**
  <img width="776" height="206" alt="image" src="https://github.com/user-attachments/assets/9df21c3a-3461-4c98-bb82-3b9243ce4f3f" />
  <img width="775" height="376" alt="image" src="https://github.com/user-attachments/assets/b1a49084-2222-442f-a5f9-aec384d3665b" />
- When Bash is started as an interactive shell that is not a login shell, the file ~/.bashrc is the only file that is read, unless the -norc option is sent to the shell to not read the ~/.bashrc file
- when Bash is started non-interactively, it inherits the contents of the $BASH_ENV variable, if it exists
- Z shell, or zsh, is very similar to Bash in that it is backwards compatible with the Bourne shell (sh) and has many of the same capabilities as Bash, but uses different files and additional/alternate environment variables
  <img width="768" height="555" alt="image" src="https://github.com/user-attachments/assets/9699ebbf-3873-4a85-940e-773dbe25553a" />

## BASH PROMPT
- A $ indicates a non-root (user Identifier [ID] other than 0) user and a # indicates commands are executed with root (user ID of 0) privileges.
- The standard prompt is set in the PS1 variable and seen with the echo $PS1 command.
  <img width="970" height="783" alt="image" src="https://github.com/user-attachments/assets/9100997e-f1d8-4c5a-af95-b5d82b272cff" />

- The following example shows the full current working directory and the time in 24-hour format (HH:MM:SS):
  - ```PS1="[\u@\h \w \T]\\$ "```
 
### Parameters
- **Parameters** are containers that store values including a name, a number, or a special character.
- A **variable** is a container that has an associated name and is declared using the format `name=value`
- Bash has several parameters that have special meanings or expansions. Some of the most common expansions include:
  <img width="550" height="800" alt="image" src="https://github.com/user-attachments/assets/a0cbd627-e7a6-49bb-ae31-4c91b267bf26" />

- Bash keeps a history containing a list of commands run from an interactive shell
- The number of commands saved is controlled by the **HISTSIZE** variable and defaults to 500 commands
- The **HISTCONTROL** and **HISTIGNORE** variables are set to not save commands that are duplicates or are prefaced with the characters described in the variable
- The options are **ignorespace** and **ignoredup**, or **ignoreboth** to set both options.
- To add ignorespace to the HISTCONTROL variable, enter the command:
  - ```HISTCONTROL=$HISTCONTROL:ignorespace```
- Bash history expansion is a powerful feature that allows a user to refer to a previous command without having to enter the entire command again. Some common history expansions are:
  <img width="963" height="503" alt="image" src="https://github.com/user-attachments/assets/3ce191ad-1cb3-4380-883f-0c5cde120df1" />

### Re-Introduction to VI/Vim
- It uses the same basic functions as Vi but allows for enhanced features like syntax highlighting, external plugins, multi-level undo/redo, screen splitting for editing multiple files, and other features documented on the Vim manual page
- Vim has two main modes: command mode (default) and insert-text mode
  
### MAN PAGES
- There may be multiple manual pages for the same object if it is used in different sections
- To open a manual page from a specific section, use the format man n command where n is the section number of the desired manual page
-  The spacebar or CTRL+F advances the manual one page at a time, CTRL+B moves back one page at a time, gg moves to the start of the manual, SHIFT+G moves to the end of the manual, /STRING searches for the next occurrence of the text after the slash, and Q exits the manual.
  <img width="963" height="563" alt="image" src="https://github.com/user-attachments/assets/c4cf5ad6-49e4-4aae-a97d-231466fbf684" />

### CHMOD
<img width="963" height="455" alt="image" src="https://github.com/user-attachments/assets/ef47d1c6-8f01-4860-ac03-32c74a036dde" />
<img width="963" height="337" alt="image" src="https://github.com/user-attachments/assets/9c89c533-56cb-4a7e-9efa-43d9ef04676c" />
- ```chmod u+x <script>```

### Standard Input, Standard Output, and Standard Error
<img width="963" height="236" alt="image" src="https://github.com/user-attachments/assets/ad5da30d-1f0f-480c-bc00-2ca4b65b0ae2" />
- Typically for Linux-based systems, a special memory-based filesystem is mounted containing information on all the processes running on the system, including the FDs the program has opened and is mounted as /proc.
- There are three standard files, also called streams, that are associated with input and output for programs: **/dev/stdin**, **/dev/stdout**, and **/dev/stderr**.
- Streams have two ends, a source and a destination like a water hose or a pipe, and contain data.
- Two additional Special Files
  <img width="963" height="384" alt="image" src="https://github.com/user-attachments/assets/db45ec98-66ba-497f-bbe9-679d1a6eaeb2" />

  <img width="963" height="786" alt="image" src="https://github.com/user-attachments/assets/981ee8a7-a434-46cb-b63d-770b8ac55e1c" />

### List of Commands

<img width="613" height="471" alt="image" src="https://github.com/user-attachments/assets/e9a4dd97-1b3a-4ac4-b4cc-393a2ce0e9d9" />


## Windows Management Instrumentation (WMI)


































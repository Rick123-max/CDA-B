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
    - During the Orders Production and Dissemination, the operational-level orders production team receives the final outputs from the capability analysis and force allocation. Outputs are developed into a formal operations order or TASKORD (or service specific mission type order). The Operational Control (OPCON) headquarters’ Operational Planning section maintains the responsibility to develop and publish orders (including coordinating or special instructions, or similar guidance) to direct and guide CPT operations. Once produced, the final order and special instructions are published and disseminated to the CPT for action; to the supported commander if a formal command relationship exists; or as a courtesy copy to the supported commander if a formal command relationship does not exist.
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


























    

    





     














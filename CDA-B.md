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


**M1036** Account Use Policies: Configure features related to account use like login attempt lockouts, specific login times, etc.
**M1015** Active Directory (AD) Configuration: Configure AD to prevent use of certain techniques; use Security Identifier (SID) filtering, etc.
M1049 Antivirus/Antimalware: Use signatures or heuristics to detect malicious software
M1013 Application Developer Guidance: Describes any guidance or training given to application developers to avoid introducing security weaknesses that an adversary may take advantage of
M1048 Application Isolation and Sandboxing: Restrict execution of code to a virtual environment on or in transit to an endpoint system
M1047 Audit: Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses
M1040 Behavior Prevention on Endpoint: Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems; could include suspicious process, file, Application Programming Interface (API) call, etc. behavior
M1046 Boot Integrity: Use secure methods to boot a system and verify the integrity of the Operating System (OS) and loading mechanisms
M1045 Code Signing: Enforce binary and application integrity with digital signature verification to prevent untrusted code from executing
M1043 Credential Access Protection: Use capabilities to prevent successful credential access by adversaries; including blocking forms of credential dumping
M1053 Data Backup: Take and store data backups from end user systems and critical servers; ensure backup and storage systems are hardened and kept separate from the corporate network to prevent compromise
M1042 Disable or Remove Feature or Program: Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries
M1055 Do Not Mitigate: Associate techniques that mitigation might increase risk of compromise and, therefore, mitigation is not recommended
M1041 Encrypt Sensitive Information: Protect sensitive information with strong encryption
M1039 Environment Variable Permissions: Prevent modification of environment variables by unauthorized users and groups
M1038 Execution Prevention: Block execution of code on a system through application control, and/or script blocking
M1050 Exploit Protection: Use capabilities to detect and block conditions that may lead to or be indicative of a software exploit occurring
M1037 Filter Network Traffic: Use network appliances to filter ingress or egress traffic and perform protocol-based filtering; configure software on endpoints to filter network traffic
M1035 Limit Access to Resource Over Network: Prevent access to file shares, remote access to systems, unnecessary services; mechanisms to limit access may include use of network concentrators, Remote Desktop Protocol (RDP) gateways, etc.
M1034 Limit Hardware Installation: Block users or groups from installing or using unapproved hardware on systems including Universal Serial Bus (USB) devices
M1033 Limit Software Installation: Block users or groups from installing unapproved software
M1032 Multi-factor Authentication: Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator
M1031 Network Intrusion Prevention: Use intrusion detection signatures to block traffic at network boundaries
M1030 Network Segmentation: Architect sections of the network to isolate critical systems, functions, or resources; use physical and logical segmentation to prevent access to potentially sensitive systems and information; use a Demilitarized Zone (DMZ) to contain any internet-facing services that should not be exposed from the internal network; configure separate Virtual Private Cloud (VPC) instances to isolate critical cloud systemsM1028 Operating System Configuration: Make configuration changes related to the OS or a common feature of the OS that results in system hardening against techniques
M1027 Password Policies: Set and enforce secure password policies for accounts
M1056 Pre-compromise: Any applicable mitigation activities that apply to techniques occurring before an adversary gains initial access, such as reconnaissance and resource development techniques
M1026 Privileged Account Management: Manage the creation, modification, use, and permissions associated with privileged accounts, including SYSTEM and root
M1025 Privileged Process Integrity: Protect processes with high privileges that can be used to interact with critical system components through use of protected process light, anti-process injection defenses, or other process integrity enforcement measures
M1029 Remote Data Storage: Use remote security log and sensitive file storage where access can be controlled better to prevent exposure of intrusion detection log data or sensitive information
M1022 Restrict File and Directory Permissions: Restrict access by setting directory and file permissions that are not specific to users or privileged accounts
M1044 Restrict Library Loading: Prevent abuse of library-loading mechanisms in the OS and software to load untrusted code by configuring appropriate library-loading mechanisms and investigating potentially vulnerable software
M1024 Restrict Registry Permissions: Restrict the ability to modify certain hives or keys in the Windows registry
M1021 Restrict Web-Based Content: Restrict use of certain websites, block downloads/attachments, block Javascript, restrict browser extensions, etc.
M1054 Software Configuration: Implement configuration changes to software (other than the OS) to mitigate security risks associated with how the software operates
M1020 Secure Sockets Layer (SSL)/Transport Layer Security (TLS) Inspection Break and Inspect: SSL/TLS sessions to look at encrypted web traffic for adversary activity
M1019 Threat Intelligence Program: Helps an organization generate their own threat intelligence information and track trends to inform defensive priorities to mitigate risk
M1051 Update Software: Perform regular software updates to mitigate exploitation riskM1052 User Account Control: Configure Windows User Account Control to mitigate risk of adversaries obtaining elevated process access
M1018 User Account Management: Manage the creation, modification, use, and permissions associated with user accounts
M1017 User Training: Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction
M1016 Vulnerability Scanning: Find potentially exploitable software vulnerabilities to remediate them

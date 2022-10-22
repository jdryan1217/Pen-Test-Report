

    Cybersecurity
Penetration Test Report Template










MegaCorpOne

Penetration Test Report

Jray Pensters, LLC





Confidentiality Statement

This document contains confidential and privileged information from MegaCorpOne Inc. (henceforth known as MegaCorpOne). The information contained in this document is confidential and may constitute inside or non-public information under international, federal, or state laws. Unauthorized forwarding, printing, copying, distribution, or use of such information is strictly prohibited and may be unlawful. If you are not the intended recipient, be aware that any disclosure, copying, or distribution of this document or its parts is prohibited.


Table of Contents

Confidentiality Statement	2
Contact Information	4
Document History	4
Introduction	5
Assessment Objective	5
Penetration Testing Methodology	6
Reconnaissance	6
Identification of Vulnerabilities and Services	6
Vulnerability Exploitation	6
Reporting	6
Scope	7
Executive Summary of Findings	8
Grading Methodology	8
Summary of Strengths	9
Summary of Weaknesses	9
Executive Summary Narrative	10
Summary Vulnerability Overview	11
Vulnerability Findings	12
MITRE ATT&CK Navigator Map	13



Contact Information

Company Name
Jray Pensters, LLC
Contact Name
Josh Ryan
Contact Title
Penetration Tester
Contact Phone
555.224.2411
Contact Email
josh@jrays.com





Document History

Version
Date
Author(s)
Comments
001
10/11/2022
Joshua Ryan
(just one copy - no revisions)




























Introduction

In accordance with MegaCorpOne’s policies, Jray Pensters, LLC (henceforth known as Jray) conducts external and internal penetration tests of its networks and systems throughout the year. The purpose of this engagement was to assess the networks’ and systems’ security and identify potential security flaws by utilizing industry-accepted testing methodology and best practices. The project was conducted on a number of systems on MegaCorpOne’s network segments by Jray during September and October of 2022.

For the testing, Jray focused on the following:

Attempting to determine what system-level vulnerabilities could be discovered and exploited with no prior knowledge of the environment or notification to administrators.
Attempting to exploit vulnerabilities found and access confidential information that may be stored on systems.
Documenting and reporting on all findings.

All tests took into consideration the actual business processes implemented by the systems and their potential threats; therefore, the results of this assessment reflect a realistic picture of the actual exposure levels to online hackers. This document contains the results of that assessment.

Assessment Objective

The primary goal of this assessment was to provide an analysis of security flaws present in MegaCorpOne’s web applications, networks, and systems. This assessment was conducted to identify exploitable vulnerabilities and provide actionable recommendations on how to remediate the vulnerabilities to provide a greater level of security for the environment.

Jray used its proven vulnerability testing methodology to assess all relevant web applications, networks, and systems in scope. 

MegaCorpOne has outlined the following objectives:

Table 1: Defined Objectives

Objective
Find and exfiltrate any sensitive information within the domain.
Escalate privileges to domain administrator.
Compromise at least two machines.





Penetration Testing Methodology


Reconnaissance 

Jray begins assessments by checking for any passive (open source) data that may assist the assessors with their tasks. If internal, the assessment team will perform active recon using tools such as Nmap and Bloodhound.

Identification of Vulnerabilities and Services

Jray uses custom, private, and public tools such as Metasploit, hashcat, and Nmap to gain perspective of the network security from a hacker’s point of view. These methods provide MegaCorpOne with an understanding of the risks that threaten its information, and also the strengths and weaknesses of the current controls protecting those systems. The results were achieved by mapping the network architecture, identifying hosts and services, enumerating network and system-level vulnerabilities, attempting to discover unexpected hosts within the environment, and eliminating false positives that might have arisen from scanning. 

Vulnerability Exploitation

Jray normal process is to both manually test each identified vulnerability and use automated tools to exploit these issues. Exploitation of a vulnerability is defined as any action we perform that gives us unauthorized access to the system or the sensitive data. 

Reporting

Once exploitation is completed and the assessors have completed their objectives, or have done everything possible within the allotted time, the assessment team writes the report, which is the final deliverable to the customer.


Scope

Prior to any assessment activities, MegaCorpOne and the assessment team will identify targeted systems with a defined range or list of network IP addresses. The assessment team will work directly with the MegaCorpOne POC to determine which network ranges are in-scope for the scheduled assessment. 

It is MegaCorpOne’s responsibility to ensure that IP addresses identified as in-scope are actually controlled by MegaCorpOne and are hosted in MegaCorpOne-owned facilities (i.e., are not hosted by an external organization). In-scope and excluded IP addresses and ranges are listed below. 

IP Address/URL
Description
172.22.117.0/24
MCO.local
*.Megacorpone.com
MegaCorpOne internal domain, range and public website





Executive Summary of Findings

Grading Methodology

Each finding was classified according to its severity, reflecting the risk each such vulnerability may pose to the business processes implemented by the application, based on the following criteria:

Critical:	 Immediate threat to key business processes.
High:		 Indirect threat to key business processes/threat to secondary business processes.
Medium:	 Indirect or partial threat to business processes. 
Low:		 No direct threat exists; vulnerability may be leveraged with other vulnerabilities.
Informational:    No threat; however, it is data that may be used in a future attack.

As the following grid shows, each threat is assessed in terms of both its potential impact on the business and the likelihood of exploitation:





Summary of Strengths

While the assessment team was successful in finding several vulnerabilities, the team also recognized several strengths within MegaCorpOne’s environment. These positives highlight the effective countermeasures and defenses that successfully prevented, detected, or denied an attack technique or tactic from occurring. 

After attempting to login with the credential we gained we were still unable to log in as administrator. It wouldn’t let us get into the account through the user interface even though we set the tstark as the admin with password.

![Semantic description of image](https://github.com/jdryan1217/Pen-Test-Report/blob/main/Screen%20Shots/1.jpg)

IP 172.22.117.150 didn’t have all ports open, 977 closed tcp ports were not shown.
IP 172.22.117.20 only had 4 ports open and 996 closed tcp ports. IP 172.22.117.10 only had 11 ports open and 989 closed tcp ports. IP 172.22.117.100 only had 3 open ports and 996 closed tcp ports.

The fact that there were credentials set up for the users was on the plus side. No one had open access or accounts without passwords set up.

Summary of Weaknesses

Jray successfully found several critical vulnerabilities that should be immediately addressed in order to prevent an adversary from compromising the network. These findings are not specific to a software version but are more general and systemic vulnerabilities.

Although all users and admin accounts had credentials, most of them were easy to crack which meant that they were commonly used passwords that were already on our password database and didn’t take long to break the hashes found.
The website itself was vulnerable to google dorking and google operand on port 80. The database wasn’t fully secured with HTTPS.
Our google search gave us the names and roles of the team, as well as a picture of the individuals.
Using an open source scan tool, Jray was able to locate open ports 22, 80 and 443.
We were also able to get the general location and Operating system/version of the web server for the hostname www.megacorpone.com.
The server was also vulnerable to exploits using metasploit via Shell commands and gained direct access to the infrastructure.
We were able to find account credentials by LLMNR Spoofing using a tool called Responder by listening to requests.
Once we had the credentials, Jray was able to run commands remotely on the victim machine with another metasploit module.
Jray was able to leverage metasploit’s SMBClient to upload a shell script to get a backdoor shell on the system to maintain persistence.
We were able to exploit the registry database by dumping the credentials cached therein with a tool called Kiwi.
The domain controller was vulnerable to password spraying and was able to use the common password to get into this system as Administrator.




Executive Summary


Planning and Reconnaissance:

We started with our enumeration process by using some Google dorking/operand to manipulate google searches of the site and found names and contacts of employees, as well as an Index of assets. We also found some code to further our recon on Port 80. 







Recon/Scanning Phase: 

Next, using Shodan.io we performed a nslookup on the webpage www.megacorpone.com and found 3 open ports: 22, 80 and 443. Further found the following: version of SSH, OS, location and version of web server running. These were as follows: SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2, Debian, in Montreal, Canada and version as Apache 2.4.38. The vulnerabilities associated with the findings during our recon phase via Shodan.io were as follows: CVE-2019-0215, CVE-2019-0220, CVE-2019-0217, CVE-2019-0197, CVE-2019-0196, CVE-2019-0211. 


Our google search gave us the names and roles of the team, as well as a picture of the individual.

 



Scanning/Exploit Phase: 

We used tools to gather information such as network information and potential vulnerabilities. The tools we used for scanning were Nessus, Hping and Nmap. Much like the open source information we found online we used command line tools to dive deeper and found exploits that showed the IP as vulnerable to ftp-vstpd-backdoor. Next, using a common metasploit exploit we were able to remote into IP 172.22.117.150 and gain root access.




Post Exploitation Phase:


Once we were able to gain our initial access into the system, we were able to locate a text file with administrative credentials. From there we were able to ssh into the system using these credentials to achieve persistence. Since the admin credentials were able to run all commands, we were able to easily escalate to the root user. Being the root user allowed us to view the password hashes of the users and we were then able to brute force and crack them. 




We also found that the Windows 10 IP 172.22.117.20 was vulnerable to LLMNR poisoning and we were able to get credentials to a domain account through this exploit.


We were able to leverage the credentials to use another metasploit module to actually run commands on this machine remotely. We were able to get the system info for the Host Windows10 machine with this scanner module.


Another exploit we were able to use was using SMBClient to interact with the windows machine and upload a shell script to get a reverse shell onto the client system. This is how we ultimately escalated to the System Administrator account.





To aid in keeping our backdoor, we leveraged Task Scheduler to automate the shell to run our payload if discovered, then we could recover it at the designated time.




We also used Metasploit kiwi extension to dump cached credentials on the Windows 10 Machine and cracked those passwords as well.


 
We then used these credentials to password spray across the network and found the administrator’s password for the Domain Controller IP 172.22.117.10.




Summary Vulnerability Overview
**NOTE: Many of these vulnerabilities could be considered high or higher due to the passwords gained and may be lower if a stronger password and Multi factor authentication requirements were set.

Vulnerability
Severity
Weak password on public web application
Critical
Google dorking and google operand
Medium
Port/IP scanning
Critical
Open Port 22
High
Backdoor exploits
High
Contact Informational vulnerabilities on webpage
Medium
Network information vulnerability 
Low
Passwords in text files
High
LLMNR poisoning
Medium
Command injection
High
SMB 
High



The following summary tables represent an overview of the assessment findings for this penetration test:

Scan Type
Total
Hosts
172.22.117.150,
172.22.117.10 and 117.22.117.20
Ports
 445 22 80 443 135 88


Exploitation Risk
Total
Critical
2
High
5
Medium
3
Low
1




Vulnerability Findings

Weak Password on Public Web Application

Risk Rating: Critical

Description: 
The site megacorpone.com is used to host the Cisco AnyConnect configuration file for MegaCorpOne. This site is secured with basic authentication but is susceptible to a dictionary attack. Jray was able to use a username gathered from OSINT in combination with a wordlist in order to guess the user’s password and access the configuration file.

Affected Hosts: vpn.megacorpone.com

Remediation: 

Set up two-factor authentication instead of basic authentication to prevent dictionary attacks from being successful.
Require a strong password complexity that requires passwords to be over 12 characters long, upper+lower case, & include a special character.
Reset the user thudson’s password.

Google dorking and google operand

Risk Rating: Medium

Description: From basic google searching and web page manipulation, the site wasn’t using HTTPS in all configurations. Therefore, many of the webpages and paths were in plain text and didn’t encrypt the locations. The source code and site becomes extremely vulnerable using only HTTP. Jray was able to use this to get access to various databases. 


Affected Hosts:megacorpone.com

Remediation: 

Make sure all site variations are set up using HTTPS to encrypt all paths and domain names.
Do not store sensitive files or information in the same web database. Use data segregation wherever possible.

Port/IP scanning

Risk Rating: Critical

Description: The website was vulnerable to basic scanning tools. We were able to use our remote connection to find all the open ports across the network. 


Affected Hosts: 172.22.117.150,
172.22.117.10 and 117.22.117.20



Remediation: 

Set up the firewalls to block all unwanted IPs from scanning the networks.
Only allow ports to be opened for limited time intervals and keep track of this closely.
Regularly scan the system and have a plan if unwanted activity is found in the logs.

Open Port 22

Risk Rating: High

Description: Open port 22 is a common attack vector for cyber criminals and leaving it wide open and detectable is an urgent matter to address. Having your network open to this common protocol will be asking for the open internet to try their hand at getting access and SSH into your network. 


Affected Hosts: 172.22.117.150



Remediation: 

Do not leave port 22 open to all IPs on the internet.
Use a different port to run this ssh protocol on to give this more of a disguise to anyone trying their hand at using this as their means of entry.
Regularly scan the system and have a plan if unwanted activity is found in the logs, making this protocol a priority.

Backdoor exploits

Risk Rating: High

Description: Once into the system through IP 172.22.117.150 we were able to pivot to the IPs for the windows 10 machine and domain controller using various open source exploits. Jray was able to get root access and maintain persistence in the network. 


Affected Hosts: 172.22.117.150,
172.22.117.10 and 117.22.117.20



Remediation: 

Regularly check logs.
One way to keep this from happening is using various Intrusion Detection and Intrusion Prevention Systems as you can to inspect the traffic and irregular activity happening on the network.
Keep good backups and off site storage if possible in case anything is detected and can wipe any backdoors that the IDS and IPS systems don’t detect once this activity is found.

Contact Informational vulnerabilities on webpage

Risk Rating: Medium

Description: Having all the high level employees contact info, twitter handle and picture is very dangerous. Hackers can use this information to develop high level phishing campaigns and gather information from linkedin profiles and can pivot to using all open source intelligence to build a profile on these valued members of the company. For instance, having the lead developers information for a hacker to easily find their target for altering the websites source code.


Affected Hosts: 172.22.117.150



Remediation: 

Keep the contact information to a need to know only.
Have general email inboxes for the general public to use to contact the company and leave job titles and social media accounts off completely if possible.

Network information vulnerability

Risk Rating: Low

Description: Having the operating system and version of software being used for the website can give the attacker a head start in how to begin their campaign against the company.


Affected Hosts: 172.22.117.150



Remediation: 

Regularly perform your own scans to see how much information is out there.
Use a VPN to proxy as much information on your network as possible.

Passwords in text files

Risk Rating: High

Description: Having a text file with credentials is a common vulnerability in most companies. This can be hard to get your company to implement but without using a password manager with encryption, if an attacker gains initial access, they can pivot to other sensitive areas of the network very easily.


Affected Hosts: 172.22.117.150



Remediation: 

Have company meetings to let everyone know to not store their passwords in any text files and regularly remind them of the dangers this can pose.
Educate the staff on how to use a password manager so they only have to remember one password and will have all their passwords encrypted and away from prying eyes.

LLMNR poisoning

Risk Rating: Medium

Description: Having the ability to listen to traffic on the network openly can lead to any sensitive data moving across the network to be collected and used to move elsewhere in the network easily. If the attacker can see passwords and other valuables backed up by DNS then escalating privileges becomes a more urgent matter.


Affected Hosts: 117.22.117.20



Remediation: 

You can disable LLMNR using a GPO under your group policy editor.
You also need to disable NetBIOS Name Service under Advanced TCP/IP Settings.

Command injection

Risk Rating: High

Description: Running commands remotely on a system can come in handy for your administrative team but should be set up with caution. If there are no detection systems in place then this should not be advisable, especially remotely. In the network and running these modules to exploit this can lead to the attack making alterations and locking out accounts and rendering the system bricked. There are several ways this could go bad.


Affected Hosts: 117.22.117.20 and 172.22.117.10



Remediation: 

Only allowing certain IPs to remote into the system at all would be a good start.
Strengthen the current firewalls and leverage Intrusion Detection Systems and if no one is able to monitor them then upgrading to a Intrusion Prevention System may be a better way to also block most of these common exploits from occuring.

SMB

Risk Rating: High

Description: Server Message Block (SMB) using port 445 was used throughout the pen test as means to upload files to the victim machines and can cause some of the most impactful damage to an organization. There are many exploits available for this protocol. This is one of the requirements for Active Directory to work properly but must be updated and patched to prevent malicious use cases.


Affected Hosts: 172.22.117.150,
172.22.117.10 and 117.22.117.20





Remediation: 

Block SMB at the Network level.
Restrict and Protect SMB at the Host level. 
Use encryption for SMB and secure authentifcation.












MITRE ATT&CK Navigator Map



The following completed MITRE ATT&CK navigator map shows all of the techniques and tactics that Jray used throughout the assessment.

Legend


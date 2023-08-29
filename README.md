## Table of contents
- [Ethical-hacking](#Ethical-hacking)
- [Introduction](#introduction)
	- [What you need to know.](#what-you-need-to-know)
	- [Where to practice ?](#where-to-practice-)
		- [Youtubers](#youtubers)
		- [Platforms](#platforms)
- [Before Hacking](#before-hacking)
- [Steps of Pen-Testing](#steps-of-pen-testing)
- [Enumeration](#enumeration)
	- [NMAP](#nmap)
	- [Fuzzing](#fuzzing)
	- [Sub Domains](#sub-domains)
	- [DNS](#dns)
	- [Logs](#logs)
- [Privilege Escalation](#privilege-escalation)
- [Tools](#tools)
- [Testing](#Testing)
- [Tools and resouces](#Tools-and-resouces)


# Ethical-hacking

Certainly, I can provide a detailed explanation of each step in the ethical hacking process. Please keep in mind that this information is for educational purposes and should only be used in a legal and ethical manner.

**1. Planning and Reconnaissance:**

- **Define the Scope:** Clearly define the scope of the engagement. Identify the systems, networks, or applications that you are authorized to test. Make sure you have written permission.

- **Gather Information:** Use various resources, including WHOIS databases, DNS records, and public information, to gather information about the target's domain, IP ranges, and more.

- **Footprinting:** This involves collecting data on the target's infrastructure, such as subdomains, IP addresses, network architecture, and technology in use.

**2. Scanning:**

- **Port Scanning:** Use tools like Nmap to perform port scanning, identifying open ports and services on the target systems. Understand potential attack vectors.

- **Vulnerability Scanning:** Utilize tools like Nessus, OpenVAS, or Qualys to scan for known vulnerabilities in the target's systems, applications, and services.

**3. Gaining Access:**

- **Exploitation:** Based on the vulnerabilities discovered, use tools like Metasploit to exploit them. Metasploit provides pre-built exploits, payloads, and post-exploitation modules.

- **Password Cracking:** Attempt to crack passwords using tools like John the Ripper, Hashcat, or Hydra. This can be used to gain unauthorized access.

**4. Maintaining Access:**

- **Backdoors and Trojans:** Create persistent access points using backdoors or Trojans. This might involve installing a hidden remote access tool that allows continued control.

**5. Analysis:**

- **Review Results:** Analyze the results of your testing, including vulnerabilities identified, their severity, and potential impact on the target systems.

- **Risk Assessment:** Evaluate the risks associated with the vulnerabilities. Consider the likelihood of exploitation and the potential business impact.

**6. Documentation:**

- **Report Writing:** Prepare a comprehensive report detailing your findings, including vulnerabilities, their impact, and recommended remediation steps.

- **Evidence Preservation:** Document all steps taken during testing, including commands used, tools employed, and screenshots. This documentation can serve as evidence of your ethical hacking activities.

**7. Remediation:**

- **Notify the Client:** Communicate your findings and recommendations to the client. Provide clear explanations of the vulnerabilities and their potential impact.

- **Patching and Mitigation:** Assist the client in addressing vulnerabilities by applying patches, changing configurations, and implementing security measures to mitigate the risks.

**8. Validation and Verification:**

- **Re-Test:** After the client has taken action to address the vulnerabilities, perform a re-test to confirm that the issues have been resolved and the systems are more secure.

- **Verification:** Ensure that the security measures put in place are effective and that the systems are now adequately protected against potential threats.

**9. Education and Improvement:**

- **Training:** Provide security training to the client's team to enhance their understanding of security practices, vulnerability management, and incident response.

- **Continuous Improvement:** Encourage the client to establish an ongoing security monitoring program, regularly update software, and conduct periodic vulnerability assessments to maintain a secure environment.
#

# Introduction

The goal of this repository is to help out beginners-medium hackers. Practicing is the only way to improve in this domain, and there are plenty of websites where you can learn, and hack at the same time. But before that, let's talk a bit about what you will find in the repository.

## What you need to know
To become a great pentester you have to be patient. Learning and practicing are definetly your way into this domain. But it will take some time.
Here's a simple list of things you should and shouldn't do in order to imporve :

-	You have to master at least one programming language. And if you still haven't learn a single programming language, I would advise you to start with C.
-	Don't just use tools without knowing how they work. Here's a [list of tools](#tools) you will need.
-	You're not ready for real targets, just focus on [practicing and learning](#where-to-practice) and you will get there. Hopefully in a lawful way.
-	Learning doesn't only rely on videos on youtube, reading could be a great way as well. From books to manuals and articles.
-	Don't be a script kiddie, not having any idea on what you're doing means you're a script kiddie.
-	Assembly language is far important than you think, specially if you're into Reverse engineeering or PWN. It would be easier to learn it if you master C language before.
-	You have to know how computers and operating system works. Do you know what a kernel is ? If not you should do some googling.
-	Twitter, as dumb as this idea looks, but I'd really recommend you to have a twitter account, and follow communities related to cyber security. Staying up to date with the world is not such a bad idea after all.
-	Last but not least, don't learn hacking for wrong reasons. Don't waste your time if your goal is to hack your girlfriends Facebook account. Set a goal, no matter how big it looks like, and chase it. [Dreams without goals are the ultimate fuel of disappointment](https://www.youtube.com/watch?v=TssZmJaoZs4&t=180s).

## Where to practice ?
Here you will find multiple resources to learn and practice hacking.

### Youtubers
Here's a list of one the best youtubers I personally follow.
| Name      	| Description																 			     | Link  |
| :-----------: |:------------------------------------------------------------------------------------------:| :----:|
| Liveoverflow  | One of the best channels on youtube to learn reverse engineering and PWN.                  | [link](https://www.youtube.com/c/LiveOverflow) |
| IPPSEC        | Does retired machines from HackTheBox, great way to learn what to do before every machine. |   [Link](https://www.youtube.com/c/ippsec) |
| John Hammond  | Does different kind of CTFs, you can learn how to use lot of tools, and techniques.        |    [Link](https://www.youtube.com/c/JohnHammond010) |
| David Bombal  | Great channel to imporve professionally in hacking if you are looking for jobs.			 | [Link](https://www.youtube.com/c/DavidBombal) |
| NetworkChuck  | If you are looking where to learn very basic stuff with a fun way, this guy is yours.		 | [Link](https://www.youtube.com/c/NetworkChuck) |
| CryptoCat		| Although this channel is newly, it has some really great content you definetly should check | [link](https://www.youtube.com/c/CryptoCat23) |
| HackerSploit  | This one explains tools, and does HackTheBox retired machines. And also does real life scenarios hacking | [Link](https://www.youtube.com/c/HackerSploit) |

### Platforms
Here's where you can learn and practice at the same time.
| Name		    | Description																				 | Link  |
| :-----------: |:------------------------------------------------------------------------------------------:| :----:|
| HackTheBox	| Perhaps the greatest platform with the hardest possible challenge. specialise in Boxes	 | [HackTheBox](https://www.hackthebox.com) |
| TryHackMe		| This one is similar to HackTheBox, difference is that is has easier challenges than HTB	 | [TryHackMe](https://tryhackme.com) |
| PwnTillDawn	| Although the name would give you PWN vibes, it has a big number of boxes ready to be PWNed | [PwnTillDawn](https://online.pwntilldawn.com/) |
| CyberTalents 	| A good platform for beginners to start their journey into hacking. It has only CTFs though | [CyberTalents](https://cybertalents.com) |
| Pwnable		| Fun platform to learn PWN from the very basics. You will need to learn C language before	 | [Pwnable](https://pwnable.kr/) |
| HackThisSite	| Free platform for hackers to test and expand their knowledge with CTFs, challenges and many more | [HackThisSite](https://www.hackthissite.org/) |
| Hacker101		| Free class for web security. Whether you're a programmer with an interest in bug bounties or a seasoned security professional | [Hacker101](https://www.hacker101.com/) |
| PicoCTF		| Free computer security education program, with original created challenges to practice your skills in different domains. | [PicoCTF](https://picoctf.org/) |
| PortSwigger		| PortSwigger is a widely-used platform for web application security testing and ethical hacking. | [PortSwigger](https://portswigger.net/web-security/all-labs) |

Go ahead a knock yourself out.

# Before Hacking
There are certain things you need to learn before even diving into hacking. Here's a list you should definetly check out.

## Languages
Many might think that programming is not really necessary in hacking, [they're not just wrong they're stupid](https://www.youtube.com/watch?v=40Pvi1XVm_s).
But you need to know that not all programming languages serve the same purpose. There are different types, you should learn at least one language in each category. Let's go ahead and check them out.

#### Languages you must know
These are the languages that will on a daily basis in your hacking journey.

- **C / Assembly**	: Low level language, for binary exploitation.
- **Bash**		: Linux scripting language.
- **Powershell**	: Windows scripting language.
- **Python**		: Easy to learn language, that can help you automate lot of work you do frequently.
- **PHP**		: You cannot do bug bounty without knowing PHP.
- **Javascript**	: Learning Javascript is as important as learning PHP, specially if you are into Bug Bounty.

#### Languages that definetly can help you out
- **C++**
- **Ruby**
- **Lua**
- **Java**
- **Perl**

# Steps of Pen-Testing
In this section, We'll give you a certain steps you should always follow when you're pentesting.

<p align="center">
	<img src="https://www.tutorialspoint.com/penetration_testing/images/penetration_testing_method.jpg" alt="Pentesting" /><br>
</p>

[Learn more](https://www.tutorialspoint.com/penetration_testing/index.htm)

# Enumeration
Now since we're finished with the introduction, let's go ahead and hack a box for the sake of an example.
The Box I chose, is [Boot2Root](https://github.com/mza7a/Boot2Root), a project in 42 Cursus.

## NMAP.
The first step you should think of, is trying to identify what exactly you're attacking(hopefully in a lawful way). You need to gather maximum of informations from this target. A great way to do so, is to use a tool called [NMAP](https://linux.die.net/man/1/nmap). It's used to to scan ip addresses, it can also be used to identify ip addresses connected to your network.
Since we do not know the ip address of our box, we have to scan our network in order to identify its ip address.

Depending on what's your network class, you can use the following command in order to scan a certain subnet.

```bash
$> nmap 10.12.100.x/24
```
You will get an output similar to this :
<p align="center">
	<img src="https://i.imgur.com/OGMJrEf.png" alt="nmap result"/><br>
</p>
And as you can see we have the ip address of the machine.
But you'll ask what else we can do with nmap. Great question, can't answer it all. You have to discover more yourself. But let me show you some couple of commands you can use in order to do stuff.

### Nmap Different Commands
In order to use the following commands, you have to specify `-A` tag on your scan. It for aggressive scanning.
```bash
$> nmap -A 10.12.11.100
```

Using nmap, you can detect what Operatin System the target uses. Note that this is not always accurate, and also you will need root privelege. Here's an example :
```bash
$> sudo nmap -o 10.12.11.100
```

You can also detect what services are running on that target, the version of those services as well. Note that `-sV` is for the version scanning.
```bash
$> nmap -sV 10.12.11.100
```

How about running a scan on all the ports from in a total of 65,535 ports.
```bash
$> nmap -p- 10.12.11.100
```

You want only one port ?
```bash
$> nmap -p 80 10.22.11.100
```

How about multiple ports ?
```bash
$> nmap -p 80,443 10.22.11.100
```

A range of ports ?
```bash
$> nmap -p 80-8080 10.22.11.100
```

There is also timing templates, if you want your scan to take more or less time.
```bash
$> nmap -T[ID] 10.22.11.100
```

Sometimes you will counter targets that blocks your pings. Use the `-Pn` tag to skip the host discovery. This treats your target as an online target.
```bash
$> nmap -Pn 10.22.11.100
```

If you want to save the results of your scan you can do it like this :
```bash
$> nmap 10.22.11.100 -oA output.name
```

Let's go ahead and gather all the tags, under one powerful command, you have to know that a command like this would take ~20-30 minutes :
```bash
$> sudo nmap -A -O -Pn -p- -T4 -sV 10.22.11.100
```

There are a lot more commands than this, you should visit the [nmap man page](https://linux.die.net/man/1/nmap) or their [Docs](https://nmap.org/docs.html) to learn even more about this tool.


There are lot of other [tools](#tools) that you can use in order to dir bust, and each tools gives you different options.

## Sub Domains
Let's say you scanned a target and you found a web application, this web application can contains a multiple subdomains that you should check.

<p align="center">
	<img src="https://blog.hubspot.com/hs-fs/hubfs/Google%20Drive%20Integration/Whats%20a%20Subdomain%20%26%20How%20Is%20It%20Used%3F-3.jpeg?width=1300&name=Whats%20a%20Subdomain%20%26%20How%20Is%20It%20Used%3F-3.jpeg" alt="subdomains" /><br>
</p>

You might ask what a [subdomain](https://blog.hubspot.com/website/what-is-a-subdomain) is. It's simply a good way to seperate the content of you website. It's piece of additional information added to the beginning of a website’s domain name. It allows websites to separate and organize content for a specific function — such as a blog or an online store — from the rest of your website.

Like sub-directories, you can also search for sub-domains , using a [wordlist](#wordlists) and a tool. In this case we'll be using as an example [gobuster](https://github.com/OJ/gobuster)

Using the following command :
```bash
$> gobuster dns -d google.com  -w /path/to/wordlist.txt
-d : To specify the domain name
-w : To specify a wordlist
```

Thus you will get something like this(don't take this example seriously, it's not true... or maybe ?).
```
www.google.com
blog.google.com
store.google.com
etc...
```

This can help you find more information about a certain website that you didn't know. Maybe even find login pannels or so.

## URL response
After generating a list of subdomain and hosts, it's time to check those who work. Doing it manualy will take a long time if a long list was generated, so here's a tools [httpx](https://github.com/projectdiscovery/httpx) that make that task easy for us.
Using the following command : 
```bash
$> cat hosts.txt | httpx
```

[httpx](https://github.com/projectdiscovery/httpx) have more other intersting functionality, check the repo for more info.


## Fuzzing
You find a web app and its subdomains too, so what can you do with it.
For instance you can try and find directories or files. There are lot of [tools](#tools) you can use to do that. But for now let's use [dirb](https://www.kali.org/tools/dirb/).

You'll need wordlist, in order to test on multiple directories or files. Check [wordlists](#wordlists) for more infos.
This is an example on how to use `dirb` command.
```bash
$> dirb http://ip_add/ /path/to/wordlist
```

## DNS
A good thing to do is to pay attention to the request you make on a website. Some websites can show you different outputs depending on what domain name you requested. Specially when you're playing challenges on websites like [HackTheBox](hackthebox.com) or [TryHackMe](tryhackme.com), always change your host file to whatever you find while scanning or while enumerating in general.

```bash
$> nano /etc/hosts
10.1.1.1	1337.htb #example
```

## Logs
Logs are really important when it comes to tracing one's moves. You can even find credentials on them. We will talk more about it in the [Privilege Escalation part](#privilege-escalation)

# Privilege Escalation
Using [HackTricks](https://book.hacktricks.xyz/linux-unix/privilege-escalation), we can use multiple commands to monitor a system and thus finding an exploit we can use to privesc the system.

## System Information

### OS Infos
```
uname -a
cat /etc/os-release
cat /proc/version
```

### Kernel Version
```
uname -r
```

### Sudo Version
```
sudo -v (might not work sometimes if you don't have the password of the user)
```

## Processors
```
ps aux
ps -ef
top -n 1
```

## Cronjobs
```
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

# Tools
Since we were inspired by this [readme](https://github.com/mza7a/hacker-roadmap) to do one where we can always contribute to it, and it won't be just the usual stuff you read online. Here you will find a list of tools by category. You can also visit [the official website of Kali Linux](https://www.kali.org/tools/) for more information.

#### :male_detective: Information Gathering

Information Gathering tools allows you to collect host metadata about services and users. Check informations about a domain, IP address, phone number or an email address.

| Tool        | Language           | Support  | Description    |
| ----------- |-------------------------|----------|----------------|
| [theHarvester](https://github.com/laramies/theHarvester)      | **Python** | `Linux/Windows/macOS` | E-mails, subdomains and names Harvester. |
| [CTFR](https://github.com/UnaPibaGeek/ctfr)      | **Python** | `Linux/Windows/macOS` | Abusing Certificate Transparency logs for getting HTTPS websites subdomains. |
| [Sn1per](https://github.com/1N3/Sn1per)      | **bash** | `Linux/macOS` | Automated Pentest Recon Scanner. |
| [RED Hawk](https://github.com/Tuhinshubhra/RED_HAWK)      | **PHP** | `Linux/Windows/macOS` | All in one tool for Information Gathering, Vulnerability Scanning and Crawling. A must have tool for all penetration testers. |
| [Infoga](https://github.com/m4ll0k/Infoga)      | **Python** | `Linux/Windows/macOS` | Email Information Gathering. |
| [KnockMail](https://github.com/4w4k3/KnockMail)      | **Python** | `Linux/Windows/macOS` | Check if email address exists. |
| [a2sv](https://github.com/hahwul/a2sv)      | **Python** | `Linux/Windows/macOS` | Auto Scanning to SSL Vulnerability. |
| [Wfuzz](https://github.com/xmendez/wfuzz)      | **Python** | `Linux/Windows/macOS` | Web application fuzzer. |
| [Nmap](https://github.com/nmap/nmap)      | **C/C++** | `Linux/Windows/macOS` | A very common tool. Network host, vuln and port detector. |
| [PhoneInfoga](https://github.com/sundowndev/PhoneInfoga)      | **Go** | `Linux/macOS` | An OSINT framework for phone numbers. |

#### :lock: Password Attacks

Crack passwords and create wordlists.

| Tool        | Language           | Support  | Description    |
| ----------- |-------------------------|----------|----------------|
| [John the Ripper](https://github.com/magnumripper/JohnTheRipper)      | **C** | `Linux/Windows/macOS` | John the Ripper is a fast password cracker. |
| [hashcat](https://github.com/hashcat/hashcat)      | **C** | `Linux/Windows/macOS` | World's fastest and most advanced password recovery utility. |
| [Hydra](https://github.com/vanhauser-thc/thc-hydra)      | **C** | `Linux/Windows/macOS` | Parallelized login cracker which supports numerous protocols to attack. |
| [ophcrack](https://gitlab.com/objectifsecurite/ophcrack)      | **C++** | `Linux/Windows/macOS` | Windows password cracker based on rainbow tables. |
| [Ncrack](https://github.com/nmap/ncrack)      | **C** | `Linux/Windows/macOS` | High-speed network authentication cracking tool. |
| [WGen](https://github.com/agusmakmun/Python-Wordlist-Generator)      | **Python** | `Linux/Windows/macOS` | Create awesome wordlists with Python. |
| [SSH Auditor](https://github.com/ncsa/ssh-auditor)      | **Go** | `Linux/macOS` | The best way to scan for weak ssh passwords on your network. |

###### :memo: Wordlists

| Tool        | Description    |
| ----------- |----------------|
| [Probable Wordlist](https://github.com/berzerk0/Probable-Wordlists)      | Wordlists sorted by probability originally created for password generation and testing. |

#### :globe_with_meridians: Wireless Testing

Used for intrusion detection and wifi attacks.

| Tool        | Language           | Support  | Description    |
| ----------- |-------------------------|----------|----------------|
| [Aircrack](https://github.com/aircrack-ng/aircrack-ng)      | **C** | `Linux/Windows/macOS` | WiFi security auditing tools suite. |
| [bettercap](https://github.com/bettercap/bettercap)      | **Go** | `Linux/Windows/macOS/Android` | bettercap is the Swiss army knife for network attacks and monitoring. |
| [WiFi Pumpkin](https://github.com/P0cL4bs/WiFi-Pumpkin)      | **Python** | `Linux/Windows/macOS/Android` | Framework for Rogue Wi-Fi Access Point Attack. |
| [Airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon)      | **Shell** | `Linux/Windows/macOS` | This is a multi-use bash script for Linux systems to audit wireless networks. |
| [Airbash](https://github.com/tehw0lf/airbash)      | **C** | `Linux/Windows/macOS` | A POSIX-compliant, fully automated WPA PSK handshake capture script aimed at penetration testing. |

#### :wrench: Exploitation Tools

Acesss systems and data with service-oriented exploits.

| Tool                                                    | Language   | Support               | Description                                                  |
| ------------------------------------------------------- | ---------- | --------------------- | ------------------------------------------------------------ |
| [SQLmap](https://github.com/sqlmapproject/sqlmap)       | **Python** | `Linux/Windows/macOS` | Automatic SQL injection and database takeover tool.          |
| [XSStrike](https://github.com/UltimateHackers/XSStrike) | **Python** | `Linux/Windows/macOS` | Advanced XSS detection and exploitation suite.               |
| [Commix](https://github.com/commixproject/commix)       | **Python** | `Linux/Windows/macOS` | Automated All-in-One OS command injection and exploitation tool.￼ |
| [Nuclei](https://github.com/projectdiscovery/nuclei)    | **Go**     | `Linux/Windows/macOS` | Fast and customisable vulnerability scanner based on simple YAML based DSL. |

#### :busts_in_silhouette: Sniffing & Spoofing

Listen to network traffic or fake a network entity.

| Tool        | Language           | Support  | Description    |
| ----------- |-------------------------|----------|----------------|
| [Wireshark](https://www.wireshark.org)      | **C/C++** | `Linux/Windows/macOS` | Wireshark is a network protocol analyzer. |
| [WiFi Pumpkin](https://github.com/P0cL4bs/WiFi-Pumpkin)      | **Python** | `Linux/Windows/macOS/Android` | Framework for Rogue Wi-Fi Access Point Attack. |
| [Zarp](https://github.com/hatRiot/zarp)      | **Python** | `Linux/Windows/macOS` | A free network attack framework. |

#### :rocket: Web Hacking

Exploit popular CMSs that are hosted online.

| Tool        | Language           | Support  | Description    |
| ----------- |-------------------------|----------|----------------|
| [WPScan](https://github.com/wpscanteam/wpscan)      | **Ruby** | `Linux/Windows/macOS` | WPScan is a black box WordPress vulnerability scanner. |
| [Droopescan](https://github.com/droope/droopescan)      | **Python** | `Linux/Windows/macOS` | A plugin-based scanner to identify issues with several CMSs, mainly Drupal & Silverstripe. |
| [Joomscan](https://github.com/rezasp/joomscan)      | **Perl** | `Linux/Windows/macOS` | Joomla Vulnerability Scanner. |
| [Drupwn](https://github.com/immunIT/drupwn)      | **Python** | `Linux/Windows/macOS` | Drupal Security Scanner to perform enumerations on Drupal-based web applications. |
| [CMSeek](https://github.com/Tuhinshubhra/CMSeek)      | **Python** | `Linux/Windows/macOS` | CMS Detection and Exploitation suite - Scan WordPress, Joomla, Drupal and 130 other CMSs. |

#### :tada: Post Exploitation

Exploits for after you have already gained access.

| Tool        | Language           | Support  | Description    |
| ----------- |-------------------------|----------|----------------|
| [TheFatRat](https://github.com/Screetsec/TheFatRat)      | **C** | `Linux/Windows/macOS` | Easy tool to generate backdoor and easy tool to post exploitation attack like browser attack, dll. |

#### :package: Frameworks

Frameworks are packs of pen testing tools with custom shell navigation and documentation.

| Tool        | Language           | Support  | Description    |
| ----------- |-------------------------|----------|----------------|
| [Operative Framework](https://github.com/graniet/operative-framework)      | **Python** | `Linux/Windows/macOS` | Framework based on fingerprint action, this tool is used to get information on a website or a enterprise target with multiple modules. |
| [Metasploit](https://github.com/rapid7/metasploit-framework)      | **Ruby** | `Linux/Windows/macOS` | A penetration testing framework for ethical hackers. |
| [cSploit](https://github.com/cSploit/android)      | **Java** | `Android` | The most complete and advanced IT security professional toolkit on Android. |
| [radare2](https://github.com/radare/radare2)      | **C** | `Linux/Windows/macOS/Android` | Unix-like reverse engineering framework and commandline tools. |
| [Wifiphisher](https://github.com/wifiphisher/wifiphisher)      | **Python** | `Linux` | The Rogue Access Point Framework. |
| [Beef](https://github.com/beefproject/beef)      | **Javascript** | `Linux/Windows/macOS` | The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser. |
| [Mobile Security Framework (MobSF)](https://github.com/MobSF/Mobile-Security-Framework-MobSF)      | **Python** | `Linux/Windows/macOS` | Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis. |
| [Burp Suite](https://portswigger.net/burp)      | **Java** | `Linux/Windows/macOS` | Burp Suite is a leading range of cybersecurity tools, brought to you by PortSwigger. **This tool is not free and open source** |

# Additional resources

- [Devbreak on Twitter](https://twitter.com/DevbreakFR)
- [The Life of a Security Researcher](https://www.alienvault.com/blogs/security-essentials/the-life-of-a-security-researcher)
- [Find an awesome hacking spots in your country](https://github.com/diasdavid/awesome-hacking-spots)
- [Awesome-Hacking Lists](https://github.com/Hack-with-Github/Awesome-Hacking/blob/master/README.md)
- [Crack Station](http://crackstation.net/)
- [Exploit Database](http://www.exploit-db.com/)
- [Hackavision](http://www.hackavision.com/)
- [Hackmethod](https://www.hackmethod.com/)
- [Packet Storm Security](http://packetstormsecurity.org/)
- [SecLists](http://seclists.org/)
- [SecTools](http://sectools.org/)
- [Smash the Stack](http://smashthestack.org/)
- [Don't use VPN services](https://gist.github.com/joepie91/5a9909939e6ce7d09e29)
- [How to Avoid Becoming a Script Kiddie](https://www.wikihow.com/Avoid-Becoming-a-Script-Kiddie)
- [2017 Top 10 Application Security Risks](https://www.owasp.org/index.php/Top_10-2017_Top_10)
- [Starting in cybersecurity ?](https://blog.0day.rocks/starting-in-cybersecurity-5b02d827fb54)

I would highly advise you guys to go and checkout [sundowndev](https://github.com/sundowndev/hacker-roadmap)

#

# Testing
Ensure you have permission before conducting any testing!

1. Reconnaissance

   a. Passive
      - Google Dorking: `site:example.com, inurl, intext, etc.`

      - WHOIS Lookup: `whois example.com`
     
      - DNS Recon: `dnsrecon -d example.com`

   b. Active
   
      - Nmap: `nmap -sn <IP_range>` (ping sweep)
      
      - Nmap: `nmap -p- <target_IP>` (port scanning)

2. Enumeration

   a. DNS Enumeration
 
      - Dig: `dig @<DNS_server> example.com AXFR`
      - Nmap: `nmap --script dns-brute <target_IP>`
      
   b. SMB Enumeration
   
      - Nmap: `nmap --script smb-enum-shares <target_IP>`
      - Smbclient: `smbclient \\\\<target_IP>\\<share_name> -U <username>`
      
   c. SNMP Enumeration
   
      - Snmpwalk: `snmpwalk -c public -v1 <target_IP>`
      - Onesixtyone: `onesixtyone <target_IP>`
      
   d. Web Application Enumeration
   
      - Nikto: `nikto -h <target_URL>`
      - Dirb: `dirb <target_URL>`

3. Vulnerability Assessment

   a. Nmap NSE Scripts
   
      - Nmap: `nmap --script vuln <target_IP>`
      
   b. OpenVAS
   
      - Setup and run OpenVAS on target systems
      
   c. Metasploit Framework
   
      - Search for modules: `search <vulnerability>`
      
      - Use a module: `use <module_name>`

4. Exploitation

   a. Metasploit Framework
   
      - Set options: `set <option> <value>`
      - Run exploit: `exploit or run`
      
   b. Manual Exploitation
   
      - Research and use known exploits for identified vulnerabilities
      
   c. Web Application Exploitation
   
      - SQL Injection: `sqlmap -u <target_URL>`
      
      - XSS: Test payloads, use automated tools like `XSStrike`

5. Post-Exploitation

   a. Privilege Escalation
   
      - Linux: `linPEAS, LinEnum`
      - Windows: `winPEAS, PowerUp, Sherlock`
      
   b. Lateral Movement
   
      - PsExec: `psexec.py <username>:<password>@<target_IP>`
      - Mimikatz: `sekurlsa::logonpasswords`
      
   c. Data Exfiltration
   
      - Identify and collect sensitive information

6. Clean Up

   Remove artifacts, backdoors, and logs

7. Reporting

   Document findings, recommendations, and mitigations

# ----- End of Checklist -----

# Tools and resouces
**Tools and Resources:**

Certainly, here's a more detailed list 

# **Footprinting and Information Gathering:**
1. **WHOIS Lookup:** Obtain domain registration information and contact details.
2. **Shodan:** Search engine for internet-connected devices and services.
3. **theHarvester:** Gather email addresses, subdomains, and information from public sources.
4. **Recon-ng:** A reconnaissance framework that collects data from various sources.
5. **Maltego:** Visualize relationships between gathered information using graphs.
6. **SpiderFoot:** OSINT automation tool to collect data from different sources.
7. **FOCA:** Extract metadata and information from documents for analysis.
8. **Sublist3r:** Subdomain enumeration tool using various search engines.
9. **Censys:** Discover hosts and networks on the internet and gather information.
10. **Amass:** In-depth subdomain enumeration and information gathering.

# **Port Scanning:**
1. **Nmap:** Versatile network discovery and port scanning tool.
2. **Masscan:** High-speed port scanner designed for large-scale scans.
3. **Zmap:** Fast network scanner for exploring the entire IPv4 address space.
4. **Unicornscan:** Lightweight network scanner with asynchronous scanning capabilities.
5. **RustScan:** Fast and efficient port scanner written in Rust.
6. **Nessus:** Commercial vulnerability scanner that includes port scanning capabilities.
7. **Angry IP Scanner:** Cross-platform IP address and port scanner.
8. **Amap:** Application layer scanner for identifying open ports and services.
9. **Hping3:** Network tool for crafting packets and sending them over the network.
10. **SuperScan:** Windows-based port scanner with additional features.

# **Vulnerability Scanning:**
1. **Nessus:** Widely used vulnerability scanner for identifying known vulnerabilities.
2. **OpenVAS:** Open-source vulnerability scanner and manager.
3. **Qualys:** Cloud-based security platform offering vulnerability management.
4. **Nexpose:** Vulnerability management tool by Rapid7, now part of InsightVM.
5. **Retina:** Network vulnerability assessment tool by BeyondTrust.


# **Exploitation:**
1. **Metasploit Framework:** Popular exploitation framework for penetration testers.
2. **Canvas:** Commercial exploitation framework for advanced security professionals.
3. **Core Impact:** Commercial penetration testing framework with exploitation capabilities.
4. **BeEF:** Browser exploitation framework for targeting web browsers.
5. **SET (Social-Engineer Toolkit):** Toolkit for social engineering attacks and exploitation.
6. **Armitage:** Metasploit GUI that simplifies exploitation and post-exploitation.
7. **Empire:** Post-exploitation framework with agent-based control.
8. **RouterSploit:** Framework for exploiting embedded devices.
9. **CrackMapExec:** Post-exploitation tool for network pivoting and lateral movement.
10. **RouterSploit:** Framework for exploiting embedded devices.

# **Password Cracking:**
1. **John the Ripper:** Password cracking tool for various encryption algorithms.
2. **Hashcat:** Powerful password cracking tool with GPU acceleration.
3. **Hydra:** Fast and flexible online password cracking tool.
4. **Medusa:** Speedy parallelized network login brute-forcer.
5. **Cain and Abel:** Windows-based password recovery tool.
6. **RainbowCrack:** Crack password hashes using precomputed tables.
7. **Patator:** Multi-purpose brute-forcing tool.
8. **Hashcat:** Powerful password cracking tool with GPU acceleration.
9. **Hydra:** Fast and flexible online password cracking tool.
10. **Medusa:** Speedy parallelized network login brute-forcer.

# **Backdoors and Trojans:**
1. **Netcat (nc):** Networking utility for creating reverse shells and backdoors.
2. **Meterpreter:** Part of the Metasploit Framework, provides advanced post-exploitation capabilities.
3. **Empire:** Powerful post-exploitation framework for Windows environments.
4. **Cobalt Strike:** Adversary simulation and red teaming platform.
5. **Veil:** Framework for generating undetectable payloads and backdoors.
6. **Pupy:** Cross-platform remote administration and post-exploitation tool.
7. **RATs:** Remote Administration Tools like DarkComet, NanoCore, and others.
8. **Beacon:** Part of Cobalt Strike, offers advanced post-exploitation functionality.
9. **Empire:** Powerful post-exploitation framework for Windows environments.
10. **Cobalt Strike:** Adversary simulation and red teaming platform.

# **Documentation:**
1. **LaTeX:** Document preparation system for high-quality documents.
2. **Microsoft Word:** Standard word processor for creating comprehensive reports.
3. **Markdown:** Lightweight markup language for creating formatted text.
4. **JIRA:** Project management and collaboration tool for documenting tasks and progress.
5. **Confluence:** Collaboration tool for creating, sharing, and collaborating on documentation.
6. **MISP:** Threat intelligence platform for documenting and sharing threat data.
7. **Dradis:** Reporting and collaboration platform that integrates with other security tools.
8. **Evernote:** Note-taking and organization tool for documentation.
9. **Git/GitHub:** Version control system and platform for collaborating on documentation.
10. **Wireshark:** Network protocol analyzer that helps with documentation and analysis.

These tools cover various aspects of ethical hacking and penetration testing, but remember that ethical hacking requires responsible and legal use. Always ensure you have proper authorization before using any tools on a target environment.

Remember that each step requires careful consideration of legal and ethical boundaries, and proper authorization is essential before proceeding. The detailed process outlined here is a guideline and can be adapted based on the specific engagement's requirements and the tools available. Always prioritize responsible and ethical behavior when conducting any form of ethical hacking.

# Enumeration
Enumeration Techniques

# Explore Google hacking and enumeration 

# AIM:

To use Google for gathering information and perform enumeration of targets

## STEPS:

### Step 1:

Install kali linux either in partition or virtual box or in live mode

### Step 2:

Investigate on the various Google hacking keywords and enumeration tools as follows:


### Step 3:
Open terminal and try execute some kali linux commands

## Pen Test Tools Categories:  

Following Categories of pen test tools are identified:
Information Gathering.

Google Hacking:

Google hacking, also known as Google dorking, is a technique that involves using advanced operators to perform targeted searches on Google. These operators can be used to search for specific types of information, such as sensitive data that may have been inadvertently exposed on the web. Here are some advanced operators that can be used for Google hacking:

site: This operator allows you to search for pages that are within a specific website or domain. For example, "site:example.com" would search for pages that are on the example.com domain.
Following searches for all the sites that is in the domain yahoo.com
![1st site](https://github.com/user-attachments/assets/01d3b5d9-689b-437d-bcce-3cf0c616e71f)


filetype: This operator allows you to search for files of a specific type. For example, "filetype:pdf" would search for all PDF files.
Following searches for pdf file in the domain yahoo.com

![2nd filetype](https://github.com/user-attachments/assets/e2b75bf8-a2c4-4879-aa81-98b331c50983)


intext: This operator allows you to search for pages that contain specific text within the body of the page. For example, "intext:password" would search for pages that contain the word "password" within the body of the page.
![3rd intext](https://github.com/user-attachments/assets/b391f297-886e-4fe2-8d81-b824771b9681)


inurl: This operator allows you to search for pages that contain specific text within the URL. For example, "inurl:admin" would search for pages that contain the word "admin" within the URL.
![4rd inurl](https://github.com/user-attachments/assets/db1f9896-acf0-4099-b83c-ecd0a1d6c77c)

intitle: This operator allows you to search for pages that contain specific text within the title tag. For example, "intitle:index of" would search for pages that contain "index of" within the title tag.
![5th intitile](https://github.com/user-attachments/assets/0ed95dd4-c8ee-4192-b02f-ad2cf9c0c807)

link: This operator allows you to search for pages that link to a specific URL. For example, "link:example.com" would search for pages that link to the example.com domain.
![6th link](https://github.com/user-attachments/assets/19a69ec6-771e-479c-8545-0579ea5b2472)

cache: This operator allows you to view the cached version of a page. For example, "cache:example.com" would show the cached version of the example.com website.
![7th(1) cache](https://github.com/user-attachments/assets/c1bffac7-43c6-484e-a8cf-a812291aaa37)
We can use foo to create a cache of a website:
![7th(2) foo](https://github.com/user-attachments/assets/cbbac3d6-d0d4-4b8c-b53f-733ecc7f8855)

#DNS Enumeration


##DNS Recon
provides the ability to perform:
Check all NS records for zone transfers
Enumerate general DNS records for a given domain (MX, SOA, NS, A, AAAA, SPF , TXT)
Perform common SRV Record Enumeration
Top level domain expansion
## OUTPUT:
![8 dnsrecon](https://github.com/user-attachments/assets/4a6d5e33-adc1-4e0b-87d6-b46d8e4ffa33)

![9 dnsrecon cdac](https://github.com/user-attachments/assets/81ab0758-b5e4-49ec-981f-35bc649a9d67)


##dnsenum
Dnsenum is a multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks. The main purpose of Dnsenum is to gather as much information as possible about a domain. The program currently performs the following operations:

Get the host’s addresses (A record).
Get the namservers (threaded).
Get the MX record (threaded).
Perform axfr queries on nameservers and get BIND versions(threaded).
Get extra names and subdomains via google scraping (google query = “allinurl: -www site:domain”).
Brute force subdomains from file, can also perform recursion on subdomain that have NS records (all threaded).
Calculate C class domain network ranges and perform whois queries on them (threaded).
Perform reverse lookups on netranges (C class or/and whois netranges) (threaded).
Write to domain_ips.txt file ip-blocks.
This program is useful for pentesters, ethical hackers and forensics experts. It also can be used for security tests.
![10 dnsenum](https://github.com/user-attachments/assets/3e1893ae-0702-49a2-91cb-55fdc59c9613)

##smtp-user-enum
Username guessing tool primarily for use against the default Solaris SMTP service. Can use either EXPN, VRFY or RCPT TO.


In metasploit list all the usernames using head /etc/passwd or cat /etc/passwd:

select any username in the first column of the above file and check the same


#Telnet for smtp enumeration
Telnet allows to connect to remote host based on the port no. For smtp port no is 25
telnet <host address> 25 to connect
and issue appropriate commands
  
 ##Output
  
  

## nmap –script smtp-enum-users.nse <hostname>

The smtp-enum-users.nse script attempts to enumerate the users on a SMTP server by issuing the VRFY, EXPN or RCPT TO commands. The goal of this script is to discover all the user accounts in the remote system.


## OUTPUT:


## RESULT:
The Google hacking keywords and enumeration tools were identified and executed successfully


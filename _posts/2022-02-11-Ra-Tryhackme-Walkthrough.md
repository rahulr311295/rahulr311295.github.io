---
layout: single
title: Tryhackme Ra Walkthrough
excerpt: "Ra is a windows machine which starts with a typical business website for Windcorp where there is a password reset function which can be used to change a user's password to gain access to a SMB share to download spark live chat application which is vulnerable that can be used to harvest a user's NTLM hash that can be used to gain initial access to the machine.On further exploring the machine a script can be seen that contains a username who's password can be changed since the user has extended rights to change password as he is a member of the account operator group.Analysing the script we can see that there is command injection vulnerability that can be abused to gain admin privilege and pwn the machine"
date: 2022-02-11
classes: wide
header:
  teaser: /assets/images/ra1.1/ra.png
  teaser_home_page: true
categories:
  - tryhackme
  - infosec
tags:  
  - smb
  - privesc
  - windows
  - bloodhound
  - spark
---


## Story
```
You have gained access to the internal network of WindCorp, the multibillion dollar company, running an extensive social media campaign claiming to be unhackable (ha! so much for that claim!).

Next step would be to take their crown jewels and get full access to their internal network. You have spotted a new windows machine that may lead you to your end goal. Can you conquer this end boss and own their internal network?

Happy Hacking!
```

# Recon

## Nmap
A Nmap  full scan shows multiple open ports running different services one of then that stands out is port **80** which is a webserver also in the nmap output there is a domain name which can be added to out hosts file.
```bash
# Nmap 7.92 scan initiated Sun Feb  6 11:21:06 2022 as: nmap -sC -sV -Pn -p- -oN initial 10.10.85.15
Nmap scan report for 10.10.85.15
Host is up (0.21s latency).
Not shown: 65499 filtered tcp ports (no-response)
PORT      STATE SERVICE             VERSION
53/tcp    open  domain              Simple DNS Plus
80/tcp    open  http                Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Windcorp.
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec        Microsoft Windows Kerberos (server time: 2022-02-06 06:10:15Z)
135/tcp   open  msrpc               Microsoft Windows RPC
139/tcp   open  netbios-ssn         Microsoft Windows netbios-ssn
389/tcp   open  ldap                Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
2179/tcp  open  vmrdp?
3268/tcp  open  ldap                Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
3389/tcp  open  ms-wbt-server       Microsoft Terminal Services
|_ssl-date: 2022-02-06T06:12:05+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: WINDCORP
|   NetBIOS_Domain_Name: WINDCORP
|   NetBIOS_Computer_Name: FIRE
|   DNS_Domain_Name: windcorp.thm
|   DNS_Computer_Name: Fire.windcorp.thm
|   DNS_Tree_Name: windcorp.thm
|   Product_Version: 10.0.17763
|_  System_Time: 2022-02-06T06:11:27+00:00
| ssl-cert: Subject: commonName=Fire.windcorp.thm
| Not valid before: 2022-02-05T05:45:30
|_Not valid after:  2022-08-07T05:45:30
5222/tcp  open  jabber              Ignite Realtime Openfire Jabber server 3.10.0 or later
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     errors: 
|       invalid-namespace
|       (timeout)
|     features: 
|     auth_mechanisms: 
|     unknown: 
|     xmpp: 
|       version: 1.0
|     stream_id: 6q1pw8isix
|_    compression_methods: 
| ssl-cert: Subject: commonName=fire.windcorp.thm
| Subject Alternative Name: DNS:fire.windcorp.thm, DNS:*.fire.windcorp.thm
| Not valid before: 2020-05-01T08:39:00
|_Not valid after:  2025-04-30T08:39:00
|_ssl-date: 2022-02-06T06:12:06+00:00; 0s from scanner time.
5223/tcp  open  ssl/jabber
| ssl-cert: Subject: commonName=fire.windcorp.thm
| Subject Alternative Name: DNS:fire.windcorp.thm, DNS:*.fire.windcorp.thm
| Not valid before: 2020-05-01T08:39:00
|_Not valid after:  2025-04-30T08:39:00
|_ssl-date: 2022-02-06T06:12:05+00:00; 0s from scanner time.
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     errors: 
|       (timeout)
|     features: 
|     auth_mechanisms: 
|     unknown: 
|     xmpp: 
|_    compression_methods: 
5229/tcp  open  jaxflow?
5262/tcp  open  jabber
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     errors: 
|       invalid-namespace
|       (timeout)
|     features: 
|     auth_mechanisms: 
|     unknown: 
|     xmpp: 
|       version: 1.0
|     stream_id: 7kayxe2awz
|_    compression_methods: 
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
5263/tcp  open  ssl/jabber
| ssl-cert: Subject: commonName=fire.windcorp.thm
| Subject Alternative Name: DNS:fire.windcorp.thm, DNS:*.fire.windcorp.thm
| Not valid before: 2020-05-01T08:39:00
|_Not valid after:  2025-04-30T08:39:00
|_ssl-date: 2022-02-06T06:12:05+00:00; 0s from scanner time.
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     errors: 
|       (timeout)
|     features: 
|     auth_mechanisms: 
|     unknown: 
|     xmpp: 
|_    compression_methods: 
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
5269/tcp  open  xmpp                Wildfire XMPP Client
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     errors: 
|       (timeout)
|     features: 
|     auth_mechanisms: 
|     unknown: 
|     xmpp: 
|_    compression_methods: 
5270/tcp  open  ssl/xmpp            Wildfire XMPP Client
| ssl-cert: Subject: commonName=fire.windcorp.thm
| Subject Alternative Name: DNS:fire.windcorp.thm, DNS:*.fire.windcorp.thm
| Not valid before: 2020-05-01T08:39:00
|_Not valid after:  2025-04-30T08:39:00
|_ssl-date: 2022-02-06T06:12:06+00:00; 0s from scanner time.
5275/tcp  open  jabber
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     errors: 
|       invalid-namespace
|       (timeout)
|     features: 
|     auth_mechanisms: 
|     unknown: 
|     xmpp: 
|       version: 1.0
|     stream_id: 6p72sw8xd
|_    compression_methods: 
5276/tcp  open  ssl/jabber          Ignite Realtime Openfire Jabber server 3.10.0 or later
|_ssl-date: 2022-02-06T06:12:05+00:00; 0s from scanner time.
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     errors: 
|       (timeout)
|     features: 
|     auth_mechanisms: 
|     unknown: 
|     xmpp: 
|_    compression_methods: 
| ssl-cert: Subject: commonName=fire.windcorp.thm
| Subject Alternative Name: DNS:fire.windcorp.thm, DNS:*.fire.windcorp.thm
| Not valid before: 2020-05-01T08:39:00
|_Not valid after:  2025-04-30T08:39:00
5985/tcp  open  http                Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7070/tcp  open  http                Jetty 9.4.18.v20190429
|_http-server-header: Jetty(9.4.18.v20190429)
|_http-title: Openfire HTTP Binding Service
7443/tcp  open  ssl/http            Jetty 9.4.18.v20190429
| ssl-cert: Subject: commonName=fire.windcorp.thm
| Subject Alternative Name: DNS:fire.windcorp.thm, DNS:*.fire.windcorp.thm
| Not valid before: 2020-05-01T08:39:00
|_Not valid after:  2025-04-30T08:39:00
|_http-title: Openfire HTTP Binding Service
|_http-server-header: Jetty(9.4.18.v20190429)
7777/tcp  open  socks5              (No authentication; connection failed)
| socks-auth-info: 
|_  No authentication
9090/tcp  open  zeus-admin?
9091/tcp  open  ssl/xmltec-xmlmail?
| ssl-cert: Subject: commonName=fire.windcorp.thm
| Subject Alternative Name: DNS:fire.windcorp.thm, DNS:*.fire.windcorp.thm
| Not valid before: 2020-05-01T08:39:00
|_Not valid after:  2025-04-30T08:39:00
9389/tcp  open  mc-nmf              .NET Message Framing
49670/tcp open  msrpc               Microsoft Windows RPC
49674/tcp open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc               Microsoft Windows RPC
49676/tcp open  msrpc               Microsoft Windows RPC
49695/tcp open  msrpc               Microsoft Windows RPC
49911/tcp open  msrpc               Microsoft Windows RPC
6 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :

Host script results:
| smb2-time: 
|   date: 2022-02-06T06:11:30
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Feb  6 11:42:19 2022 -- 1 IP address (1 host up) scanned in 1272.50 seconds

```

## Port 80 (webserver)
Visiting the webserver shows a company website for **windcorp** which contains information regaring the company the employees etc also in the website there is something that stands out a space that shows IT support people who are online at the moment which will be used in a later stage.

![](/assets/images/ra.1.1/webpage.png)

![](/assets/images/ra.1.1/itstaffs.png)

![](/assets/images/ra.1.1/users.png)



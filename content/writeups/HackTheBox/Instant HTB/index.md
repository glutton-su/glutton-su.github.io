---
title: "Instant"
description: A simple writeup of Instant Box of HTB.
date: 2025-03-14
hidemeta: true
tags:
- HackTheBox
- Medium
---

# Instant-htb

First of all add the machine IP to your /etc/hosts file.

The nmap scan for the machine IP showed:

![Screenshot_2024-12-13_08-43-17.png](Instant-htb%2015bb62881f09801a8d20e31537db9e35/Screenshot_2024-12-13_08-43-17.png)

I didn’t use any options as it gives quick results but also provides less details.

There is http and ssh in default ports. The HTTP server seems to be a wallet webapp. Only interaction i could get was download and contact us. I downloaded  the apk  and used apktools.

`apktool d instant.apk`

This revealed the application’s code and assets, including Smali files that contain the app’s logic.

I checked “/smali/com/instantlabs/instant/adminactivities.smali” and found a JWT token and used it in burp suite. Also, I found another sub domain there “*mywalletv1.instant.htb*”. Using this as host and adding the JWT token as authorization I ran burpsuite.

![Screenshot_2024-12-13_12-15-53.png](Instant-htb%2015bb62881f09801a8d20e31537db9e35/Screenshot_2024-12-13_12-15-53.png)

Then I looked in xml directory inside res directory. I concated the “network_security_config.xml” file and found another subdomain, “swagger-ui.instant.htb”. Then i used this in burp requesto to views logs.

![Screenshot_2024-12-13_12-23-40.png](Instant-htb%2015bb62881f09801a8d20e31537db9e35/Screenshot_2024-12-13_12-23-40.png)

![Screenshot_2024-12-13_12-25-01.png](Instant-htb%2015bb62881f09801a8d20e31537db9e35/Screenshot_2024-12-13_12-25-01.png)

Then I used LFI exploit

![Screenshot_2024-12-13_12-28-46.png](Instant-htb%2015bb62881f09801a8d20e31537db9e35/Screenshot_2024-12-13_12-28-46.png)

I used LFI to get ssh key

![Screenshot_2024-12-13_12-42-19.png](Instant-htb%2015bb62881f09801a8d20e31537db9e35/Screenshot_2024-12-13_12-42-19.png)

# Privilege Escalation

After gaining the ssh shell, I used [linpeas.sh](http://linpeas.sh) to scan the machine and found an db(instant.db).

There were some hashed passwords and usernames but i was unable to crack the hash. So, I checked another file i found using linpeash, “sessions-backup.dat” present in /opt/backups folder.

It normally contains passwords for root. It had encrypted password. 

 I used this github repo to crack it: “[https://github.com/ItsWatchMakerr/SolarPuttyCracker](https://github.com/ItsWatchMakerr/SolarPuttyCracker)”.

![Screenshot_2024-12-15_10-54-42.png](Instant-htb%2015bb62881f09801a8d20e31537db9e35/Screenshot_2024-12-15_10-54-42.png)

![Screenshot_2024-12-15_10-56-51.png](Instant-htb%2015bb62881f09801a8d20e31537db9e35/Screenshot_2024-12-15_10-56-51.png)

![Screenshot_2024-12-15_10-59-11.png](Instant-htb%2015bb62881f09801a8d20e31537db9e35/Screenshot_2024-12-15_10-59-11.png)

Then I switched to root and got the root flag.
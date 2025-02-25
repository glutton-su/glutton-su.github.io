---
title: "Rabbit Store"
description: A simple writeup of this Medium box.
type: "text"
date: 2025-02-22
hidemeta: true

---
# Rabbit Store

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image.png)

# Enumeration

For port enumeration, I started with rustscan and then did a detailed scan with nmap.

Rustscan result:

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%201.png)

nmap result for the ports:

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%202.png)

For directory enumeration, I mainly use gobuster.

Gobuster directory enumeration:

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%203.png)

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%204.png)

There wasn’t anything useful i could get from here so I went back to main site.

Then, I tried signing up but it was for subscribed users only. Then after some messing around I found we can add another parameter in burp request. also we have to change our email and password while sending the request. These will be our creds to login as subscribed user.

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%205.png)

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%206.png)

# Getting shell

This is what we see when login. There is a file upload but it strips the extension and uploads it. while going to the file path it is downloaded to the system.

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%207.png)

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%208.png)

Now let’s try getting it local host files.

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%209.png)

It works!! BUT idk if it will give me anything outside /var 

SINCE, this is rabbit mq, maybe there is an admin port in the [localhost](http://localhost) of the machine?? Let’s try.

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%2010.png)

Looks like it works.

Looking at this result, I didn’t find anything interesting so, I fuzzed /api endpoint.

After fuzzing for /api endpoints i found a /api/docs endpoint which then uploaded gave a interesting endpoint of an chatbot

After catching the request for chatbot, i messed around a bit but could not find anything. After I received a hint that there was either XSS or SSTI, I realized there was no XSS so I then searched for SSTI exploit payloads. A simple payload, if I were to put some values between two curly brackets like so {{7*3}} it’s result would be printed in the response. This worked, which meant I could insert a payload to gain a reverse shell. As I had no experience in exploiting SSTI, I asked the almighty ChatGPT for help. It generated me a payload which I inserted in the username parameter.

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%2011.png)

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%2012.png)

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%2013.png)

# Privilege Escalation

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%2014.png)

With a linpeas scan I found a directory called rabbitmq. When I listed all files I found a cookie file. This could mean we have a exploit using this cookie??

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%2015.png)

Searching for erlang in metasploit we do get a cookie reverse shell exploit. BUT this wasn’t working on my machine because my metasploit was recently updated, so I had to use TryHackMe attackbox. After gaining a shell of rabbitmq from metasploit, I ran a python3 reverse shell and got the shell in my machine. 

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%2016.png)

Remember how we got index.html of the admin port through [localhost](http://localhost)? We are going to forward that port to our localhost so that we can access the admin page. For this i used chisel and forwarded the port.

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%2017.png)

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%2018.png)

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%2019.png)

The default credentials were not working, digging around in official documentation of rabbitmq, we need to make the user with admin permission ourselves then we can access the page. So, I again closed the chisel server-client i was running and created the user called admin in the rabbitmq’s shell and again ran chisel.

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%2020.png)

IT WORKED!!

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%2021.png)

Looking around, I find a interesting file and downloaded it.

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%2022.png)

Turns out this contains hashes, what a luck right? NOOOO

I spent more than 5 hours trying to crack it but no use. THIS WAS A RABBIT HOLE.

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%2023.png)

After many trials and errors we found the password for root, the password seems to be the hash it self.

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%2024.png)

![image.png](Rabbit%20Store%201a2b62881f098084a8c9ffae9b796ac5/image%2025.png)
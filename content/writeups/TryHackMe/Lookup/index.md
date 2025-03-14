---
title: "Lookup"
description: A simple writeup of this easy box.
date: 2025-01-27
hidemeta: true
---

![image.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/image.png)

after gaining the ip of machine i quickly started nmap scan

`nmap <machine_ip>`

i found there were two ports running 

# 22 for ssh and 80 for http

![lookup_nmap.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/lookup_nmap.png)

Then I tried to take a peek at the page running on port 80 and realized I had to edit my hosts file

`sudo echo <machine_ip> lookup.thm>>/etc/hosts`

then accessing the webpage I got a login page where I tried default creds [admin:admin].

but it didn't work and asked me to try again 3 seconds later.

Then I used wappalyzer to see which version of apache it is using. It was v 2.4.41 which tried to search for exploits but couldn’t find.

![Screenshot_2024-11-27_10_03_03.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/8403eaba-4230-4c19-92b9-45cdf6119e56.png)

then I used hydra tool to gain the password

`hydra -l admin -P ~/Downloads/rockyou.txt lookup.thm http-post-form "/login.php:username=^USER^&password=^PASS^:Wrong password. Please try again."`

here, hydra will put up a http-post request, the ‘^USER^’ will be replaced by admin and ‘^PASS^’ will be replaced by rockyou.txt. hydra will then check if the combination returns wrong password, if it doesn’t then it will return us the password

![hydralookup.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/hydralookup.png)

and i got a password.

![adminpass.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/adminpass.png)

i tried logging in with this but  still couldn’t get in. so i tried to find the username for obtained password. i found about login.php from its source code.

![usernamefind.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/usernamefind.png)

then i got a username jose

![josepasslkup.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/josepasslkup.png)

with this we can log in to the website. 

![loginlookup.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/loginlookup.png)

and we are redirected to files.lookup.thm which we need to add to our hosts file to access

![subdoinlookup.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/subdoinlookup.png)

![filesInLooup.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/filesInLooup.png)

we have two files without locks so i opened them up test file was empty but creds file had smth

![creds_txt.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/creds_txt.png)

I thought maybe this is ssh login pass but seems like i fell to a rabbit-hole. But we have a user “think”. Then i tried to gather more info from this site and i found this

![Screenshot_2024-11-27_10-29-27.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/Screenshot_2024-11-27_10-29-27.png)

i searchsploit elfinder and i found its vunlerabilities

![elfindersploit.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/elfindersploit.png)

then i ran metasploit and searched for it: `search elfinder 2.1.48` and got one exploit. i used it and after setting some options i ran it and gained a meterpreter shell

![Screenshot_2024-11-27_10_48_44.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/1e43f06a-2c85-4d9a-8656-d8a8668c9707.png)

![Screenshot_2024-11-27_10_49_49.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/2d33af82-a67d-4b9e-ab52-b329c852a62e.png)

here the rhosts should have been files.lookup.thm, which i later corrected and it returned a meterpreter shell. after i got the shell i ran a few commands, we were logged in as www-data. so i looked up how can i escalate my privileges to that of a user. we already have a user called ‘think’, so my first thought was to check for login creds. I ran a find command to search for files with perms 4000

`find / -perm  /4000 2>/dev/null`

![perm s.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/perm_s.png)

here, the interesting one was `/usr/sbin/pwm` when i tried to run it, it was searching for .passwords file.

![image.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/image%201.png)

 then i went on to `/tmp` directory as it is worldwritable. i created a file named id there.
`echo -e '#!/bin/bash\n echo "uid=33(think) gid=33(think) groups=33(think)"' > id`

also make id an executable file `chmod +x id`

![thinkusr.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/thinkusr.png)

then  i ran the `/pwm` again and got a list of passwords which I saved to a file in my machine. After which  i started hydra to bruteforce ssh of ‘think’ user.

![thinkPass.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/thinkPass.png)

I successfully got the ssh password and logged in.

![Screenshot_2024-11-27_11_07_40.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/ec2c7910-ab05-42a8-863d-59e9a002cc25.png)

the user flag was just one `ls` away. following to it I searched for something i could use without root permissions. `sudo -l`

doing this i found `look` so i went to gtfobins and there it was

![Screenshot_2024-11-27_11_14_20.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/11edc3bb-eb83-41ea-9665-78d7a1f0cf75.png)

what we need is the third one

```
LFILE=/root/.ssh/id_rsa

sudo look '' "$LFILE"
```

this gives us direct access to .ssh file of root and displays the id_rsa

![Screenshot_2024-11-27_11_10_25.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/Screenshot_2024-11-27_11_10_25.png)

I saved this to my machine and gave it perms 600 and sshed to root

![ridrsa.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/ridrsa.png)

![Screenshot_2024-11-27_11_13_08.png](lookup%20thm%20149b62881f0980b78996cc37fe1ab28a/e06c29c3-b37c-4b4a-90f8-3f880bd1d1ef.png)

then root flag is found with just `ls`
[# Relevant room tryhackme:

#   

*   using rustscan for scanning open ports :

  

![](https://t9003275564.p.clickup-attachments.com/t9003275564/f2564d31-c853-4dc0-b343-fddb8ad2c0b8/image.png)

http port is open lets try open the browser :

![](https://t9003275564.p.clickup-attachments.com/t9003275564/6faa1c9c-6191-4482-a221-ac8d6d34458b/image.png)

  

we can see that port 445 of smb is open lets do some smb Enumeration :

![](https://t9003275564.p.clickup-attachments.com/t9003275564/a157a135-77ee-46c4-b479-02dca6a30c6f/image.png)

![](https://t9003275564.p.clickup-attachments.com/t9003275564/f1328341-445a-4e39-af8e-2837d69ec04c/image.png)

we gain some info on the system :

message\_signing: disabled (dangerous, but default) - maybe smb relay ?

| smb2-security-mode:

| 3:1:1:

|\_ Message signing enabled but not required

| smb-os-discovery:

| OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)

| Computer name: Relevant

| NetBIOS computer name: RELEVANT\\x00

| Workgroup: WORKGROUP\\x00

|\_ System time: 2023-11-30T10:33:11-08:00

  

  

lets try to connect to the smb server :

![](https://t9003275564.p.clickup-attachments.com/t9003275564/b743d1d6-d245-41a4-8c2b-6b27eb1c910e/image.png)

we can see an intresting share here nt4wrksv let try to accsess it:

![](https://t9003275564.p.clickup-attachments.com/t9003275564/6e3b2c12-dd33-4d93-8e5e-3918d598489e/image.png)

we made it !

we found some passwords.txt file including :

![](https://t9003275564.p.clickup-attachments.com/t9003275564/bc5a9a55-c529-40b3-ac97-cf02986307d9/image.png)

very intresting its looks like base64 format lets decode it :

Let's decode the strings:

1. `Qm9iIC0gIVBAJCRXMHJEITEyMw==` decodes to `Bob - !P@$$W0rD!123`.
2. `QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk` decodes to `Bill - Juw4nnaM4n420696969!$$`.

we now can try and login with these users :

  

the users not really helps us as we can see we cant login :

![](https://t9003275564.p.clickup-attachments.com/t9003275564/fcccda3d-7818-4b05-bcd1-0d38b9b2d3e5/image.png)

  

  

pretty tough ah , lets go back to the other ports that we found :

  

![](https://t9003275564.p.clickup-attachments.com/t9003275564/cbfeb736-1dc9-4a72-a44c-47b3a5a99c87/image.png)

  

let use [dirsearch.py](http://dirsearch.py) or ffuz to enumerate the other ports also :

  

![](https://t9003275564.p.clickup-attachments.com/t9003275564/c8b6740d-ac52-4c83-bf08-6cf818830331/image.png)

  

after a while of wating we found something intresting ,

we can see that /nt4wrskv/ directory is not giving us an error.

  

that might be intresting because this is the name of the share we connected to earlier maybe we can upload some file that has reverse shell to the smb share and than it will be also on the windows server directory !

lets set a put shell.aspx reverse shell file in the directory :

  

now go access the file and we got a shell

![](https://t9003275564.p.clickup-attachments.com/t9003275564/9347ca5e-3b0b-4190-ac8f-ef452ec3cda6/image.png)

  

lets display  the security privileges of the current user .

![](https://t9003275564.p.clickup-attachments.com/t9003275564/51ca578d-4b73-4224-bef2-f7b5ffbdc4db/image.png)

we can see that :

SeImpersonatePrivilege Impersonate a client after authentication Enabled

[https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)

we can u printspoofer to escalate this - [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer) :

![](https://t9003275564.p.clickup-attachments.com/t9003275564/63816955-b6eb-47a3-a610-a177d03e2662/image.png)

  

  

![](https://t9003275564.p.clickup-attachments.com/t9003275564/3970ae03-87f1-427d-a522-72246fc6a64b/image.png)

we can see that we are nt authority ( like root in linux)

![](https://t9003275564.p.clickup-attachments.com/t9003275564/92c08bfe-be36-4492-8f47-79e2cada6b3f/image.png)

and we got the user flag

and the root flag :

![](https://t9003275564.p.clickup-attachments.com/t9003275564/6fa5a049-fd52-4aa5-8b3d-4ead87142058/image.png)

  

  

  

THING THAT DIDNT WORK FAILED WHEN TRIED METASPLOIT

  

  

lets scanning Vulnerabilities :

  

![](https://t9003275564.p.clickup-attachments.com/t9003275564/bc8a6fac-5d70-44e9-9b8a-585bb1af8c1a/image.png)

we found that the machine is vulnerable to ms17-010 or in another name [EternalBlue](https://en.wikipedia.org/wiki/EternalBlue) !

  

lets exploit it using Metasploit :

  

didnt work ): and the room creator said you dont need to use metasploit herre so there is a catch
](https://t9003275564.p.clickup-attachments.com/t9003275564/f2564d31-c853-4dc0-b343-fddb8ad2c0b8/image.png)https://t9003275564.p.clickup-attachments.com/t9003275564/f2564d31-c853-4dc0-b343-fddb8ad2c0b8/image.png

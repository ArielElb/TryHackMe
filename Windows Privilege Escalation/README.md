
# Windows Privilege Escalation

write up for thm room :
https://tryhackme.com/room/windows10privesc

## Exploiting Insecure Service Permissions
1. using winpeas
![image](https://github.com/ArielElb/TryHackMe/assets/94087682/3483372e-e751-4615-9df4-a006136dba46)
2.
![image](https://github.com/ArielElb/TryHackMe/assets/94087682/c0cff255-ecd9-44b6-857e-eb0bca7cbbd2)
![image](https://github.com/ArielElb/TryHackMe/assets/94087682/520b1c4e-8d31-43d3-b627-a696092ea219)

key thing we need to know : 

- if we want for example to change the path in the config file to a malicous binary file we need to know that this file will run with the permissions of the service so to actually get elevated priv we need higher priv

![image](https://github.com/ArielElb/TryHackMe/assets/94087682/42b6680e-8369-482a-a8ae-78208700fd28)

### breakdown :

The output of "sc qc" command, which is used to query the configuration information for a specific Windows service. In this case, the service you are querying is named "daclsvc." Let's break down the information:

1. **SERVICE_NAME: daclsvc**
   - This is the name of the service.

2. **TYPE: 10 WIN32_OWN_PROCESS**
   - This indicates that the service runs in its own process and does not share it with other services.

3. **START_TYPE: 3 DEMAND_START**
   - The service starts on demand, meaning it does not automatically start with the system but is started when specifically requested.

4. **ERROR_CONTROL: 1 NORMAL**
   - In case of an error during startup, the system will attempt to start the service normally.

5. **BINARY_PATH_NAME: "C:\Program Files\DACL Service\daclservice.exe"**
   - This specifies the executable file that runs the service. In this case, the executable is located at "C:\Program Files\DACL Service\daclservice.exe."

6. **LOAD_ORDER_GROUP:**
   - This field is empty, indicating that the service does not belong to any specific load order group.

7. **TAG: 0**
   - The tag is a value that determines the load order of services that have the same start type. A tag of 0 means that the service does not have a specific load order.

8. **DISPLAY_NAME: DACL Service**
   - This is the user-friendly display name of the service that is shown in service management tools.

9. **DEPENDENCIES:**
   - There are no dependencies listed, indicating that this service does not depend on other services.

10. **SERVICE_START_NAME: LocalSystem**
    - The service is configured to run under the LocalSystem account, which is a high-privileged built-in account.

In summary, the "daclsvc" service is a demand-start service that runs in its own process, and its executable is located at "C:\Program Files\DACL Service\daclservice.exe." It does not have any dependencies, belongs to no load order group, and is configured to start under the LocalSystem account.


- generate a payload using msfvenom :

![image](https://github.com/ArielElb/TryHackMe/assets/94087682/056d71fc-2fc2-4849-a750-c48811376669)

- Modify the service config and set the BINARY_PATH_NAME (binpath) to the reverse.exe executable you created:
![image](https://github.com/ArielElb/TryHackMe/assets/94087682/5f22a840-7e62-4790-a819-a47eaff7164e)

![image](https://github.com/ArielElb/TryHackMe/assets/94087682/8207074c-f95a-4b86-a315-8bb2938aa6bd)

![image](https://github.com/ArielElb/TryHackMe/assets/94087682/714d361b-0107-402c-8ca6-76cdd340514a)

![image](https://github.com/ArielElb/TryHackMe/assets/94087682/5698e04d-8c19-4ecc-8ad0-9415c2a93a04)


##  Service Exploits - Unquoted Service Path 

"Unquoted service path" is a common security vulnerability that occurs when a service executable's path contains spaces but is not enclosed in double quotation marks. This can potentially lead to privilege escalation or other security issues.

Windows uses a specific search algorithm to locate the executable associated with a service when it starts. This search algorithm involves looking for the executable file in different directories, and it starts from the root of the drive.

When a service is started, Windows follows a predefined path resolution strategy to find the executable file. The system typically searches in the following order:

1. **The directory specified in the service configuration:** This is the path provided when configuring the service. If the path contains spaces and is not enclosed in double quotation marks, it can lead to misinterpretation.

2. **The current working directory:** The directory from which the service was started.

3. **The Windows system directories:** These are directories like `C:\Windows\System32` where system files are located.

4. **The directories listed in the system's PATH environment variable:** The PATH variable contains a list of directories where the operating system searches for executable files.

When a service is configured with an unquoted service path, and the path contains spaces without proper quoting, Windows may misinterpret the path during the search. This can result in unexpected behavior, such as attempting to execute a file with part of the path misunderstood.

By properly quoting paths with spaces, administrators can ensure that the system correctly interprets the full path to the service executable, preventing potential security vulnerabilities associated with the "unquoted service path" issue.

- scanning with winpeas again and as you can see there are services that are unquoted : 
  ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/92198fe3-0886-4deb-a407-550165c74506)

- or using Windows Service Control to query :
  ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/c23f1d25-eb7b-49c7-a3a2-ee9af59d2992)

  we can see that we have Read Write permitions in thr Unqueted Path Service directory because user is part of   the USERS group.
  ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/6fad0f41-4386-4018-b690-13f13adc3086)

 - setting up the payload ( we already had one we created with msf venomd ):
    ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/8125cc98-ebc6-4b31-b1f5-5e365630532b)

   - set a listeer and start the service :
     ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/4281b481-dc25-4f54-a079-736fc34cc9ca)
     ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/9dd138f9-4764-41e6-adbd-7e622bb092cd)
     as we can see we are nt authority!
     
     ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/070571d6-8966-4c9e-a373-b61eb9dd854e)

##  Service Exploits - Weak Registry Permissions:
   - we can see in winpeas there is a service registry we can edit and change the path of from the real             services to a malicious such as reverse shell, if this service have higher privileges we can escalte them.
   ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/27591201-7651-40b4-b0e6-55ac62efc933)
   - or with the command - sc qc regsvc :
     Query the "regsvc" service and note that it runs with SYSTEM privileges (SERVICE_START_NAME).
   ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/964d901c-9c0e-43d5-a9e2-2a78a15955fb)

   - Using accesschk.exe, note that the registry entry for the regsvc service is writable by the "NT                AUTHORITY\INTERACTIVE" group (essentially all logged-on users):
  
     C:\PrivEsc\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc :
     The service start name is “LocalSystem”, meaning the service runs under the Local System account, which        has full access to the system.
     ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/bb812a27-1403-4d63-9df6-e3788bf98232)

   - Overwrite the ImagePath registry key to point to the reverse.exe executable you created:
     using the command :
     reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d             
     C:\PrivEsc\reverse.exe /f
     ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/d9fb224a-8639-4079-bcfb-89bb4e351156)

   - we can also edit it from the regisry editor :
     ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/f103e28d-2e40-4a93-9d66-9608d6d17ce4)


Deeper explanation :

- `reg add` is a command that adds a new subkey or entry to the registry.
- `HKLM\SYSTEM\CurrentControlSet\services\regsvc` is the path of the subkey that holds the registry item that you want to change. In this case, it is the subkey for the service named "RegSVC".
- `/v ImagePath` is the parameter that specifies the name of the registry entry that you want to add or change. In this case, it is the "ImagePath" entry, which contains the path of the executable file for the service.
- `/t REG_EXPAND_SZ` is the parameter that specifies the type of the registry entry that you want to add or change. In this case, it is the "REG_EXPAND_SZ" type, which is a null-terminated string that contains unexpanded references to environment variables (for example, "%PATH%").
- `/d C:\PrivEsc\reverse.exe` is the parameter that specifies the data for the registry entry that you want to add or change. In this case, it is the path of the reverse.exe executable that you created.
- `/f` is the parameter that forces the command to overwrite the existing registry entry without prompting for confirmation.

The command will overwrite the "ImagePath" registry entry for the "RegSVC" service with the path of the reverse.exe executable that you created. This means that the next time the service is started, it will run the reverse.exe executable instead of the original one. This can be used to gain a reverse shell or execute arbitrary code on the system.

##  Service Exploits - Insecure Service Executables:

A brief explanation of service exploits - insecure service executables is:
- Service exploits are a type of privilege escalation technique that targets Windows services, which are programs that run in the background and perform various tasks for the system or applications.
- Insecure service executables are services that use executable files with weak permissions, meaning that they can be modified or overwritten by unprivileged users.
- An attacker can exploit this vulnerability by replacing the original executable file with a malicious one, such as a reverse shell or a code injector, and then restarting the service. This will execute the malicious code with the same privileges as the service, which could be SYSTEM, the highest level of access on Windows.
- To identify insecure service executables, one can use tools such as sc, accesschk, or winPEAS to list the services and their permissions, and then look for services that have write access for low-privileged users or groups, such as Everyone, Users, or Authenticated Users.
- To exploit insecure service executables, one can use tools such as msfvenom, nc, or powershell to generate a malicious executable file, and then copy it to the location of the original executable file, overwriting it. Then, one can use tools such as sc, net, or psexec to restart the service and trigger the exploit. This will result in a reverse shell or code execution on the target system.

     
   1. scan for insecure service executables with winPEAS :
   ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/6ee60f09-82f5-45c6-ba60-f02a3c59085d)
   2. verify using the command sc qc filepermsvc
       ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/23fef0e2-7584-4ce4-8f78-7c34df5521f3)
      we can see that service running an executable with LocalSytem privileges.
      and that the file permmisions is everyone , we can also see this using the next command :
      ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/2f592683-5a13-433a-bc2b-d3e0ff44750f)

  
   4. lets exploit it by editing the path to be a binary of reverse shell to our attack machine that will have       local system permissions:
      - set up a listener using metasploit :
      ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/6e6f9765-b2cb-444c-bce8-131b60f4e825)

      - set the new path to the reverse shell :
        ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/2b6b2fe9-8c41-4213-9ada-139b3089506d)
      - start the service and active the reverse shell :
        ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/df53a312-c8e8-4b4e-8503-a418c07dc02a)
      ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/9f27c830-8a3e-4416-a569-8b5fe51e4bee)

        
  ##  Windows Privilege Escalation - Exploiting AutoRun Programs

   Autoruns are programs that automatically start when Windows boots up or when a user logs in. They are usually stored in the Run or RunOnce registry keys, which contain the path of the executable file for the program. Registry autoruns can be used for legitimate purposes, such as launching antivirus software or system utilities, but they can also be exploited by malware or attackers to gain persistence or privilege escalation on a system.
   
   There are two main ways to exploit autoruns:
   
   - If an attacker can write to the registry key that controls the autorun program, they can change the path of the executable file to point to a malicious one. This way, the malicious program will run instead of the original one when Windows starts or when a user logs in. This can be used to execute arbitrary code, create a backdoor, or steal information from the system.
   - If an attacker can overwrite the executable file of the autorun program with a malicious one, they can achieve the same effect as the previous method. This requires the attacker to have write access to the folder where the executable file is located, which may be protected by the system or the owner of the file.
   
   To identify and exploit registry autoruns, an attacker can use various tools, such as:
   
   - Reg, a command-line tool that can query, add, or modify registry keys and values¹.
   - Icacls or Accesschk, command-line tools that can display or modify the permissions of files and folders.
   - WinPEAS, a script that can enumerate various information about the system, including registry autoruns and their permissions⁴.
   - Autorunsc, a tool from Sysinternals that can list all the autorun programs on the system and their locations.
   - MSFvenom, a tool that can generate malicious executable files for various payloads, such as reverse shells or code injectors.
   - Netcat, a tool that can create network connections and listen for incoming connections, which can be used to catch reverse shells from the exploited system.

   1. Lets search for vulnerable registry entries that we can change  (the path need to modifiable) using winPEAS :
      ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/ee3f20aa-4f18-4628-953d-d82de38891f0)
      ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/c7f92369-74c2-4773-bcf8-61a6888c71d7)

  or with using the command :
   ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/b5f2f1cd-16f3-4a98-a459-50e483bd3520)

   2. Using accesschk.exe, note that one of the AutoRun executables is writable by everyone:
   ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/2f430271-1d40-4e2f-b849-7aacf232cf95)
   
   3. Copy the reverse.exe executable you created and overwrite the AutoRun executable with it:
    ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/fd0f0840-3985-4ab3-8b2a-31d05e86d0d5)

   4.Start a listener on Kali and then restart the Windows VM. Open up a new RDP session to trigger a reverse shell running with admin privileges. You should not have to authenticate to trigger it, however if the payload does not fire, log in as an admin (admin/password123) to trigger it. Note that in a real world engagement, you would have to wait for an administrator to log in themselves!
     ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/cf6b7748-916f-474d-a87c-7286110e271d)

   ##  Windows Privilege Escalation - Exploiting AlwaysInstallElevated:

  AlwaysInstallElevated exploit is a way to gain elevated privileges on a Windows system by abusing a policy that allows non-administrator users to install MSI packages with SYSTEM level permissions. This means that an attacker can create a malicious MSI package that executes arbitrary code and install it on the target system, resulting in privilege escalation. To exploit this vulnerability, the attacker needs to have write access to the registry keys that control the policy, or to the folder where the MSI package is located. There are various tools that can help to identify and exploit this vulnerability, such as Reg, Icacls, WinPEAS, Autorunsc, MSFvenom, and Netcat.

  1. lets start by Query the registry for AlwaysInstallElevated keys:
     - reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated:
       
       ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/b77a97b0-16cd-4673-a0de-94f0f0f0d077)

     - reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated:
        
      ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/cc88b558-6aa2-48ce-9699-edc905953926)

The commands   are used to query the registry values of the AlwaysInstallElevated policy on the current user (HKCU) and local machine (HKLM) keys. This policy determines whether non-administrator users can install MSI packages with SYSTEM level permissions, which can be exploited for privilege escalation. If the commands return 1 for both keys, it means the policy is enabled and the system is vulnerable. If the commands return 0 or do not find the values, it means the policy is disabled or not configured and the system is not vulnerable.

2. upload the reverse.msi to the windows machine after created using msfvenom and set a listener on kali:
   ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/32e7721b-df86-4f89-b6eb-8f8546e7b836)
   ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/f5fe416c-3ae9-40c6-aa01-6b314bd9ba53)


3. run the command: msiexec /quiet /qn /i C:\PrivEsc\reverse.msi to get the reverse shell
![image](https://github.com/ArielElb/TryHackMe/assets/94087682/acc4a421-7080-4b63-bf14-4f98a94b3cc8)
![image](https://github.com/ArielElb/TryHackMe/assets/94087682/6d7c1489-2504-486e-9a96-fe30d967d98d)



  ## Searching For Passwords In Windows Registry:

  1. lets begin with searching for passwords within the registry using the command :
     - reg query HKLM /f password /t REG_SZ /s
        ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/bd8ce217-4eca-4cc9-b0a0-0f7e6de23eb2)
       we can note that its very inefficient and slow and got alot of useless information.

   2. we can search for more spesifc information with the command:
      - reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
        ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/33e0aa15-b23a-4214-8b09-02714cd6ebcc)
explanation:
The command is used to query the registry subkey that contains information about the Windows logon process. The command will return the name, type, and data of all the values under the subkey HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon. Some of the values that can be found under this subkey are¹:

- AutoAdminLogon: A string value that determines whether Windows automatically logs on a user account when the system starts. The default value is 0, which means disabled. If set to 1, Windows will use the credentials stored in the DefaultUserName, DefaultPassword, and DefaultDomainName values to log on the user.
- DefaultUserName: A string value that specifies the user name for the automatic logon process. This value is only used if AutoAdminLogon is set to 1.
- DefaultPassword: A string value that specifies the password for the automatic logon process. This value is only used if AutoAdminLogon is set to 1.
- DefaultDomainName: A string value that specifies the domain name for the automatic logon process. This value is only used if AutoAdminLogon is set to 1.
- Shell: A string value that specifies the program that runs as the user interface. The default value is explorer.exe, which runs the Windows Explorer shell. This value can be changed to run a different program as the shell, such as cmd.exe or powershell.exe.
- Userinit: A string value that specifies the program that runs after a user logs on. The default value is userinit.exe, which initializes the user environment. This value can be changed to run a different program after the user logs on, such as a script or a malware.

   3. lets use winPEAS to see the information more clearly and search for more information:
      ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/4cec0649-21b2-43cb-b54f-ce488fc4e6e4)
      we can also decode the base64:
      ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/4fa0bf7b-206a-4f80-a026-1e06a2c510a8)

   4. connecting using psexec :
      ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/077414d6-e132-48e2-ad39-fbb2e80c8f56)

##  Windows Privilege Escalation - Using Stored Credentials:

   1. we gonna use cmdkey windows tool , but what is cmdkey ?
      Windows cmdkey is a command-line tool that creates, lists, and deletes stored user names and passwords or credentials. These credentials can be used to access remote servers, network resources, or web sites that require authentication. Windows cmdkey can also retrieve credentials from a smart card if one is available on the system.

Some of the benefits of using Windows cmdkey are:

- It can help you manage multiple credentials for different targets without having to enter them every time.
- It can improve the security of your credentials by storing them in an encrypted form and preventing unauthorized access.
- It can automate the logon process for remote servers or network resources by using the /add or /generic parameters.
- It can delete unwanted or outdated credentials by using the /delete parameter.

Some of the limitations of using Windows cmdkey are:

- It can only store user names and passwords, not other types of credentials such as certificates or tokens.
- It can only store credentials for the current user, not for other users or groups.
- It can only store credentials for the local machine, not for other machines or domains.
- It can only store credentials for the current session, not for future sessions.

   1. lets list any saved credentials using cmdkey tool:
   ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/3a04ff0b-eb13-4b50-807b-ff7fa78e980e)       2. or using the credential manger
   ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/12c64367-43bc-4642-8f2b-604c2c2c67dc)

  - we can see that there are some admin acoount with higher priviliges that is part of the local windows administrators group.
  - we can use this saved credentials to run .exe with the admin permissions:
    
   ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/a8183b64-965d-408c-897b-8ab7e0c99828)
   ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/0b8ef6d1-89c4-4cfd-bf48-86afbea7f90f)


  ##  Passwords - Security Account Manager (SAM) :
   - " The SAM and SYSTEM files can be used to extract user password hashes. This VM has insecurely stored backups of the SAM and SYSTEM files in the C:\Windows\Repair\ directory. "
  - Note: We need to understand that it is definitely an unlikely scenario to keep a copy of the *SAM* or *SYSTEM* entirely elsewhere.
But it is more likely that we will extract the hashes from the memory in the post exploitation part when you got an nt authority or other elvated user permissions, that is, from the cache of the lsass process using mimikatz!

1. but we will still go over it lets start from transfering the SAM and SYSTAM files to our attacker machince :
  ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/68edcfbc-2d94-47ad-9bfc-8d917be2ee17)
2. lets dump the hashes using the reddump7 repository :

   - here i actually had a bug because i used python 3.11 and pycrypto doesnt support it so u can see 
      that we can actually do it in the next write up :
         https://0xaniket.medium.com/tryhackme-windows-privesc-walkthrough-e5e323d2282

   - or i will show another method using mimikatz after uploading the mimikatz.exe from /usr/share/windows-resources/mimikatz/x64" :
     ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/ba9d142e-9913-4c07-b5f3-619ba109f6e3)
     ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/d1871eec-6305-4364-a5cd-65402d096bce)


3. Crack the admin NTLM hash using hashcat:
    ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/56573a9a-54a8-4925-8ad9-f35ed3669a13)


## Passing the hash / pass the password:
   1.pass the password using psexec :
      ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/e15f03d8-fed9-4a61-a867-37a6a9596248)

   2. pass the hash -
      To pass the hash using psexec.py, you need to have the following information:

- The target IP address or hostname
- The username of the account you want to impersonate
- The NTLM hash of the account's password

`psexec.py  admin@10.10.221.198 -hashes aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da`

![image](https://github.com/ArielElb/TryHackMe/assets/94087682/765e51b6-76ba-4edc-8b73-eb2d4b8030db)

   - explanation: 

   The psexec.py script, which is a Python implementation of the PsExec tool. PsExec is a tool that allows remote code execution on Windows hosts using SMB and RPC protocols. The output shows the following steps:

- The script requests the shares on the target host 10.10.221.198 using SMB.
- The script finds a writable share named ADMIN$, which is the default administrative share for the system root.
- The script uploads a file named FwfYkPIg.exe to the ADMIN$ share. This file is a binary wrapper based on the PAExec library, which is an open source equivalent to PsExec.
- The script opens the Service Manager on the target host using RPC and creates a service named dsmk that runs the uploaded file as the SYSTEM account.
- The script starts the service dsmk, which creates a named pipe and waits for commands from the script.
- The script sends the process details to the service, such as the command to execute, the user credentials, the priority, the timeout, etc.
- The script sends a request to the service to start the process based on the settings sent.
- The script connects to the stdout, stderr, and stdin pipes of the new process and reads the output until the process is complete.
- The script gets the return code of the new process and stops and removes the service dsmk.
- The script removes the file FwfYkPIg.exe from the ADMIN$ share and disconnects from the SMB connection.
   
   we getting NT AUTHORITY account after running the psexec.py script because the script uses the RemComSvc service to execute the command on the target host. RemComSvc is a lightweight service that runs the command as the SYSTEM account, which is a built-in account that has high privileges and permissions on the local system. The SYSTEM account is also known as NT AUTHORITY\SYSTEM, which is why you see this account name when you run the script. The script uploads the RemComSvc binary to the ADMIN$ share, creates and starts a service named RemComService, runs the command, and then stops and removes the service and the binary.
   
   the service is dsmk, but that is the name of the service that the script creates on the target host using the Service Manager. The script then uses this service to run the uploaded file FwfYkPIg.exe, which is the binary wrapper based on the PAExec library. The PAExec library then uses another service named RemComService, which is the actual service that runs the command as the SYSTEM account. The script does not show the name of the RemComService in the output, but you can see it in the source code of the PAExec library.
   
       
  


        



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
        ![image](https://github.com/ArielElb/TryHackMe/assets/94087682/53097269-dcd3-42a5-bad5-913ec3ec5d2f)
        ![Uploading image.png…]()

        
        

   


   

   

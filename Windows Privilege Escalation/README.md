
# Windows Privilege Escalation

## Exploiting Insecure Service Permissions
1. using winpeas
![image](https://github.com/ArielElb/TryHackMe/assets/94087682/3483372e-e751-4615-9df4-a006136dba46)
2.
![image](https://github.com/ArielElb/TryHackMe/assets/94087682/c0cff255-ecd9-44b6-857e-eb0bca7cbbd2)
![image](https://github.com/ArielElb/TryHackMe/assets/94087682/520b1c4e-8d31-43d3-b627-a696092ea219)

key thing we need to know : 

- if we want for example to change the path in the config file to a malicous binary file we need to know that this file will run with the permissions of the service

![image](https://github.com/ArielElb/TryHackMe/assets/94087682/42b6680e-8369-482a-a8ae-78208700fd28)

### breakdown :

The output you provided is from the "sc qc" command, which is used to query the configuration information for a specific Windows service. In this case, the service you are querying is named "daclsvc." Let's break down the information:

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



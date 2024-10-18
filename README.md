# SOAR/EDR With LimaCharlie Project

## Objective

The primary objective of this project is to write detection rules in LimaCharlie (EDR) and implement SOAR capabilities by utilizing Tines for responsive actions against malicious threats found on endpoints.

### Skills Learned
- Understanding how to configure and write detection rules in LimaCharlie.
- Gained insight on how to configure and utilize Tines for SOAR capabilities.
- Configured pfSense (Firewall) to provide a target endpoint with its own isolated virtual network.
 
### Tools Used

- LimaCharlie
- Tines
- Pfsense
- LaZagne

## General Knowledge
Before we begin I will give a litle background on LimaCharlie, Tines, Pfsense, and LaZagne.

LimaCharlie is a cloud-based Endpoint Detection and Response (EDR) platform. It’s designed for managing security across endpoints with custom detection rules, real-time telemetry, and automation capabilities. Its key features allow security professionals to build and deploy custom rules for detecting threats, automate responses, and collect data for analysis.

Tines is a Security Orchestration, Automation, and Response (SOAR) platform. Its main purpose is to automate repetitive security tasks and incident response processes without the need for code. Its key features allow users to create workflows that automate actions like data enrichment, threat intelligence lookups, and alert responses, making it easier to respond to security incidents efficiently.

pfSense is an open-source firewall and router software. Its main purpose is to provide advanced networking features and security capabilities for small to large networks. For this project, I will be utilizing it to provide my target endpoint with its own isolated virtual network.

LaZagne is a credential-harvesting tool written in Python. Its purpose is to extract stored passwords and sensitive information from a compromised machine. For this project, I will be utilizing LaZagne to simulate malicious activity on the target endpoint so I can write a detection rule in LimaCharlie to promote investigation and response capabilities.

## Project Logial Diagram:
![Screenshot 2024-08-16 151425](https://github.com/user-attachments/assets/c36c24fd-7c68-4914-947c-d1c5082c5f59)
This is the logical diagram of the project, showing everything that will happen, starting from when the malicious process (LaZagne) is run to the isolation of the machine, and a message being sent in Slack to notify the team that the specific endpoint has been isolated. <br> 

To further explain what’s happening in the logical diagram, the target endpoint in red will have malware installed (LaZagne). When that malware is run, an alert will be sent to LimaCharlie; then, that alert will be forwarded to Tines. Tines will simultaneously send the alert details to the SOC team in Slack as well as send an email. <br>

The email/Slack message will include the time the security incident took place, computer name, source IP, process, command line, file path, sensor ID, and the link to the detection (if applicable). In the email, it will also prompt the user (the analyst) with the question, “Does the user want to isolate the machine?” If the user chooses NO, then a message will be sent to the Slack channel saying, “The computer was not isolated. Please investigate.” If the user chooses YES, then LimaCharlie will isolate the machine and send a message to the Slack channel stating the isolation status as well as the computer name.

## Steps
Ref1: Creating Target windows 10 machine:
![Num 1](https://github.com/user-attachments/assets/b1389e8e-5ce6-4f26-bec3-0767c3fd173c)
This Windows 10 virtual machine (vm) will have 8 GB of RAM and 4 CPU cores. What’s important here is the network adapter portion; I will specifically choose a custom network to give this Windows machine its own separate network, isolated from my own machine's network.

<br> 

Ref 2: Creating pfSense firewall/router:
![Num 2](https://github.com/user-attachments/assets/d203bc42-1afa-4022-9076-34aaf2c40e42)
pfSense will have 20 GB of storage, 512 MB of memory, as well as being on the same network adapter as the Windows 10 vm which is VMnet2.

<br>

Ref 3: Setting up pfSense server:
![Num 3](https://github.com/user-attachments/assets/ff3ed150-4322-464b-9c61-5841d45e5577)
Looking at the above screenshot, this is what appeared after going through the pfSense installation process. pfSense's IP address is 192.168.1.1, and for the WAN interface, 192.168.68.134 is the IP address that packets will use to access the internet.

<br>

Ref 4: Configuring pfSense Web interface:
![Num 4](https://github.com/user-attachments/assets/48403bfd-420f-49d5-a285-3a9c40515884)
The red arrow shows I typed in pfSense's Ip address into the address bar to start the web configuration process. During the configuration, I made the primary DNS server 8.8.8.8 which is google's public DNS server and the secondary DNS Server at 4.4.4.4 which is another public DNS server.
<br> <br>
![Num 5](https://github.com/user-attachments/assets/01f86141-0b09-4c8a-8fa8-f020de859c7f)
As for this configuration, I made sure that the LAN IP address is set to 192.168.1.1 which is pfSense's Ip address.

<br>

Ref 5: Configuring Ipv4 for Windows 10 VM for Internet Access:
![Num 6](https://github.com/user-attachments/assets/83211d86-691a-4526-a9da-e3a51fe15d77)
The red arrows show the changes I've made in the target Windows 10 VM's IPv4 settings. I've set the IP address to 192.168.1.100 to ensure the target VM is on the same network as pfSense. I've set the default gateway to 192.168.1.1, which is pfSense's IP address, and I've also done the same for the preferred DNS server. 
<br><br>
![Num 7](https://github.com/user-attachments/assets/bc67f0b5-dfcd-4b04-b46c-6b7358266a24)
This screenshot just shows the target vm is connected to the internet after saving the configurations I've made in Ipv4 settings.

<br>

Ref 6: Creating a new organization:
![Num 7](https://github.com/user-attachments/assets/4c6ee06c-229f-49ba-8d46-73aabaeed765)
After making a LimaCharlie account, I created a new organization called "Payz - SOAR-EDR"

<br>

Ref 7: Creating installation key:
![Num 9](https://github.com/user-attachments/assets/6fa44fcb-360d-49d4-99fb-94b8ecddf5c3)
On the left under "Sensors" I selected "Installation Keys". Afterwards, on the right I click on "Create Installation Key".
![Num 10](https://github.com/user-attachments/assets/477ba7c3-5b01-4f7c-9173-a7b0bfff12fc)
As for the Description of this installation key, I just put the name of the project.

<br>

Ref 8: Downloading LimaCharlie as well as copying Sensor Key:
![Num 11](https://github.com/user-attachments/assets/c6b81d4f-61cc-45c2-9e82-13da230d00e9)
This is where I download the LimaCharlie EDR into the target Windows vm, so I made sure I selected "Windows 64 bit".
![Num 12](https://github.com/user-attachments/assets/8cbd0719-48b5-43d9-bee3-60585c9cd476)
After  downloading LimaCharlie into the vm, I will copy the sensor key.

<br>

Ref 9: Installing LimaCharlie into target vm:
![Num 13](https://github.com/user-attachments/assets/5e348502-9d8f-4192-8232-af277c4bcf06)
To install LimaCharlie, I opened PowerShell and changed into the Downloads directory. After navigating to the Downloads directory, I typed the file name and specified the 'i' in the command to include the sensor key so I could monitor this specific device. After running the command, it shows, circled in red, that the agent was installed successfully.
![Num 14](https://github.com/user-attachments/assets/e6fad4a4-d805-48fe-87da-6816846edcdc)
Heading over to the Windows Services, I can see that the LimaCharlie service is running.


<br>

Ref 10: 



















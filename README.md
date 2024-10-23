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

Ref 10-16: LimaCharlie sensor vision:
![Num 15](https://github.com/user-attachments/assets/4f533d2c-744d-4f81-b9cb-380f6397cf0e)
Now that LimaCharlie is available and running in the background, we can now see everything related to the target machine via Sensors List.
<br> <br>
Ref 11:
![Num 16](https://github.com/user-attachments/assets/6d851d9d-c0fd-4695-ac91-dfcc64a7a5bb)
Looking at an overview, we can see important information related to the target machine, such as its external/internal IP addresses, platform version, and MAC address. We can even isolate this machine from the network, which is very useful during incident response scenarios.
<br><br>

Ref 12:
![Num 17](https://github.com/user-attachments/assets/5ae40760-e754-462b-8e6f-15b5dfcf3b74)
Heading over to the file system sensor, we can see all directories and files installed on the target machine as if we were on the machine itself. We can access critical information such as when a file was created, modified, accessed, as well as the attributes associated with each file, such as whether they are hidden or executables. There's also an option to quickly see file hashes if we ever need to perform any file analysis to see if a particular file is malicous or not.
<br><br>

Ref 13:
![Num 18](https://github.com/user-attachments/assets/ae021981-4b87-4e55-9c24-59ab27f3af3e)
Looking at the network sensor, it essentially allows us to see netstat information, which can be very helpful as it displays all active TCP and UDP connections on a system, showing which IP addresses are communicating with your device and which ports they are using. This way, you'll be able to identify a potential reverse shell by spotting an unfamiliar IP address using a port that is not typically used on that server.
<br><br>

Ref 14:
![Num 19](https://github.com/user-attachments/assets/8ff784b4-f894-4d08-bb48-03ad1b112e87)
Next up are current running processes. With LimaCharlie, we have the ability to immediately kill a running process if we deem it malicious. This is also very helpful during incident response scenarios.
<br><br>

Ref 15:
![Num 20](https://github.com/user-attachments/assets/38a1ebd6-b474-47cd-8d99-03cbc8fed407)
We can also see an event timeline of everything that occurs within the machine, similar to a SIEM. By clicking on a log, I'm able to see valuable information such as the command line executed, process ID, user, and the hash of the executable. This can be very useful during incident response scenarios because we can see a timeline of events if the system gets compromised, allowing us to monitor the adversary's actions.
<br><br>

Ref 16:
![Num 21](https://github.com/user-attachments/assets/ec34630e-3cba-4dae-8709-9b8cd51344ce)
One more very useful sensor is the Users sensor. We can see various information about a specific user, such as their country code, which can be useful for determining unauthorized login access from an unfamiliar geolocation, password age, which tells us when a password needs to be changed, last logon, and so on.

<br>

Ref 17: Running LaZagne:
![Num 22](https://github.com/user-attachments/assets/3268cbc8-e300-44b5-8001-c58bed8e822b)
After installing LaZagne, I ran the following command in powershell: ".\LaZagne.exe all -v"
<br> <br>
To break down what this command did, ".\LaZagne.exe" runs the executable from the current directory. The .\ indicates that the executable is in the current directory.
<br> <br>
The "all" option instructs LaZagne to attempt to recover all types of passwords it supports. LaZagne can extract passwords from web browsers, email clients, Wi-Fi, databases, and many other types of applications.
<br> <br>
The -v option stands for "verbose." This makes the output more detailed, providing additional information about each step of the password recovery process. It is useful for understanding what LaZagne is attempting to do as it tries to extract passwords.
<br><br>

Ref 18-20: Creating detection rule:
![Num 23](https://github.com/user-attachments/assets/0808ce3c-fafd-4894-95fb-2f95d68bf863)
To create a new detection rule, we head over to the menu on the left and select 'D&R Rules,' which stands for Detection & Response rules. The best way to create a new D&R rule is to go to an existing rule, copy and paste it into a new rule, and edit that rule to meet our needs.
<br><br>
From what’s circled in red, I chose this specific rule because it detects Windows process creation, which is essentially what happens when LaZagne.exe is run in PowerShell; it creates a new process.
<br><br>

Ref 19:
![Num 24](https://github.com/user-attachments/assets/2bf31993-ee28-4d82-8ce9-eadff69711a6)
After copying and pasting the rule parameters into a new untitled rule, you can see that this rule has detect and respond parameters. I'll be editing both to successfully detect and respond to the LaZagne process being ran.
<br> <br>

Ref 20:
![Num 25](https://github.com/user-attachments/assets/3a6ba2f3-2b15-41ee-adee-a03e7daa7876)
After deleting all unnecessary parameters for our new rule and editing it, I wrote a sentence on lines 12 and 13 to explain what the new parameters do, as well as color-coded specific words to make it easier to relate to the edited rule.
<br><br>
The event type being New_Process or Existing_Process is highlighted in yellow, meaning this rule will detect LaZagne being run if it is a newly created process or an already existing process that is currently running.
<br><br>
"And must be windows" meaning the operating system must be windows for the detection to work.
<br><br>
"ignore case sensitivity" meaning this rule will detect LaZagne.exe wether the characters are capital letters or not.
<br><br>
"file_path must end with Lazagne.exe" meaning the rule will trigger an alert or response only if the detected file or process matches that specific executable name.
<br><br>

Ref 21: Adding on to detection rule:
![Num 26](https://github.com/user-attachments/assets/9d747796-6b49-4c83-9285-113c50357012)
I want to add LaZagne's file hash to the detection rule. To do this, I'll head over to the timeline sensor and search for the log entry from when I ran LaZagne.exe in Reference 17.
<br><br>
![Num 27](https://github.com/user-attachments/assets/e58dbb13-c04b-4dfb-ab30-41d10b289818)
Now, to build on the rule I was already creating, everything from line 13 onward includes all the new parameters added.
<br><br>
Line 33 mentions "OR Command_Line ends with all", this means if the "all" option is used in the command just like in ref 17 it'll also detect it.
<br><br>
"command_line contains Lazagne" means it will detect if the command line, such as PowerShell, includes the word 'Lazagne.'
<br><br>
"OR hash == LaZagne hash" means I want to include LaZagne's file hash in the detection rule because if the LaZagne.exe file is renamed to something else, such as pasta.exe, this rule will still be able to detect that LaZagne is running, as a file's hash does not change when you rename the file.
<br><br>
Also as you can notice, there's a pattern occuring when a new set of rules are being added in the parameters. Everytime a new rule is added, it starts with the case sensitivity, then the operation, and so forth.




















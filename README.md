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

Ref 18-22: Creating detection rule:
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
As you can see, there’s a pattern occurring when a new set of rules is added to the parameters. Every time a new rule is added, it starts with case sensitivity, followed by the operation, and so on.
<br><br>

Ref 22: Editing Respond rule:
![Num 28](https://github.com/user-attachments/assets/30536007-9104-485c-805d-7a8f11b0ed20)
Now that we have completed our detection rule, I want to create a response action that generates a report detailing the author— the person who created this detection rule— along with a description, severity levels, and the type of malicious executable, which in this case is credential access.
<br> <br>
To do this, I followed along and edited the previous response action to cater to my needs.
<br><br>

Ref 23-28: Testing New Rule:
![Num 29](https://github.com/user-attachments/assets/968746d5-c774-4f21-8c35-f3ddef014873)
One really cool thing about LimaCharlie is that you can test before allowing the rule to go into production. To do this, we'll head over to the Target event and copy and paste the log from the timeline (Ref 21).
<br><br>

Ref 24: 
![Num 30](https://github.com/user-attachments/assets/35d0439d-8c9a-4efd-884d-9441702450d4)
As you can see, all I did was pasted the timeline log from Ref 21, and now I'll test the rule by selecting Test Event at the bottom. 
<br><br>

Ref 25: Result:
![Num 31](https://github.com/user-attachments/assets/609b96e8-a575-4621-8872-f49dd54fcbfc)
As you can see, this rule is successful, and there was a match for the log that was sent. 
<br><br>

Ref 26: Seeing if rule works in production:
![Num 32](https://github.com/user-attachments/assets/e4ec24ab-943e-4b1b-b6b5-d0b2d430ec8f)
As you can see on the sensor's tab, no detections have been notified yet.
<br><br>

Ref 27: 
![Num 33](https://github.com/user-attachments/assets/99196f0b-634e-493e-b893-799b8c3a8730)
Running LaZange on powershell to see if detection will be notified.
<br><br>

Ref 28:
![Num 34](https://github.com/user-attachments/assets/f9fab2db-48e7-45fd-9066-37d7633249a7)
As you can see, after running LaZagne on the target machine, I received notifications of detections. By clicking on one of them, you can view various details due to the parameters set during the rule's creation. We can see the command line, hash, and the parent process, which shows that 'LaZagne.exe all' was run on powershell.exe, highlighted in green.
<br><br>
![Num 35](https://github.com/user-attachments/assets/0f0abc7b-ffb0-4909-a0c1-63d1181f0fd0)
Scrolling down, we can see more information, such as the author who created the detection rule, which is MarcP, the description, and the type of attack, which was credential access, underlined in red.
<br><br>

Ref 29-34: SOAR implementation via Tines:
![Num 36](https://github.com/user-attachments/assets/d614f4b8-3014-4760-96e3-32c8659ffa66)
Now, to implement SOAR capabilities, we are going to utilize Tines. Heading over to Tines, the first thing we're going to do is implement a webhook. After dragging the webhook into the middle, I gave it a name and description, and now I'll copy the webhook URL. 
<br><br>
A webhook in Tines is a way to receive real-time data from external sources. It acts as a listener that waits for specific events or triggers from other applications or services.
<br><br>

Ref 30:
![Num 37](https://github.com/user-attachments/assets/1c627fe0-b77c-4542-b335-08debf63a973)
Now heading back to LimaCharlie, on the left hand side, I will select outputs, which allows me to integrate data from LimaCharlie into other cloud tools.
<br><br>

Ref 31: Choosing output stream:
![Num 38](https://github.com/user-attachments/assets/d5525d55-068d-432a-ad26-b1f307d7bb80)
Now it'll ask me to choose an output stream. Since we created a detection rule earlier, I'll select detections as my output stream.
<br><br>

Ref 32: Choosing output destination:
![Num 39](https://github.com/user-attachments/assets/5f463117-b255-456c-bb11-3b85299d9263)
Next, we need to choose an output destination for our alerts. As you can see, there are many places to send our alerts, but we are interested in outputting them directly to Tines.
<br><br>

Ref 33: Pasting destination host:
![Num 40](https://github.com/user-attachments/assets/f693e540-39ff-4bb9-871a-da6fd88f765e)
The last thing we need to do is to paste our destination host. We do this by copying the webhook URL form Tines and pasting that into the destination host.
<br><br>

Ref 34: Testing webhook implementation:
![Num 41](https://github.com/user-attachments/assets/8b07f03d-2aa0-45e4-a827-d8a7b5e118d7)
Now, by re-running the command again on PowerShell, it should generate another detection, which will be forwarded to Tines. After selecting Test, you can see that the alert was successfully integrated into Tines from LimaCharlie. We see the exact same information just like in Ref 28.
<br><br>

Ref 35: Creating Alert Slack Channel for SOC team:
![Num 43](https://github.com/user-attachments/assets/ba9f09ad-874d-4a59-bac7-3b981755eb0e)
This Slack channel is for the SOC team to receive alert notifications if they are away from the keyboard (AFK) or for documentation purposes. The automated alert message enables them to quickly investigate any detected malicious threats on the endpoint and take prompt action if necessary.
<br><br>

Ref 36: Adding Slack in Tines:
![Num 44](https://github.com/user-attachments/assets/9b5ca6db-02cc-4239-9132-6f96ee2ee3ce)
I am integrating Slack in Tines to ensure that information from the webhook, which contains all the alert details, is sent directly to the Slack alert channel. This setup will allow the SOC team to receive real-time updates on alerts and streamline the incident response process.
<br><br>

Ref 37: Connecting Slack to Tines:
<br>
![Num 45](https://github.com/user-attachments/assets/7ab1051e-085d-4737-b956-bca715e8ed5e)
<br>
To properly connect the Slack channel to Tines, I have to copy and paste the Channel/ User ID from the channel and paste it into field in Tines as you'll see in the following image.
<br> <br>
![Num 46](https://github.com/user-attachments/assets/a02fee01-bc88-43f9-99fe-d4ec1588a57e)
<br>
As you can see I pasted the Channel/ User ID into Tines, as well as added a test message to be sent to the slack channel to see if it worked.
<br><br>
![Num 47](https://github.com/user-attachments/assets/748995ee-c7c4-4aad-b519-4c0279673675)
<br>
Next step is to authenticate with our slack credentials from Tines by pressing connect.
<br><br>
![Num 48](https://github.com/user-attachments/assets/524a927e-9a57-47af-81ce-a34d7297ed86)
<br>
And now all that's left to do is to physically connect the webhook to slack as you can see by that line, and select test.
<br><br>
![Num 49](https://github.com/user-attachments/assets/1f6d5afa-434a-4482-8713-3a46d597d796)
As you can see, it worked successfully—Tines was able to send a message to the Slack channel! I made some changes to the message sent due to a bit of troubleshooting I had to do.
<br><br>

Ref 38: Connecting Gmail to Tines:
![Num 50](https://github.com/user-attachments/assets/422706be-1c2e-4876-a0a5-747233988b95)
To connect Gmail to Tines, I followed some of the same steps as when integrating Slack. I provided the Tines fields with the recipient email address, set the sender name as 'Alerts', used 'Let's see' as the subject, and kept the body as the default message that Tines provides.
<br><br>
![Num 51](https://github.com/user-attachments/assets/6bc3b740-ad4a-4bf1-8bee-b9b6b4bfa3e2)
After selecting 'Test,' an email message was successfully sent to my inbox, as you can see. The purpose of this setup is to provide flexibility with alert notifications. If the SOC analyst doesn't see or receive the Slack message, they will still be notified via email. This serves as a form of redundancy in case Slack goes down or, conversely, if Gmail stops working for any reason.
<br><br>

Ref 39: Adding User Prompt:
![Num 52](https://github.com/user-attachments/assets/216e0ed1-61da-49c7-9d6e-962632baab55)
Next up is the User Prompt. The purpose of this prompt is to ask the SOC analysts (the users) whether they want to isolate the machine (Yes/No). After selecting an option, the user prompt will generate a message saying, 'Thank you for your response.'
<br><br>
![Num 53](https://github.com/user-attachments/assets/6e9502ec-fa59-496e-a486-9c32be51cd93)
By double-clicking into the User Prompt, Tines allows you to customize the prompt's appearance using elements on the left side. I kept it simple, and this is how the user prompt will appear to the user.
<br><br>






























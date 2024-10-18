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









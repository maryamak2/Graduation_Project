Secure Healthcare Access and Monitoring System Based on Zero Trust Architecture
This project presents a secure hospital web platform built using Zero Trust Architecture (ZTA) to protect sensitive medical data and services. As cyber threats become more advanced, older security methods that rely on protecting the outer network are no longer enough. ZTA follows a "Never Trust, Always Verify" approach by checking each user’s identity, device security, and access context before allowing entry. The platform is designed for doctors, nurses, and patients, with security integrated at every level. It uses Multi-Factor Authentication (MFA) and JSON Web Tokens (JWT) to ensure only the right users can access specific parts of the system. JWTs securely carry user information like roles and expiry times in a verified and tamper-proof way. All communication is encrypted to maintain data privacy and integrity. Role-based access control (RBAC) ensures that each user only sees what they are permitted to. The system also includes segmentation of services by tailscale and dynamic access enforcement based on behavioral signals. The platform is hosted on a secure cloud environment to support scalability and availability. To monitor activity, the platform uses the ELK stack—Elasticsearch, Logstash, and Kibana—which collects and analyzes logs in real time. These logs track logins, API usage, role-based actions, and unusual access to private data, helping detect suspicious behavior while staying compliant with data privacy regulations.

Installation
1.	Install Elasticsearch, Kibana, and Logstash.
2.	Replace each of: elasticsearch.yml, kibana.yml, and logstash.conf by the attached modified versions of them.
3.	Run Logstash: .\bin\logstash.bat -f .\config\logstash.conf
4.	In our project we used Tailscale for encrypted communication between Servers. If you want to do so setup Tailscale on your devices with minimum of 3 devices to achieve microsegmentation concept.
5.	Run Policy engine on same server the ELK stack running on which has IP 100.69.247.53 (replace this IP in the code by the IP of your server in your case).
6.	Run main.py by entering:” uvicorn main:app --host 0.0.0.0 --port 8000” on another server which has IP 100.89.45.27 while this server having backend codes (replace this IP in the code by the IP of your server in your case).
7.	MySQL database should be ready with the data of your system.
8.	Run all Front-end files on IP 100.85.90.51, for this step it can be done using hosting but this is the temporary alternative for hosting.
9.	If you don’t want to run the files on 3 devices you can simply change all IP’s to localhost (127.0.0.1).

•	Server 1: 
  -ELK and Policy Engine
  -Files: Policy_Engine.py

•	Server 2: 
  -Backend
  -Files: Identity_Management.py, Session_Management.py, dbtestmysql.py, modelsmysql.py, Patient_record_Server.py, main.py

•	Server 3: 
  -Frontend
  -Files: all .html and .css files.

•	All requirements are attached in requirements.txt.
•	Further explanation 


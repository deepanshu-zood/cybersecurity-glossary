const glossaryData = [
  {
    term: "Access Control",
    definition: "A method used to allow or deny access to resources in a computer system or network.",
    example: " Only employees with admin roles can access financial records due to access control policies.",
    difficulty: "beginner"
  },
  {
    term: "Account Hijacking",
    definition: "When someone gains unauthorized access to your online account and uses it maliciously.",
    example: " A hacker used leaked credentials to hijack a user's email account and send spam.",
    difficulty: "advanced"
  },
  {
    term: "Adware",
    definition: "Software that displays unwanted ads on your device, often bundled with free applications.",
    example: " After installing a free game, the user noticed pop-up ads caused by hidden adware.",
    difficulty: "intermediate"
  },
  {
    term: "Advanced Persistent Threat (APT)",
    definition: "A targeted, prolonged cyberattack where hackers remain undetected in a system to steal data.",
    example: " APT attacks are commonly used by state-sponsored groups to spy on government networks.",
    difficulty: "advanced"
  },
  {
    term: "Antivirus",
    definition: "Software designed to detect and remove malicious software like viruses and worms.",
    example: " The antivirus detected and removed a trojan before it could harm the system.",
    difficulty: "beginner"
  },
  {
    term: "Authentication",
    definition: "The process of verifying someone’s identity before giving access to a system.",
    example: " Entering a password to unlock your email is a form of authentication.",
    difficulty: "beginner"
  },
  {
    term: "Authorization",
    definition: "The process of determining what resources a user is allowed to access after authentication.",
    example: " A manager can view salary details, but an intern cannot—this is authorization control.",
    difficulty: "intermediate"
  },
  {
    term: "Backup",
    definition: "A copy of data stored separately to restore in case of loss or corruption.",
    example: " The company performs weekly backups to avoid data loss during cyberattacks.",
    difficulty: "beginner"
  },
  {
    term: "Biometric Authentication",
    definition: "A security method that uses unique biological traits to verify identity.",
    example: " Unlocking your phone with a fingerprint is biometric authentication.",
    difficulty: "intermediate"
  },
  {
    term: "Black Hat",
    definition: "A hacker who uses their skills for illegal or malicious purposes.",
    example: " A black hat hacker broke into a retail website to steal customer credit card data.",
    difficulty: "intermediate"
  },
  {
    term: "Blockchain Security",
    definition: "Techniques used to protect blockchain systems from fraud, attacks, and breaches.",
    example: " Blockchain security ensures Bitcoin transactions can’t be tampered with.",
    difficulty: "advanced"
  },
  {
    term: "Blue Team",
    definition: "Cybersecurity professionals who defend systems from attacks in simulations or real threats.",
    example: " The blue team patched a firewall weakness found during the security drill.",
    difficulty: "intermediate"
  },
  {
    term: "Botnet",
    definition: "A network of infected computers controlled by a hacker to perform coordinated tasks.",
    example: " A hacker used a botnet to launch a DDoS attack that took down a website.",
    difficulty: "advanced"
  },
  {
    term: "Brute Force Attack",
    definition: "A hacking method that tries many passwords until the correct one is found.",
    example: " A brute force attack tried thousands of combinations to guess the admin password.",
    difficulty: "advanced"
  },
  {
    term: "Bug Bounty",
    definition: "A reward offered to ethical hackers who find and report security flaws.",
    example: " An ethical hacker earned $5,000 for discovering a login bypass bug in a bank app.",
    difficulty: "intermediate"
  },
  {
    term: "Asset Management",
    definition: "The process of identifying, tracking, and managing IT assets in an organization.",
    example: " A company keeps a record of all laptops and software licenses as part of asset management.",
    difficulty: "beginner"
  },
  {
    term: "Attack Vector",
    definition: "The method or path used by an attacker to gain unauthorized access to a system.",
    example: " A phishing email is a common attack vector to steal login credentials.",
    difficulty: "intermediate"
  },
  {
    term: "Attack Surface",
    definition: "The total number of points where an attacker can try to enter or extract data.",
    example: " Unpatched software and exposed APIs increase a company's attack surface.",
    difficulty: "intermediate"
  },
  {
    term: "Audit Trail",
    definition: "A record that shows who accessed a system and what operations were performed.",
    example: " An audit trail showed that a file was deleted by an unauthorized user at 3 AM.",
    difficulty: "intermediate"
  },
  {
    term: "Asymmetric Encryption",
    definition: "An encryption method using a public key to encrypt and a private key to decrypt.",
    example: " Emails are secured using asymmetric encryption like RSA to ensure privacy.",
    difficulty: "advanced"
  },
  {
    term: "Anomaly Detection",
    definition: "The process of identifying unusual patterns in data that could indicate a threat.",
    example: " A sudden spike in login attempts triggered anomaly detection alerts.",
    difficulty: "advanced"
  },
  {
    term: "Application Security",
    definition: "The practice of protecting applications from security threats during and after development.",
    example: " Developers used input validation to prevent injection attacks in a web app.",
    difficulty: "intermediate"
  },
  {
    term: "Anti-Spam",
    definition: "Tools or methods used to block unwanted or malicious email messages.",
    example: " Gmail's anti-spam filter automatically sent phishing emails to the spam folder.",
    difficulty: "beginner"
  },
  {
    term: "Anti-Malware",
    definition: "Software that detects, prevents, and removes malicious programs.",
    example: " The anti-malware tool stopped ransomware from encrypting important files.",
    difficulty: "beginner"
  },
  {
    term: "Application Whitelisting",
    definition: "A security practice that only allows pre-approved software to run on a system.",
    example: " Only approved business tools were allowed on company laptops through whitelisting.",
    difficulty: "intermediate"
  },
  {
    term: "Attribute-Based Access Control (ABAC)",
    definition: "A method of granting access based on user attributes like role, location, or time.",
    example: " An employee could only access sensitive files during business hours using ABAC.",
    difficulty: "advanced"
  },
  {
    term: "Auto-Update",
    definition: "A feature that automatically installs software updates to fix bugs and vulnerabilities.",
    example: " The browser auto-updated to patch a known zero-day exploit.",
    difficulty: "beginner"
  },
  {
    term: "Address Space Layout Randomization (ASLR)",
    definition: "A technique that randomly arranges memory addresses to make attacks harder.",
    example: " ASLR made it difficult for the attacker to predict where code was stored in memory.",
    difficulty: "advanced"
  },
  {
    term: "Business Continuity Plan (BCP)",
    definition: "A strategy to keep a business running during and after a cybersecurity incident.",
    example: " After a ransomware attack, the BCP helped employees continue work using backup systems.",
    difficulty: "intermediate"
  },
  {
    term: "Buffer Overflow",
    definition: "A vulnerability where too much data is sent to a buffer, causing unexpected behavior.",
    example: " A hacker exploited a buffer overflow to execute malicious code on a server.",
    difficulty: "advanced"
  },
  {
    term: "Browser Hijacking",
    definition: "When malicious software alters browser settings without user permission.",
    example: " The user's homepage was changed to a fake search engine by a browser hijacker.",
    difficulty: "intermediate"
  },
  {
    term: "Behavioral Analytics",
    definition: "The use of user behavior data to detect anomalies and potential threats.",
    example: " The system flagged unusual login times for a user, indicating suspicious activity.",
    difficulty: "advanced"
  },
  {
    term: "Backdoor",
    definition: "A secret method of bypassing normal authentication to gain access to a system.",
    example: " The malware created a backdoor that allowed hackers to control the system remotely.",
    difficulty: "advanced"
  },
  {
    term: "BYOD (Bring Your Own Device)",
    definition: "A policy that allows employees to use personal devices for work purposes.",
    example: " BYOD lets staff use their own phones for email but requires strict security policies.",
    difficulty: "intermediate"
  },
  {
    term: "BIOS Security",
    definition: "Measures used to protect a computer's BIOS from unauthorized changes.",
    example: " BIOS passwords were enabled to prevent boot-time tampering.",
    difficulty: "intermediate"
  },
  {
    term: "BitLocker",
    definition: "A Windows encryption feature that protects data on a disk.",
    example: " BitLocker was used to encrypt all laptops at the company in case of theft.",
    difficulty: "beginner"
  },
  {
    term: "BGP Hijacking",
    definition: "An attack where malicious routing announcements divert internet traffic.",
    example: " A BGP hijack rerouted users to a fake banking site without their knowledge.",
    difficulty: "advanced"
  },
  {
    term: "Certificate Authority",
    definition: "An entity that issues digital certificates to verify identities on the internet.",
    example: " A certificate authority verified the identity of the e-commerce site before issuing an SSL certificate.",
    difficulty: "intermediate"
  },
  {
    term: "CIA Triad",
    definition: "A security model consisting of Confidentiality, Integrity, and Availability.",
    example: " The bank’s security team follows the CIA triad to ensure secure transactions.",
    difficulty: "beginner"
  },
  {
    term: "Clickjacking",
    definition: "A technique where users are tricked into clicking something different from what they perceive.",
    example: " A button on a fake webpage redirected users to a malware download—classic clickjacking.",
    difficulty: "advanced"
  },
  {
    term: "Cloud Security",
    definition: "Techniques and practices for protecting cloud-based infrastructure and data.",
    example: " The company used encryption and firewalls to enhance their cloud security setup.",
    difficulty: "intermediate"
  },
  {
    term: "Command and Control (C2)",
    definition: "A method attackers use to maintain communications with compromised systems.",
    example: " The botnet received instructions from a hidden command and control server.",
    difficulty: "advanced"
  },
  {
    term: "Cross-Site Scripting (XSS)",
    definition: "A vulnerability that allows attackers to inject malicious scripts into web pages.",
    example: " A user’s browser was hijacked via a comment field due to XSS.",
    difficulty: "advanced"
  },
  {
    term: "Cryptography",
    definition: "The science of encrypting and decrypting information to keep it secure.",
    example: " Messages between users were protected with modern cryptography like AES.",
    difficulty: "intermediate"
  },
  {
    term: "Cyber Espionage",
    definition: "The act of spying or obtaining confidential data through cyber means.",
    example: " Hackers launched a cyber espionage campaign to steal defense documents.",
    difficulty: "advanced"
  },
  {
    term: "Cyber Hygiene",
    definition: "Basic practices and steps users take to maintain good security habits.",
    example: " Regularly updating software and using strong passwords are parts of cyber hygiene.",
    difficulty: "beginner"
  },
  {
    term: "Cyber Threat Intelligence",
    definition: "Information about potential or current cyber threats collected and analyzed to reduce risks.",
    example: " The company used cyber threat intelligence to prepare for an upcoming phishing campaign.",
    difficulty: "advanced"
  },
  {
    term: "Cybercrime",
    definition: "Any criminal activity carried out using computers or the internet.",
    example: " Stealing credit card data through a hacked website is an example of cybercrime.",
    difficulty: "beginner"
  },
  {
    term: "Cyberwarfare",
    definition: "Nation-state level attacks aimed at disrupting or damaging other countries' systems.",
    example: " A military network was disabled in a suspected act of cyberwarfare.",
    difficulty: "advanced"
  },

 {
    term: "Dark Web",
    definition: "A hidden part of the internet not indexed by search engines, often used for illegal activity.",
    example: " Stolen credit card data was found being sold on the dark web.",
    difficulty: "intermediate"
  },
  {
    term: "Data Breach",
    definition: "An incident where confidential information is accessed or exposed without authorization.",
    example: " A data breach at a social media company exposed millions of user passwords.",
    difficulty: "beginner"
  },
  {
    term: "Data Encryption",
    definition: "The process of converting data into a secret code to protect it from unauthorized access.",
    example: " All emails were encrypted to prevent interception during transmission.",
    difficulty: "beginner"
  },
  {
    term: "Data Exfiltration",
    definition: "The unauthorized transfer of data from a computer or network.",
    example: " Malware silently exfiltrated files from the employee’s laptop to a remote server.",
    difficulty: "advanced"
  },
  {
    term: "Data Integrity",
    definition: "The accuracy and consistency of data over its lifecycle.",
    example: " Checksums are used to ensure data integrity during file transfers.",
    difficulty: "intermediate"
  },
  {
    term: "DDoS Attack",
    definition: "A type of cyberattack where servers are overwhelmed with traffic to make them unavailable.",
    example: " The gaming website went offline after a massive DDoS attack from thousands of IPs.",
    difficulty: "intermediate"
  },
  {
    term: "Deepfake",
    definition: "AI-generated fake media (video, audio) made to look real, often used for misinformation.",
    example: " A deepfake video of a politician spread misinformation before an election.",
    difficulty: "advanced"
  },
  {
    term: "Decryption",
    definition: "The process of converting encrypted data back into its original form.",
    example: " The system used a private key to decrypt the secured communication.",
    difficulty: "beginner"
  },
  {
    term: "Digital Certificate",
    definition: "An electronic document that proves ownership of a public key.",
    example: " A website used a digital certificate to establish a secure HTTPS connection.",
    difficulty: "intermediate"
  },
  {
    term: "Digital Forensics",
    definition: "The practice of investigating cybercrimes by analyzing digital devices and data.",
    example: " Digital forensics experts recovered deleted messages as evidence in a hacking case.",
    difficulty: "advanced"
  },
  {
    term: "Digital Signature",
    definition: "A mathematical method used to verify the authenticity of digital messages or documents.",
    example: " The contract was signed using a digital signature to ensure it hadn’t been tampered with.",
    difficulty: "intermediate"
  },
  {
    term: "DMARC",
    definition: "A protocol that protects email domains from spoofing by verifying the sender.",
    example: " DMARC helped prevent phishing emails pretending to be from the company’s domain.",
    difficulty: "advanced"
  },
  {
    term: "DNS Spoofing",
    definition: "An attack where fake DNS data is used to redirect users to malicious websites.",
    example: " A user trying to access their bank’s website was redirected to a fake page via DNS spoofing.",
    difficulty: "advanced"
  },
  {
    term: "Drive-by Download",
    definition: "Malware downloaded to a user’s device without their consent when visiting a malicious website.",
    example: " Just visiting a compromised site triggered a drive-by download that installed spyware.",
    difficulty: "intermediate"
  },
{
    term: "Eavesdropping",
    definition: "Intercepting private communication or data transmission without permission.",
    example: " Hackers performed eavesdropping by tapping into unsecured Wi-Fi to read messages.",
    difficulty: "intermediate"
  },
  {
    term: "Email Spoofing",
    definition: "Forging the sender's address to make an email appear as if it's from someone trustworthy.",
    example: " The scammer used email spoofing to impersonate a bank and trick users.",
    difficulty: "intermediate"
  },
  {
    term: "Endpoint Detection and Response (EDR)",
    definition: "Security tools that monitor and respond to threats on devices like laptops or phones.",
    example: " The company’s EDR system detected malware on a remote worker’s laptop.",
    difficulty: "advanced"
  },
  {
    term: "Encryption",
    definition: "Converting readable data into unreadable code to protect it from unauthorized access.",
    example: " Messaging apps use encryption so only the sender and receiver can read the messages.",
    difficulty: "beginner"
  },
  {
    term: "Ethical Hacking",
    definition: "Hacking done legally to find and fix security vulnerabilities before criminals can exploit them.",
    example: " An ethical hacker found a serious flaw in a bank's app during a penetration test.",
    difficulty: "intermediate"
  },
  {
    term: "Exploit",
    definition: "A piece of code or technique that takes advantage of a vulnerability in software.",
    example: " The hacker used an exploit to gain admin access to the server.",
    difficulty: "advanced"
  },
   {
    term: "Firewall",
    definition: "A system designed to block unauthorized access while allowing safe traffic through.",
    example: " The office network was protected by a firewall that blocked suspicious connections.",
    difficulty: "beginner"
  },
  {
    term: "Firmware",
    definition: "Low-level software permanently programmed into hardware devices to control their functions.",
    example: " The router’s firmware was updated to patch a security vulnerability.",
    difficulty: "intermediate"
  },
  {
    term: "Forensics",
    definition: "The process of collecting and analyzing digital evidence after a security incident.",
    example: " Cyber forensics experts traced the data breach to a compromised laptop.",
    difficulty: "advanced"
  },
  {
    term: "Grey Hat",
    definition: "A hacker who may violate laws or ethics but doesn't have malicious intent.",
    example: " A grey hat hacker found a flaw in a website and reported it without permission.",
    difficulty: "intermediate"
  },
  {
    term: "Governance",
    definition: "The overall management approach through which an organization manages its cybersecurity strategy.",
    example: " The IT team created a cybersecurity governance policy for all departments.",
    difficulty: "intermediate"
  },
  {
    term: "Gateway",
    definition: "A network point that acts as an entrance to another network and often enforces security rules.",
    example: " The secure gateway scanned all incoming files for malware.",
    difficulty: "beginner"
  },
  {
    term: "Group Policy",
    definition: "A Windows feature used to control the working environment of user accounts and devices.",
    example: " IT admins used Group Policy to prevent users from installing unauthorized apps.",
    difficulty: "intermediate"
  },
    {
    term: "Hashing",
    definition: "A process that converts data into a fixed-length string, often used to store passwords securely.",
    example: " User passwords were hashed before being stored in the database.",
    difficulty: "intermediate"
  },
  {
    term: "Honeypot",
    definition: "A security mechanism set up to attract attackers and study their methods.",
    example: " The cybersecurity team used a honeypot server to observe real hacking attempts.",
    difficulty: "advanced"
  },
  {
    term: "Hacktivism",
    definition: "Hacking carried out as a form of political or social protest.",
    example: " A hacktivist group defaced a government website to support a human rights campaign.",
    difficulty: "advanced"
  },
  {
    term: "Hardware Security Module (HSM)",
    definition: "A physical device used to manage and store encryption keys securely.",
    example: " Banks use HSMs to protect sensitive cryptographic keys and transactions.",
    difficulty: "advanced"
  },
  {
    term: "Identity Theft",
    definition: "A crime where someone uses another person's personal data to commit fraud.",
    example: " The hacker used stolen credentials to open a credit card in the victim’s name.",
    difficulty: "beginner"
  },
  {
    term: "Incident Response",
    definition: "The process of detecting, responding to, and recovering from a cybersecurity incident.",
    example: " The security team activated their incident response plan after detecting a breach.",
    difficulty: "intermediate"
  },
  {
    term: "Information Assurance",
    definition: "The practice of managing risks related to the use, processing, and storage of information.",
    example: " A company performed risk assessments as part of their information assurance efforts.",
    difficulty: "advanced"
  },
  {
    term: "Information Security",
    definition: "The protection of information systems against unauthorized access or modification.",
    example: " Data encryption and access control are key parts of information security.",
    difficulty: "beginner"
  },
  {
    term: "Insider Threat",
    definition: "A security risk that originates from people within the organization.",
    example: " A disgruntled employee leaked sensitive files, making it an insider threat case.",
    difficulty: "advanced"
  },
  {
    term: "Integrity",
    definition: "The assurance that data is accurate and has not been tampered with.",
    example: " File checksums were used to maintain the integrity of transferred documents.",
    difficulty: "beginner"
  },
  {
    term: "Intrusion Detection System (IDS)",
    definition: "Software or hardware that monitors network traffic for suspicious activity.",
    example: " The IDS alerted admins about unusual traffic from an internal device.",
    difficulty: "intermediate"
  },
  {
    term: "Intrusion Prevention System (IPS)",
    definition: "A system that not only detects threats but actively blocks them in real time.",
    example: " The IPS blocked a known malware signature before it reached user systems.",
    difficulty: "advanced"
  },
  {
    term: "IP Spoofing",
    definition: "A technique where attackers disguise their IP address to appear legitimate.",
    example: " The attacker used IP spoofing to mimic a trusted server and bypass security.",
    difficulty: "advanced"
  },
   {
    term: "Jailbreaking",
    definition: "The process of removing restrictions from a device to gain full control over it.",
    example: " Jailbreaking an iPhone lets users install apps outside the App Store, but weakens security.",
    difficulty: "intermediate"
  },
  {
    term: "JavaScript Injection",
    definition: "A type of attack where malicious JavaScript code is injected into a webpage.",
    example: " The attacker used JavaScript injection to steal user data from the login page.",
    difficulty: "advanced"
  },
  {
    term: "Keylogger",
    definition: "A tool or malware that records a user’s keystrokes to steal sensitive information.",
    example: " A keylogger captured the victim’s passwords as they typed them.",
    difficulty: "intermediate"
  },
  {
    term: "Kill Chain",
    definition: "A model that outlines the steps cyber attackers take to compromise a system.",
    example: " Security teams analyzed the kill chain to stop the ransomware before execution.",
    difficulty: "advanced"
  },
{
    term: "Logic Bomb",
    definition: "Malicious code triggered by specific conditions, like a certain date or user action.",
    example: " A logic bomb was programmed to delete files if the employee was terminated.",
    difficulty: "advanced"
  },
  {
    term: "Log Management",
    definition: "The process of collecting, storing, and analyzing system logs for security insights.",
    example: " Log management tools helped detect suspicious login attempts at night.",
    difficulty: "intermediate"
  },
  {
    term: "MAC Filtering",
    definition: "A security method that allows or blocks network access based on device MAC addresses.",
    example: " Only authorized laptops could connect to the office Wi-Fi using MAC filtering.",
    difficulty: "intermediate"
  },
  {
    term: "Malware",
    definition: "Any software designed to harm, exploit, or steal information from systems.",
    example: " The malware locked the files and demanded a ransom for decryption.",
    difficulty: "beginner"
  },
  {
    term: "Man-in-the-Middle Attack (MitM)",
    definition: "An attack where a third party secretly intercepts and possibly alters communication.",
    example: " During public Wi-Fi use, a hacker launched a MitM attack to steal login data.",
    difficulty: "advanced"
  },
  {
    term: "Mobile Security",
    definition: "Protecting smartphones and tablets from threats like malware, theft, and phishing.",
    example: " Mobile security apps blocked an SMS phishing attempt on the CEO’s phone.",
    difficulty: "intermediate"
  },
  {
    term: "Multi-Factor Authentication (MFA)",
    definition: "A login method requiring two or more proofs of identity, like password + OTP.",
    example: " Logging in required both a password and a code sent via SMS thanks to MFA.",
    difficulty: "beginner"
  },
   {
    term: "Network Security",
    definition: "Practices and technologies used to protect a network from intrusions and attacks.",
    example: " Firewalls and intrusion detection systems were used to ensure strong network security.",
    difficulty: "beginner"
  },
  {
    term: "Nonce",
    definition: "A random number used only once in cryptographic communication to prevent replay attacks.",
    example: " The system used a nonce during login to verify the request’s freshness.",
    difficulty: "advanced"
  },
  {
    term: "Nmap",
    definition: "A powerful tool used for scanning and mapping computer networks.",
    example: " Security professionals used Nmap to find open ports on the web server.",
    difficulty: "intermediate"
  },
  {
    term: "Network Segmentation",
    definition: "Dividing a network into smaller parts to improve performance and security.",
    example: " Sensitive data servers were placed in a separate segment to limit access.",
    difficulty: "intermediate"
  },
  {
    term: "NAT (Network Address Translation)",
    definition: "A method to translate private IP addresses to a public one for internet access.",
    example: " NAT enabled multiple devices to share one public IP without exposing them.",
    difficulty: "intermediate"
  },
  {
    term: "OAuth",
    definition: "An open standard for token-based authorization that allows apps to access user data without sharing passwords.",
    example: " The app used OAuth to let users log in with their Google account safely.",
    difficulty: "intermediate"
  },
  {
    term: "Open Source Intelligence (OSINT)",
    definition: "Collecting information from publicly available sources for cybersecurity or investigative purposes.",
    example: " The analyst used OSINT to gather threat data from forums and social media.",
    difficulty: "advanced"
  },
  {
    term: "Obfuscation",
    definition: "A technique used to make code or data harder to understand or analyze.",
    example: " The malware code was heavily obfuscated to avoid detection by antivirus tools.",
    difficulty: "advanced"
  },
  {
    term: "Operating System Hardening",
    definition: "The process of securing an OS by reducing its vulnerabilities.",
    example: " The server was hardened by disabling unused ports and removing unnecessary software.",
    difficulty: "intermediate"
  },
  {
    term: "Packet Sniffing",
    definition: "Capturing data packets moving across a network to analyze or intercept information.",
    example: " Hackers used packet sniffing tools to steal login credentials from open Wi-Fi.",
    difficulty: "advanced"
  },
  {
    term: "Patch Management",
    definition: "The process of regularly updating software to fix vulnerabilities and bugs.",
    example: " IT teams implemented patch management to prevent known exploits from being used.",
    difficulty: "intermediate"
  },
  {
    term: "Penetration Testing",
    definition: "A simulated cyberattack used to identify and fix security vulnerabilities.",
    example: " The company hired ethical hackers for a full penetration test before launch.",
    difficulty: "intermediate"
  },
  {
    term: "Phishing",
    definition: "A method of tricking people into revealing sensitive information through fake communication.",
    example: " A phishing email claimed to be from a bank asking for login details.",
    difficulty: "beginner"
  },
  {
    term: "Polymorphic Malware",
    definition: "Malware that changes its code to avoid detection by antivirus programs.",
    example: " Polymorphic malware infected the system and mutated to bypass security tools.",
    difficulty: "advanced"
  },
  {
    term: "Privileged Access Management (PAM)",
    definition: "Controls and monitors access to critical systems by users with elevated privileges.",
    example: " PAM restricted administrator access and recorded all changes made to system settings.",
    difficulty: "advanced"
  },
  {
    term: "Proxy Server",
    definition: "A server that acts as an intermediary between a user and the internet for privacy and control.",
    example: " Students accessed blocked websites through a proxy server at school.",
    difficulty: "beginner"
  },
  {
    term: "Public Key Infrastructure (PKI)",
    definition: "A system of digital certificates and encryption to secure online communications.",
    example: " PKI was used to issue SSL certificates for secure website connections.",
    difficulty: "advanced"
  },
   {
    term: "Quantum Cryptography",
    definition: "A method of encryption that uses the principles of quantum mechanics for extreme security.",
    example: " Researchers used quantum cryptography to send messages that were impossible to intercept undetected.",
    difficulty: "advanced"
  },
  {
    term: "Quarantine",
    definition: "The isolation of potentially harmful files or programs to prevent system damage.",
    example: " The antivirus quarantined a suspicious file before it could run on the system.",
    difficulty: "beginner"
  },
  {
    term: "Ransomware",
    definition: "Malware that locks or encrypts data until a ransom is paid to the attacker.",
    example: " Ransomware locked all hospital files and demanded payment in cryptocurrency.",
    difficulty: "beginner"
  },
  {
    term: "Red Team",
    definition: "A group of ethical hackers that simulate real-world attacks to test defenses.",
    example: " The red team tested the company’s incident response by simulating a data breach.",
    difficulty: "advanced"
  },
  {
    term: "Risk Assessment",
    definition: "The process of identifying and evaluating potential threats to an organization.",
    example: " The IT department conducted a risk assessment before launching the new web portal.",
    difficulty: "intermediate"
  },
  {
    term: "Rootkit",
    definition: "Malware designed to give unauthorized users root or administrative access to a system.",
    example: " A rootkit hid deep in the system, allowing hackers to control the device remotely.",
    difficulty: "advanced"
  },
  {
    term: "Role-Based Access Control (RBAC)",
    definition: "A method of restricting access based on a user’s role within an organization.",
    example: " Only managers could view salary data due to RBAC rules.",
    difficulty: "intermediate"
  },
  {
    term: "Sandbox",
    definition: "An isolated environment used to safely test or run untrusted code or files.",
    example: " The malware sample was opened in a sandbox to observe its behavior without risking the main system.",
    difficulty: "intermediate"
  },
  {
    term: "Security Patch",
    definition: "A software update that fixes known security vulnerabilities.",
    example: " A security patch was released to close a loophole in the email application.",
    difficulty: "beginner"
  },
  {
    term: "Shoulder Surfing",
    definition: "The act of spying on someone’s screen or keyboard to obtain private information.",
    example: " A thief watched over someone’s shoulder to steal their ATM PIN at a cash machine.",
    difficulty: "beginner"
  },
  {
    term: "Social Engineering",
    definition: "Manipulating people into giving up confidential information or access.",
    example: " A scammer used social engineering to trick an employee into revealing their login credentials.",
    difficulty: "intermediate"
  },
  {
    term: "Software Vulnerability",
    definition: "A flaw or weakness in software that can be exploited by attackers.",
    example: " Hackers exploited a software vulnerability to gain admin access.",
    difficulty: "beginner"
  },
  {
    term: "Spam",
    definition: "Unwanted or unsolicited digital communication, often sent in bulk.",
    example: " The user's inbox was flooded with spam emails advertising fake products.",
    difficulty: "beginner"
  },
  {
    term: "Spoofing",
    definition: "Faking an identity, such as an IP address or email, to deceive a system or user.",
    example: " The attacker used email spoofing to impersonate the CEO and request a wire transfer.",
    difficulty: "intermediate"
  },
  {
    term: "Spyware",
    definition: "Malware that secretly monitors a user's activities and sends the data to a third party.",
    example: " The spyware tracked the user’s browsing history and reported it to advertisers.",
    difficulty: "beginner"
  },
  {
    term: "SQL Injection",
    definition: "A code injection technique that manipulates a database through malicious input.",
    example: " Hackers used SQL injection to access sensitive customer data from the database.",
    difficulty: "advanced"
  },
  {
    term: "Supply Chain Attack",
    definition: "An attack that targets the less-secure elements in a system’s supply chain.",
    example: " A compromised software update from a vendor led to a widespread supply chain attack.",
    difficulty: "advanced"
  },
  {
    term: "Symmetric Encryption",
    definition: "A type of encryption where the same key is used for both encryption and decryption.",
    example: " The file was secured using symmetric encryption with a shared secret key.",
    difficulty: "intermediate"
  },
   {
    term: "Threat Actor",
    definition: "An individual or group responsible for carrying out a cyberattack.",
    example: " The ransomware attack was traced back to a known threat actor group.",
    difficulty: "intermediate"
  },
  {
    term: "Threat Hunting",
    definition: "The proactive search for cyber threats that may be hiding in a network.",
    example: " The security team began threat hunting after noticing unusual login times.",
    difficulty: "advanced"
  },
  {
    term: "Tokenization",
    definition: "Replacing sensitive data with unique identification symbols (tokens) for protection.",
    example: " Credit card details were tokenized so the system never stored real numbers.",
    difficulty: "intermediate"
  },
  {
    term: "Trojan Horse",
    definition: "Malware disguised as a legitimate program to trick users into installing it.",
    example: " The game installer turned out to be a Trojan that stole passwords.",
    difficulty: "beginner"
  },
  {
    term: "Two-Factor Authentication (2FA)",
    definition: "A security method requiring two forms of verification to access an account.",
    example: " After entering her password, Lisa used a phone code as the second step in 2FA.",
    difficulty: "beginner"
  },
  {
    term: "Traffic Analysis",
    definition: "Studying communication patterns in a network to gather information or detect anomalies.",
    example: " The analyst noticed a large spike in outbound data through traffic analysis.",
    difficulty: "advanced"
  },
  {
    term: "TLS (Transport Layer Security)",
    definition: "A cryptographic protocol used to secure communications over the internet.",
    example: " TLS ensures that data sent between a browser and a server is encrypted and safe.",
    difficulty: "intermediate"
  },
  {
    term: "Typosquatting",
    definition: "Registering domain names similar to real ones to trick users who mistype URLs.",
    example: " A fake site used typosquatting to imitate 'amaz0n.com' and steal credentials.",
    difficulty: "advanced"
  },
  {
    term: "Unauthorized Access",
    definition: "When someone gains access to a system, network, or data without permission.",
    example: " A former employee used an old password to gain unauthorized access to company files.",
    difficulty: "beginner"
  },
  {
    term: "URL Filtering",
    definition: "Blocking access to specific websites or URLs based on content or threat level.",
    example: " The school used URL filtering to block access to gaming and adult sites.",
    difficulty: "intermediate"
  },
  {
    term: "User Awareness Training",
    definition: "Educating users about cybersecurity best practices to prevent human error.",
    example: " The company held user awareness training to teach employees how to spot phishing emails.",
    difficulty: "beginner"
  },
  {
    term: "Virtual Private Network (VPN)",
    definition: "A secure connection that encrypts internet traffic between a device and the network.",
    example: " She used a VPN to safely access work files over public Wi-Fi.",
    difficulty: "beginner"
  },
  {
    term: "Virus",
    definition: "A type of malware that replicates and spreads to other programs or files.",
    example: " The virus spread through email attachments and corrupted multiple systems.",
    difficulty: "beginner"
  },
  {
    term: "Vishing",
    definition: "A type of phishing attack carried out over phone calls or voice messages.",
    example: " A scammer pretended to be from tech support in a vishing attack.",
    difficulty: "intermediate"
  },
  {
    term: "Vulnerability",
    definition: "A weakness in a system that could be exploited by an attacker.",
    example: " The outdated software had a vulnerability that allowed remote code execution.",
    difficulty: "beginner"
  },
   {
    term: "Watering Hole Attack",
    definition: "A cyberattack that targets websites frequently visited by a specific group to infect them.",
    example: " Hackers compromised a research website in a watering hole attack to target scientists.",
    difficulty: "advanced"
  },
  {
    term: "Whaling",
    definition: "A phishing attack that targets high-profile individuals like executives or CEOs.",
    example: " The CEO received a fake invoice email in a whaling attempt.",
    difficulty: "advanced"
  },
  {
    term: "White Hat",
    definition: "An ethical hacker who uses skills to find and fix security vulnerabilities.",
    example: " A white hat reported a major security flaw in the company’s website.",
    difficulty: "beginner"
  },
  {
    term: "Worm",
    definition: "A type of malware that replicates itself to spread across systems without needing a host file.",
    example: " The worm infected hundreds of computers by exploiting a network vulnerability.",
    difficulty: "beginner"
  },
  {
    term: "XSS (Cross-Site Scripting)",
    definition: "An attack where malicious scripts are injected into trusted websites.",
    example: " The comment box was exploited for XSS to steal users’ session cookies.",
    difficulty: "advanced"
  },
  {
    term: "Zero-Day",
    definition: "A vulnerability unknown to the software vendor, with no patch yet available.",
    example: " Attackers exploited a zero-day flaw before the company could release a fix.",
    difficulty: "advanced"
  },
  {
    term: "Zero Trust",
    definition: "A security model that assumes no one is trusted by default, even inside the network.",
    example: " The company adopted a zero trust policy to verify every login request.",
    difficulty: "intermediate"
  }
];
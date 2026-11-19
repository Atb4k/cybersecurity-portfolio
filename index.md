---
layout: page
---

# Welcome to My Cybersecurity Portfolio

**Master of Cyber Security Student · Network Security · Penetration Testing**

Welcome to my professional cybersecurity portfolio. This website showcases my technical skills, practical projects, and continuous learning in cybersecurity.

## About Me

I am currently pursuing a Master of Cyber Security at Universiti Malaya, with a strong interest in network security, penetration testing, and security operations.

My technical background includes practical experience with Cisco Packet Tracer, Kali Linux, Nmap, and virtual networking environments. Through hands-on laboratory exercises, I have developed skills in network configuration, vulnerability identification, access control, and secure network management.

I have also gained professional exposure to operational technology security and identity and access management through an internship. This experience strengthened my understanding of cybersecurity challenges in professional environments.

I enjoy learning how systems and networks operate, identifying potential security weaknesses, and implementing appropriate security measures. This portfolio showcases my technical projects, practical learning experiences, and continuous development in cybersecurity.

As I progress through my postgraduate studies, my goal is to further strengthen my technical abilities and develop the skills required for a career in cybersecurity.

## Technical Skills

| Skill | Proficiency |
|---|---|
| Network Configuration and Troubleshooting | Working Knowledge |
| Cisco Packet Tracer | Working Knowledge |
| Access Control Lists (ACLs) | Working Knowledge |
| SSH and Network Device Security | Working Knowledge |
| Switch Port Security | Working Knowledge |
| Kali Linux | Working Knowledge |
| Nmap and Network Reconnaissance | Working Knowledge |
| Linux Command Line | Working Knowledge |
| Python Programming | Beginner |
| Vulnerability Assessment | Beginner |

My practical projects below demonstrate several of these skills through configuration, testing, and documented results.

## Certifications and Training

- **Master of Cyber Security, Universiti Malaya** — In progress (2026/2027 academic year).
- **Cisco Networking Academy coursework** — Networking, switching, routing, and network security laboratory activities (coursework in progress; confirm completion date before submission).
- **Hands-on cybersecurity lab training** — Kali Linux, Metasploitable 2, Nmap, and Cisco Packet Tracer.

*Formal certifications and verification badges will be added only when earned and verified. The items above are studies and training, not claims of professional certification.*

## Projects

### Project 1: Network Reconnaissance and Vulnerability Assessment Lab

**Tools:** Kali Linux, Metasploitable 2, Nmap, virtual machines, and an isolated laboratory network.

**Objective:** Set up an authorised virtual testing environment and identify exposed network services on a deliberately vulnerable host.

**Work performed:** Configured an isolated lab, verified connectivity, used Nmap to discover open ports and service versions, and documented findings such as FTP, SSH, HTTP, and SMB services. The activity focused on reconnaissance and understanding potential attack surfaces rather than testing unauthorised systems.

**Outcome:** Improved my understanding of safe network scanning, service enumeration, and the importance of validating security findings. A separate project write-up and supporting screenshots will be published in the `projects/` folder.

### Project 2: Enterprise Network Design and Security Enhancement

**Tools:** Cisco Packet Tracer, Cisco IOS, access control lists, SSHv2, and switch port security.

**Objective:** Improve the security of an existing multi-department enterprise network while maintaining permitted connectivity.

**Work performed:** Verified the original network and subnet configuration, applied an extended ACL to prevent Reception devices from reaching the CEO/CTO subnet, configured SSHv2 for encrypted router management, restricted SSH logins to the Administration subnet, and enabled sticky-MAC port security on a selected Administration switch access port.

**Verified results:** Reception-to-CEO connectivity changed from successful to blocked, while permitted gateway communication still worked. Administration SSH access succeeded and Reception SSH access was refused. A replacement device triggered a port-security violation, while the authorised PC remained functional when restored.

**Scope:** Port security was configured and tested on one access port (Fa0/13), not across every port. The detailed write-up, Packet Tracer file, and sanitised evidence screenshots will be added to the `projects/` folder.

## Learning Journey

Studying cybersecurity has helped me move beyond understanding what a network is and towards understanding how networks can be protected, tested, and monitored. At the beginning of my practical learning, I mainly focused on getting devices connected and ensuring that they could communicate. I now pay more attention to which connections should be allowed, which should be denied, and how to prove that a security control is working. This change in perspective has been especially important when completing network security and penetration testing laboratory activities.

One area that strengthened my understanding was access control on Cisco network devices. In my enterprise network project, I first verified that a Reception computer could communicate with a CEO computer. I then configured an extended access control list on the router to block traffic between those networks while permitting other traffic. By repeating the ping tests, I could compare the results before and after the change. This taught me that a configuration command alone is not enough: a security improvement needs measurable testing to demonstrate that it meets the intended policy without unnecessarily disrupting legitimate communication.

Another useful learning experience involved network reconnaissance with Kali Linux and Nmap in an isolated virtual lab. I used scanning results to identify ports and network services on a deliberately vulnerable target. I learned that finding an open service does not automatically prove that a system has been compromised. Instead, the findings provide evidence that needs interpretation and further authorised investigation. Working in a controlled environment also reinforced why permission, scope, and careful documentation are essential in cybersecurity practice.

I encountered a troubleshooting challenge while configuring sticky-MAC port security on an Administration switch. Initially, the switch reported that port security was enabled but had learned zero secure MAC addresses. I generated traffic from the connected PC, checked the MAC address table, and confirmed that the correct address had been learned. Later, after testing with a replacement device, the protected interface briefly showed a secure-down state because the connection had been disconnected. I rechecked the interface status, restored the correct PC connection, and confirmed successful connectivity. This experience helped me understand the value of checking interface status, learned MAC addresses, and test results rather than assuming a configuration had failed.

One area I still find challenging is writing Python programs for cybersecurity tasks. I understand basic programming concepts, but translating networking and security requirements into reliable code requires more practice, particularly when handling different inputs and interpreting packet data. I want to become more confident in writing small, testable tools and explaining how they work.

**My improvement goal is to complete and document one Python-based network analysis tool by 31 January 2027.** I will measure progress by building it for an authorised lab, testing it against at least five defined input cases, recording the results, and publishing a clear README that explains its purpose and limitations. I also plan to review my earlier labs regularly so that I can troubleshoot configurations with less reliance on step-by-step instructions. These activities will help me turn course knowledge into practical, repeatable skills.

## Career Objective

My career goal is to become a cybersecurity analyst, with an initial focus on security operations, network defence, and incident investigation. I am interested in understanding how attacks appear in network traffic, how security teams identify suspicious behaviour, and how organisations respond to threats. My academic training and practical work with network configuration, reconnaissance, and access controls have motivated me to develop stronger technical investigation skills.

My first step is to strengthen my networking and Linux fundamentals through continued laboratory practice and structured coursework. Second, I plan to improve my Python skills so that I can automate simple security analysis tasks and document my results. Third, I want to gain more practical exposure to security monitoring, alert triage, and incident response through safe exercises and entry-level learning opportunities.

In the longer term, I hope to combine these skills with my exposure to operational technology security and identity and access management. I aim to become a professional who can communicate technical findings clearly and recommend practical security improvements.

## Contact Information

- **GitHub:** [Atb4k](https://github.com/Atb4k)
- **LinkedIn:** Add your LinkedIn profile URL here before submission.
- **Professional email:** Add your preferred professional email address here before submission.

*For privacy and security, no personal phone number, home address, or credentials are published on this site.*

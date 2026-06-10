\# LinuxHardener: System Security \& Compliance Audit Engine



A lightweight, automated Shell script designed to assess local Linux server nodes against foundational security baselines. The tool acts as a local security compliance checker, focusing on access vectors, network boundaries, and file system privilege protection.



\---



\## 🛠️ Security Vectors Checked



The engine targets three major defensive vectors within Linux architectures:



| Audit Phase | Focus Area | Technical Mechanism | Intent / Mitigation |

| :--- | :--- | :--- | :--- |

| \*\*1. Access Control\*\* | SSH Daemon | Parses `/etc/ssh/sshd\_config` | Thwats brute-force password spraying by enforcing key-based access and dropping remote root access. |

| \*\*2. Perimeter Defence\*\* | Service Firewall | System checks via `ufw` / `firewall-cmd` | Ensures network layer segregation is active to mitigate lateral network scanning. |

| \*\*3. Privilege Management\*\* | File System Hooks | Octal checks via `stat -c "%a"` | Guarantees sensitive cryptographic artifacts (like account hash tables) cannot be parsed by low-privilege actors. |



\---



\## 🚀 Execution \& Deployment



\### Prerequisites

\* Administrative (`sudo`/`root`) privileges are mandatory to access restricted configuration blocks within the root system namespace.




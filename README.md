# Advanced Network Scanner



An advanced network scanning and security auditing tool with an integrated AI assistant. This application is designed for educational purposes and authorized security testing, providing detailed insights into network devices, open ports, and potential vulnerabilities.

---

## 🌟 Key Features

-   **Comprehensive Network Discovery:** Utilizes ARP scans to quickly and reliably find all active devices on your local network.
-   **Detailed Host Information:** Gathers IP address, MAC address, hostname, OS guess, and MAC vendor for each device.
-   **Advanced Port Scanning:** Leverages Nmap to perform service detection (`-sV`) and OS detection (`-O`) on discovered hosts.
-   **Vulnerability Assessment:** Identifies common security misconfigurations and high-risk open ports with clear severity ratings and recommendations.
-   **AI-Powered Analysis:** Integrates with Google's Gemini AI to provide context-aware analysis of scan results and answer network security questions.
-   **Professional User Interface:** A clean, multi-tabbed GUI built with CustomTkinter, featuring:
    -   A dedicated sidebar for scan configuration.
    -   Organized tabs for Devices, Ports, and Vulnerabilities.
    -   A real-time logging window for monitoring scan progress.
    -   An interactive AI chat interface.
-   **Data Export:** Allows you to save complete scan results to a JSON file for documentation or further analysis.
-   **Auto-Network Detection:** Automatically identifies the local network range to simplify the scanning process.

---

## ⚖️ Disclaimer & Ethical Use Policy

This software is provided for educational purposes, ethical security testing, and academic research **ONLY**.

-   **DO NOT USE THIS TOOL ON ANY NETWORK OR SYSTEM YOU DO NOT OWN OR HAVE EXPLICIT, WRITTEN PERMISSION TO TEST.**
-   Unauthorized scanning of networks is illegal and can lead to severe legal consequences.
-   The authors and contributors of this software accept **NO liability** for any damage, data loss, or legal issues caused by the use or misuse of this tool.

By using this software, you agree that you are solely responsible for your actions and for complying with all applicable local, state, and federal laws.

---

## 🛠️ Setup & Installation

### Prerequisites

-   Python 3.8+
-   **Nmap:** This tool relies on Nmap for its scanning capabilities. You **must** install Nmap and ensure it is in your system's PATH.
    -   [Download Nmap](https://nmap.org/download.html)

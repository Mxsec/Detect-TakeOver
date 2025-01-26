# Detect TakeOver Tool

**Detect TakeOver Tool** is a tool developed in Python to identify subdomains vulnerable to subdomain takeover attacks.
## Features

- Detects CNAMEs pointing to vulnerable providers.
- Checks multiple HTTP responses for signs of subdomain takeover (`403`, `404`, `401`, etc.).
- Includes an up-to-date list of vulnerable providers.
- Support for checking a single subdomain or a list.

---

## Installation

Follow these steps to install and set up the **Detect TakeOver Tool**:

### 1. Clone the Repository
Start by cloning the repository from GitHub

```bash
git clone https://github.com/<your-username>/detect-takeover.git
cd detect-takeover
```

```bash
python3 -m venv myenv
source myenv/bin/activate  # On Linux/Mac
myenv\Scripts\activate     # On Windows
```

### 2. Install the Dependencies

Make sure you have Python 3.6 or higher installed and install the dependencies:

```bash
pip install -r requirements.txt
```

This installs:

requests: For HTTP requests to verify subdomain status.
dnspython: For DNS queries to identify CNAME records.

Usage

To Check a Specific Subdomain

```bash
python3 detect_takeover.py -d <subdomain>
```

Example

```bash
python3 detect_takeover.py -d example.com
```

To Check a List of Subdomains

```bash
python3 detect_takeover.py -l <file>
```

Example 

```bash
python3 detect_takeover.py -l subdomains.txt
```

View Help

```bash
python3 detect_takeover.py -h
```

Output Example

████████╗ █████╗ ██╗  ██╗███████╗     ██████╗ ██╗   ██╗███████╗██████╗  
╚══██╔══╝██╔══██╗██║ ██╔╝██╔════╝    ██╔═══██╗██║   ██║██╔════╝██╔══██╗ 
   ██║   ███████║█████╔╝ █████╗      ██║   ██║██║   ██║█████╗  ██████╔╝ 
   ██║   ██╔══██║██╔═██╗ ██╔══╝      ██║   ██║██║   ██║██╔══╝  ██╔═══╝  
   ██║   ██║  ██║██║  ██║███████╗    ╚██████╔╝╚██████╔╝███████╗██║  ██╗ 
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝     ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝ 

                      === Detect TakeOver Tool ===

[INFO] Checking test.example.com
[ALERT] Vulnerable provider detected: Azure (Websites) (azurewebsites.net)
[SUCCESS] Potential takeover detected: test.example.com


Vulnerable Providers
The tool already has an internal list of vulnerable providers based on reliable sources such as the can-i-take-over-xyz project. This list is constantly updated to include the most relevant providers known to be susceptible to subdomain takeover attacks.

How it works
The tool automatically checks CNAME records and compares them with the list of vulnerable providers.
There's no need to configure or modify the list manually - everything is already integrated into the code.
To see the full list of providers, you can directly check the code in the detect_takeover.py file.

Contributing
Contributions are welcome! To report problems or suggest improvements, open an issue.

License
This project is licensed under the MIT License.

You are free to use, modify, and distribute this software for personal or commercial purposes, as long as proper credit is given to the author. See the LICENSE file for detailed terms and conditions.



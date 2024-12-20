# LFIer 🔍

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![GitHub Issues](https://img.shields.io/github/issues/Cybersecurity-Ethical-Hacker/lfier.svg)](https://github.com/Cybersecurity-Ethical-Hacker/lfier/issues)
[![GitHub Stars](https://img.shields.io/github/stars/Cybersecurity-Ethical-Hacker/lfier.svg)](https://github.com/Cybersecurity-Ethical-Hacker/lfier/stargazers)
[![Contributions Welcome](https://img.shields.io/badge/Contributions-Welcome-brightgreen.svg)](CONTRIBUTING.md)

🔍 LFIer is a tool engineered to detect **Local File Inclusion (LFI)** vulnerabilities in web applications. It scans URLs with parameters, injects various payloads, and checks for indicators in the responses to identify potential LFI vulnerabilities. Leveraging asynchronous programming, LFIer ensures efficient and accurate scanning, even in environments protected by WAFs or cloud-based defenses.

## 📸 Screenshot:
![lfier](https://github.com/user-attachments/assets/41ee1815-28fe-44ad-b34a-000e48951614)

## 🌟 Features

- **⚡ High Performance**: Utilizes Async Engine to perform rapid, non-blocking requests, making scanning large target lists fast and efficient.
- **🔍 Advanced Detection**: Uses payloads and response indicators to accurately detect LFI vulnerabilities.
- **🛡️ WAF/Cloud Bypass**: It simulates real browser requests with custom payloads, effectively bypassing WAFs and protections.
- **💉 Custom Payload Injection**: Supports grouped LFI payloads, allowing you to craft and load your own payloads for maximum flexibility and effectiveness.
- **🌐 Custom Headers**: Supports inclusion of custom HTTP headers to mimic specific client requests or bypass certain filters.
- **⏱️ Rate Limiting & Batching**: Control how many requests per second are sent and how many URLs are processed per batch, preventing server overload and improving scan reliability.
- **📝 Flexible Output**: Outputs results in JSON or plain text format, suitable for integration into CI/CD pipelines or manual review.
- **🔧 Configurable Settings**: Adjustable rate limiting, timeouts, and worker counts to optimize scanning performance.
- **📊 Detailed Logging & Progress Tracking**: Provides real-time progress via a terminal progress bar, along with comprehensive logging to assist in debugging and analysis.
- **🔄 Easy Updates**: Keep the tool up-to-date with the latest features and security patches using the `-u` or `--update` flag.
- **📂 Organized Scans**: Automatically organizes scan results into structured directories based on domains or URL lists in text or json format.

## 📥 Kali Linux Installation - (Recommended)

**Clone the repository:**

   ```bash
   git clone https://github.com/Cybersecurity-Ethical-Hacker/lfier.git
   cd xssdynagen
   ```

**Kali Linux (Kali 2024.4+) already includes the following dependencies by default. However, if needed, you can install the required dependencies manually using `pipx`:**

   ```bash
   pipx install aiohttp 
   pipx install colorama
   pipx install tqdm
   ```

**If you're using an older Kali Linux version or a different Linux distribution ensure that you have Python 3.8+ installed. Then install the required dependencies using pip:**

   ```bash
   pip install -r requirements.txt
   ```

## 📥 Install using Virtual Environment:

**Create and activate a virtual environment (optional but recommended):**

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

**Upgrade pip (Optional but Recommended):**

   ```bash
   pip install --upgrade pip
   ```

**Clone the repository:**

   ```bash
   git clone https://github.com/Cybersecurity-Ethical-Hacker/lfier.git
   cd xssdynagen
   ```

**Ensure you have Python 3.8+ installed. Install the required dependencies using pip:**

   ```bash
   pip install -r requirements.txt
   ```


❗ Important: Always Activate The Virtual Environment Before Use
Whenever you:

- Open a New Terminal Window
- Restart Your Computer
  
You must activate the virtual environment before running XSSDynagen to ensure that all dependencies are correctly loaded.


## 📄 Payloads Mechanism
Lfier utilizes a structured file containing payloads and indicators to detect vulnerabilities. The file is organized into groups, allowing users to add their own custom payloads and categorize indicators as needed. Lfier tests each payload in `# Payloads` group against the upcoming `# Indicators` group to identify potential security issues effectively.

Example:
```
# Payloads
/..\\../..\\../..\\../..\\../..\\../..\\../etc/passwd
.\\./.\\./.\\./.\\./.\\./.\\./etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd

# Indicators
root:x:0:0:
nobody:x:65534:

# Payloads
C:/boot.ini
C:\boot.ini

# Indicators
[boot loader]
timeout=30
```

Lfier utilizes the `# Payloads` section to target Linux systems by attempting to read the contents of the `/etc/passwd` file. After executing these payloads, it scans the upcoming `# Indicators` group for specific signatures, such as `root:x:0:0:` or `nobody:x:65534:`, to determine if the payload successfully accessed the sensitive information.

On the second `# Payloads` section for Windows systems is attempting to read the contents of the `C:\boot.ini` file. After executing these payloads, it scans the upcoming `# Indicators` group for specific signatures, such as `[boot loader]` or `timeout=30`, to determine if the payload successfully accessed the sensitive information.

## 🧩 **URLs with Parameters**

The tool requires URLs with parameters (e.g., `?id=1` or `?search=example&page=2`) to work effectively.

If you don't have a URL with parameters or a list of such URLs, you can generate one using the following method (replace the `domain.com`):

```bash
paramspider -d domain.com -s 2>&1 | grep -Ei "https?://" | sort -u > urls.txt
```

Alternatively, you can combine tools like `waybackurls`, `httpx`, `katana`, and others to collect URLs efficiently.

Then just load the list using `-l urls.txt`.

## 🚀 Usage
Lfier can be used to scan a single domain or a list of URLs.

📍 Command-Line Options:
```
Usage: lfier.py [options]

options:
  -h, --help         show this help message and exit
  -d, --domain       Specify the domain with parameter(s) to scan (required unless -l is used)
  -l, --url-list     Provide a file containing a list of URLs with parameters to scan
  -t, --timeout      Total request timeout in seconds
  --connect-timeout  Timeout for establishing connections in seconds
  --read-timeout     Timeout for reading responses in seconds
  -w, --workers      Maximum number of concurrent workers
  -r, --rate         Request rate limit
  -b, --batch-size   Number of items to process in each batch
  -p, --payloads     Custom file containing payloads
  -o, --output       Specify the output file name (supports .txt or .json)
  -j, --json         Output results in JSON format
  -H, --header       Custom headers can be specified multiple times. Format: "Header: Value"
  -u, --update       Check for updates and automatically install the latest version
```

## 💡 Examples
💻 Scan a single domain with parameter(s) using default settings:
```bash
python lfier.py -d "https://domain.com/file.php?parameter=1234"
```
💻 Scan multiple URLs with parameter(s) from a file with a custom rate limit:
```bash
python lfier.py -l urls.txt -r 5
```
💻 Scan with custom payloads and increased timeout:
```bash
python lfier.py -d "https://domain.com/file.php?parameter=1234" -p custom_payloads.txt -t 10
```
💻 Include custom headers in the requests:
```bash
python lfier.py -l urls.txt -H "Authorization: Bearer <token>" -H "X-Forwarded-For: 127.0.0.1"
```
💻 Update LFIer to the latest version:
```bash
python lfier.py --update
```

## 📊 Output
- Results are saved in the scans/ directory, organized by domain or list name.
- The output file name includes a timestamp for easy reference.
- If JSON output is enabled (-j flag), results include detailed scan summaries and vulnerabilities found.

## 🐛 Error Handling
- Graceful Exception Handling: The tool gracefully handles exceptions and logs errors to lfi_scanner.log.
- Informative Messages: Provides clear messages if payload files or URL lists are not found.
- Interruption Support: Supports interruption via Ctrl+C, safely stopping the scan and providing a summary.

## 🛠️ Troubleshooting

**Common Issues and Solutions**

If you encounter problems while using **LFIer**, consider the following common causes and their respective solutions:

1. **Excessive Max Workers Setting**
   - **Issue:** Setting the `Max Workers` value too high can lead to excessive resource consumption, causing the tool to crash or perform inefficiently.
   - **Solution:** Reduce the `Max Workers` value to a more manageable number (e.g., 4 or 8) to balance performance and resource usage.

2. **Overly Large Payloads List**
   - **Issue:** Utilizing an excessively large payloads list can overwhelm the tool, resulting in slow performance or failures.
   - **Solution:** Optimize your payloads list by removing redundant or unnecessary entries.

**Recommendations:**
- **Start Simple:** Begin with a moderate number of workers and a streamlined payloads list to ensure smooth operation.
- **Gradual Scaling:** If needed, gradually increase the `Max Workers` and payloads size while monitoring system performance.
- **Customization:** Tailor the payloads and worker settings based on your system's capabilities and the specific requirements of your testing environment.

## 📂 Directory Structure
- `lfier.py`: Main executable script.
- `lfi_payloads.txt`: Default payload file containing grouped payloads and indicators.
- `extra_payloads.txt`: Contains extra payloads.
- `requirements.txt`: Contains a list of dependencies required to run the script.
- `scans/`: Contains output files and scan results.
- `logs/`: Contains detailed log files.

## 🤝 Contributing
Contributions are welcome! Please open an issue or submit a pull request for any improvements, bug fixes, or new features.

## 🛡️ Ethical Usage Guidelines
I am committed to promoting ethical practices in cybersecurity. Please ensure that you use this tool responsibly and in accordance with the following guidelines:

1. Educational Purposes Only
This tool is intended to be used for educational purposes, helping individuals learn about penetration testing techniques and cybersecurity best practices.

2. Authorized Testing
Always obtain explicit permission from the system owner before conducting any penetration tests. Unauthorized testing is illegal and unethical.

3. Responsible Vulnerability Reporting
If you discover any vulnerabilities using this tool, report them responsibly to the respective organizations or maintainers. Do not exploit or disclose vulnerabilities publicly without proper authorization.

4. Compliance with Laws and Regulations
Ensure that your use of this tool complies with all applicable local, national, and international laws and regulations.

## 📚 Learn and Grow
Whether you're a budding penetration tester aiming to enhance your skills or a seasoned professional seeking to uncover and mitigate security issues, LFier is here to support your journey in building a safer digital landscape.

> [!NOTE]
> Building a Safer Digital World. 🔒

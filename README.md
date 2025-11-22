# EVA-Tool (External Vulnerability Assessment Tool)

**Version:** 8.3
**Author:** Ryan Kucher
**Last Updated:** 2025-08-11

## ⚠️ LEGAL DISCLAIMER

**READ THIS CAREFULLY BEFORE USING THIS TOOL**

This tool is designed **EXCLUSIVELY** for authorized security testing, vulnerability assessment, and educational purposes. Unauthorized access to computer systems is illegal under laws including but not limited to:

- **United States**: Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030
- **European Union**: Network and Information Security Directive (NISD)
- **United Kingdom**: Computer Misuse Act 1990
- **International**: Council of Europe Convention on Cybercrime

### Legal Use Requirements

✅ **AUTHORIZED USE ONLY:**
- You have **explicit written permission** from the system owner
- You are conducting authorized penetration testing under a formal engagement
- You are scanning systems you own or have legal authority to test
- You are using this in a controlled lab/educational environment
- You are participating in authorized security competitions (CTFs) or bug bounty programs

❌ **PROHIBITED USE:**
- Scanning systems without explicit authorization
- Unauthorized network reconnaissance
- Attempting to exploit discovered vulnerabilities without permission
- Mass scanning or attacking multiple targets
- Any malicious or illegal activities

### User Responsibility

By using this tool, you acknowledge that:
1. **You are solely responsible** for obtaining proper authorization before scanning any target
2. **You will comply** with all applicable laws and regulations
3. **The author is not liable** for any misuse, damage, or legal consequences resulting from use of this tool
4. You understand that **unauthorized use may result in criminal prosecution**

**If you do not have explicit authorization to scan a target, DO NOT USE THIS TOOL.**

---

## 📋 Description

EVA (External Vulnerability Assessment) Tool is a sequential, banner-style network security scanner that performs comprehensive port-based vulnerability assessments with live, colorized output. It automates the discovery and enumeration of network services, providing security professionals with detailed reconnaissance data.

### Key Features

- **Live Streaming Output**: Real-time, colorized command output with clear section headers
- **Intelligent Service Detection**: Automatic protocol detection and specialized scanning
- **Fast TLS Analysis**: Optimized HTTPS scanning with integrated testssl.sh
- **Web Service Intelligence**: Auto-discovery with Firefox integration and robots.txt analysis
- **Comprehensive Protocol Support**: HTTP/HTTPS, SSH, SMTP, DNS, SNMP, IKE, NTP
- **Human-Friendly Errors**: Clear guidance without verbose stack traces
- **Smart Timeout Management**: Prevents hanging on unresponsive services
- **Flexible Port Specification**: Individual ports, ranges, and comma-separated lists
- **Root Privilege Enforcement**: Security-critical operations with proper permissions

---

## 🔧 System Requirements

### Operating System
- **Recommended**: Kali Linux 2023.1+ or Debian 11+
- **Supported**: Any Debian-based Linux distribution
- **Required**: Linux kernel 4.4+

### Privileges
- **Root access required** (uses raw sockets and privileged ports)

### Python
- **Python 3.8 or higher**

---

## 📦 Installation

### 1. Install System Dependencies

```bash
# Update package lists
sudo apt-get update

# Install core tools (required)
sudo apt-get install -y nmap netcat-traditional curl dnsutils

# Install optional tools (recommended for full functionality)
sudo apt-get install -y snmpcheck ssh-audit ike-scan firefox-esr

# Note: Some tools may have different package names on non-Kali systems:
# - snmpcheck might be 'snmp' on some distributions
# - ssh-audit may need: pip install ssh-audit
```

### 2. Install Python Dependencies

```bash
# Using pip
pip install colorama tqdm requests

# Or using pip3
pip3 install colorama tqdm requests
```

### 3. Install testssl.sh (Recommended)

```bash
# Option A: Clone to /root/tools/ (default location)
sudo mkdir -p /root/tools
cd /root/tools
git clone --depth 1 https://github.com/drwetter/testssl.sh.git
sudo chmod +x /root/tools/testssl.sh/testssl.sh

# Option B: Install via package manager (if available)
sudo apt-get install testssl.sh

# Option C: Set custom path via environment variable
export TESTSSL_PATH=/path/to/your/testssl.sh
```

### 4. Download EVA-Tool

```bash
git clone https://github.com/yourusername/EVA-Tool.git
cd EVA-Tool
chmod +x eva_scanner.py  # Make executable
```

### 5. Verify Installation

```bash
# Check all dependencies
./eva_scanner.py --help
```

---

## 🚀 Usage

### Basic Syntax

```bash
sudo ./eva_scanner.py --target <IP/HOSTNAME> --ports <PORT_SPEC> [OPTIONS]
```

### Required Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `--target` | Target IP address or hostname | `192.168.1.100` or `example.com` |
| `--ports` | Port(s) to scan (comma-separated or ranges) | `80,443` or `1-1000` |

### Optional Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--no-ssl` | Skip all TLS/SSL scans (faster but less thorough) | Enabled |
| `--no-web` | Skip HTTP/HTTPS requests and Firefox integration | Enabled |
| `--no-firefox` | Disable automatic Firefox page opening | Opens Firefox |
| `--debug` | Enable verbose logging for troubleshooting | Disabled |

---

## 📖 Usage Examples

### Example 1: Basic Web Server Scan
```bash
sudo ./eva_scanner.py --target 192.168.1.100 --ports 80,443
```
Scans HTTP and HTTPS ports with full web analysis.

### Example 2: Common Service Ports
```bash
sudo ./eva_scanner.py --target example.com --ports 22,25,80,443,8080
```
Scans SSH, SMTP, HTTP, HTTPS, and alternative HTTP port.

### Example 3: Port Range Scan
```bash
sudo ./eva_scanner.py --target 10.0.0.50 --ports 1-1024
```
Scans all privileged ports (1-1024).

### Example 4: Mixed Port Specification
```bash
sudo ./eva_scanner.py --target 192.168.1.1 --ports 22,80,443,8000-8888
```
Scans specific ports plus a range.

### Example 5: Headless Scan (No Browser)
```bash
sudo ./eva_scanner.py --target 192.168.1.100 --ports 443 --no-firefox
```
Performs scan without opening Firefox.

### Example 6: Quick Scan (Skip TLS Deep Dive)
```bash
sudo ./eva_scanner.py --target 192.168.1.100 --ports 443,8443 --no-ssl
```
Faster scan without testssl.sh analysis.

### Example 7: Debug Mode for Troubleshooting
```bash
sudo ./eva_scanner.py --target 192.168.1.100 --ports 22 --debug
```
Enables verbose output to diagnose issues.

### Example 8: Internal Network Audit
```bash
sudo ./eva_scanner.py --target 10.10.10.5 --ports 22,80,161,443,3306,5432
```
Scans common internal services (SSH, Web, SNMP, databases).

---

## 🔍 Supported Services & Protocols

### Web Services
- **HTTP** (80, 8000, 8080, 8880): Full web enumeration, headers, robots.txt
- **HTTPS** (443, 10443): TLS analysis with testssl.sh, cipher suite testing

### Secure Shell
- **SSH** (22): Version detection, algorithm auditing via ssh-audit

### Email
- **SMTP** (25, 465, 587, 2525): STARTTLS testing, banner grabbing

### Network Management
- **SNMP** (161): Community string enumeration (public/private), MIB walking
- **DNS** (53, 5353): Service discovery, zone transfer testing
- **NTP** (123): Version detection, vulnerability scanning

### VPN/Tunneling
- **IKE** (500): IPsec enumeration, aggressive mode testing, vendor fingerprinting
- **IKE NAT-T** (4500): Generic probing (specialized scanning only on port 500)

### Generic Ports
Any unlisted port receives intelligent service detection and protocol-specific scanning.

---

## 📊 Output & Results

### Output Format
- **Real-time streaming**: See results as they happen
- **Color-coded sections**: Easy visual parsing
  - 🟢 Green: Success indicators
  - 🟡 Yellow: Warnings and informational messages
  - 🔴 Red: Errors and failures
  - 🔵 Blue: Command execution details
  - 🟣 Magenta: Special content (e.g., robots.txt)

### What Gets Displayed
1. **Command being executed**: Full command line for transparency
2. **Live tool output**: Streaming results from nmap, testssl, etc.
3. **Success/failure indicators**: Clear status after each operation
4. **HTTP status codes**: For web services with human-readable descriptions
5. **robots.txt content**: Automatic retrieval and display
6. **Progress bar**: Overall scan progress across ports

### Browser Integration
- Automatically opens discovered web services in Firefox (unless `--no-firefox`)
- Opens both main page and robots.txt if accessible

---

## 🛠️ Troubleshooting

### Common Issues

#### "This tool needs root privileges"
**Solution:** Run with sudo or as root user
```bash
sudo ./eva_scanner.py --target 192.168.1.1 --ports 80
```

#### "Required tool 'X' is not installed"
**Solution:** Install the missing dependency
```bash
sudo apt-get install <tool-name>
```

#### "Could not resolve 'hostname'"
**Solutions:**
- Verify hostname spelling
- Check DNS configuration
- Try using IP address directly
- Ensure network connectivity

#### Commands timing out
**Solutions:**
- Use `--debug` to see detailed output
- Check if target is blocking/rate-limiting
- Reduce scan scope (fewer ports)
- Run individual commands manually to diagnose

#### testssl.sh not found
**Solutions:**
- Install to `/root/tools/testssl.sh/testssl.sh`
- Install via package manager: `sudo apt-get install testssl.sh`
- Set environment variable: `export TESTSSL_PATH=/your/path/testssl.sh`
- Tool will gracefully skip TLS scans if unavailable

#### Permission denied errors
**Solutions:**
- Ensure script is executable: `chmod +x eva_scanner.py`
- Verify you're running with sufficient privileges (sudo/root)
- Check file ownership: `ls -l eva_scanner.py`

#### Firefox won't open
**Solutions:**
- Install Firefox: `sudo apt-get install firefox-esr`
- Use `--no-firefox` flag to skip browser integration
- Check X11/display configuration if running remotely

---

## 🔒 Security Best Practices

### Before Scanning
1. **Obtain written authorization** from the target system owner
2. **Define scope** clearly (which IPs/ports are authorized)
3. **Coordinate timing** to avoid disrupting business operations
4. **Document authorization** and keep records

### During Scanning
1. **Monitor scan impact** - watch for service disruption
2. **Respect rate limits** - built-in 0.3s pace between ports
3. **Stay within scope** - only scan authorized targets
4. **Log all activities** for audit trails

### After Scanning
1. **Secure scan results** - contain sensitive information
2. **Report findings responsibly** to stakeholders
3. **Do not exploit** discovered vulnerabilities without explicit permission
4. **Delete sensitive data** when no longer needed

### Data Handling
- **Scan results may contain**: Service versions, configuration details, potential vulnerabilities
- **Treat as confidential**: Encrypt at rest, secure in transit
- **Minimize retention**: Delete when no longer needed
- **Access control**: Restrict to authorized personnel only

---

## 🧪 Testing & Validation

### Test in Safe Environments First
```bash
# Test against your own systems
sudo ./eva_scanner.py --target localhost --ports 22,80

# Use intentionally vulnerable VMs (legally)
# - Metasploitable
# - DVWA (Damn Vulnerable Web Application)
# - HackTheBox (with subscription)
# - TryHackMe (with subscription)
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

### Reporting Issues
1. Check existing issues first
2. Provide detailed description
3. Include system information (OS, Python version)
4. Attach relevant logs (use `--debug`)

### Submitting Code
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Follow existing code style
4. Test thoroughly
5. Submit pull request with clear description

### Code of Conduct
- Be respectful and professional
- Focus on constructive feedback
- Prioritize security and legal compliance
- No malicious code or techniques

---

## 📄 License

**[Specify License Here - Recommended: GPLv3 for security tools]**

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

---

## 📞 Contact & Support

**Author:** Ryan Kucher
**Version:** 8.3
**Repository:** [https://github.com/yourusername/EVA-Tool](https://github.com/yourusername/EVA-Tool)

### Getting Help
1. Check this README thoroughly
2. Run with `--debug` flag for detailed diagnostics
3. Search existing GitHub issues
4. Create new issue with detailed information

### Responsible Disclosure
If you discover security vulnerabilities in EVA-Tool itself:
1. **Do not** open public GitHub issues
2. Contact the author privately
3. Allow reasonable time for fixes before disclosure

---

## 🙏 Acknowledgments

This tool builds upon the excellent work of:
- **nmap** - Network exploration and security auditing
- **testssl.sh** - Testing TLS/SSL encryption
- **ssh-audit** - SSH server auditing
- **ike-scan** - IPsec VPN scanning
- And many other open-source security tools

---

## ⚖️ Ethical Use Guidelines

### The Security Researcher's Pledge
As a user of EVA-Tool, commit to:

1. **Authorization First**: Never scan without permission
2. **Do No Harm**: Avoid disrupting services or degrading performance
3. **Responsible Disclosure**: Report vulnerabilities appropriately
4. **Respect Privacy**: Handle discovered data with care
5. **Legal Compliance**: Follow all applicable laws and regulations
6. **Continuous Learning**: Use for education and improvement
7. **Community Benefit**: Share knowledge responsibly

### When in Doubt
If you're unsure whether scanning a target is authorized:
- **STOP** and seek clarification
- Get **written permission** before proceeding
- Consult with **legal counsel** if necessary
- Remember: **It's better to be safe than sorry (or prosecuted)**

---

## 📚 Additional Resources

### Learning Resources
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PTES - Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### Legal Frameworks
- [CFAA - Computer Fraud and Abuse Act](https://www.justice.gov/jm/criminal-resource-manual-1030-computer-fraud-and-abuse-act)
- [GDPR - Data Protection](https://gdpr.eu/)
- [ISO 27001 - Information Security](https://www.iso.org/isoiec-27001-information-security.html)

### Related Tools
- [Nmap](https://nmap.org/) - Network scanner
- [Metasploit](https://www.metasploit.com/) - Penetration testing framework
- [Burp Suite](https://portswigger.net/burp) - Web application security testing
- [Wireshark](https://www.wireshark.org/) - Network protocol analyzer

---

**Remember: With great power comes great responsibility. Use EVA-Tool ethically and legally.**

---

*Last Updated: 2025-08-11 | Version 8.3*

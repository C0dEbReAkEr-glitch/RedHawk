# RedHawk 🦅
## Advanced Remote Reconnaissance Framework

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security Tool](https://img.shields.io/badge/Security-Reconnaissance-red.svg)](https://github.com/yourusername/redhawk)

**RedHawk** is a comprehensive remote reconnaissance framework designed for authorized penetration testing, CTF challenges, and cybersecurity education. It combines multiple reconnaissance techniques into a single, powerful tool that can gather extensive intelligence about target systems remotely.

---

## 🚀 Features

### Core Reconnaissance
- **🔍 Port Scanning**: Multi-threaded TCP port discovery (1-65535)
- **🔧 Service Enumeration**: Banner grabbing and service identification
- **🖥️ OS Fingerprinting**: Operating system detection via multiple techniques
- **🌐 Network Mapping**: Subnet discovery and network topology analysis

### Advanced Capabilities
- **🛡️ Vulnerability Assessment**: Automated CVE and security flaw detection
- **📸 Screenshot Capture**: Visual documentation of web services
- **📄 Metadata Extraction**: EXIF, PDF, and document metadata analysis
- **🕵️ OSINT Integration**: Social media and domain intelligence gathering
- **🔐 Credential Testing**: Multi-protocol authentication testing

### Web Application Security
- **SQL Injection Detection**
- **Cross-Site Scripting (XSS) Testing**
- **Directory Traversal Assessment**
- **Default Credential Validation**
- **Technology Stack Identification**
- **Administrative Panel Discovery**

---

## 📦 Installation

### Prerequisites
```bash
# Python 3.8 or higher required
python3 --version

# Install core dependencies
pip3 install -r requirements.txt
```

### Required Dependencies
```bash
pip3 install requests paramiko selenium pillow PyPDF2 python-nmap urllib3
```

### Optional Dependencies (for full functionality)
```bash
# For screenshot capture
# Ubuntu/Debian:
sudo apt install chromium-chromedriver

# macOS:
brew install chromedriver

# Windows:
# Download ChromeDriver from https://chromedriver.chromium.org/
```

### Quick Setup
```bash
git clone https://github.com/yourusername/redhawk.git
cd redhawk
pip3 install -r requirements.txt
python3 redhawk.py --help
```

---

## 🎯 Usage

### Basic Reconnaissance
```bash
# Standard comprehensive scan
python3 redhawk.py 192.168.1.100

# Quick scan (faster, essential ports only)
python3 redhawk.py 10.0.0.50 --quick
```

### Advanced Options
```bash
# Skip screenshot capture (faster execution)
python3 redhawk.py 172.16.1.25 --no-screenshots

# Skip credential testing (stealth mode)
python3 redhawk.py 192.168.1.75 --no-creds

# Save results to specific directory
python3 redhawk.py 10.0.0.100 --output ./scan_results

# Combine options
python3 redhawk.py 172.16.1.50 --quick --no-screenshots --output ./results
```

### Command Line Arguments
| Argument | Description |
|----------|-------------|
| `target` | Target IP address (required) |
| `--quick` | Fast scan mode (ports 1-100) |
| `--no-screenshots` | Skip web service screenshot capture |
| `--no-creds` | Skip credential testing modules |
| `--output`, `-o` | Specify output directory for results |

---

## 📊 Output & Reporting

### Generated Files
- **`advanced_recon_[IP]_[timestamp].json`** - Comprehensive scan results
- **`screenshots/`** - Web service screenshots (if enabled)
- **Console Output** - Real-time scan progress and findings

### Report Sections
1. **Port Scan Results** - Open ports and services
2. **Web Services** - HTTP/HTTPS applications and technologies
3. **Vulnerability Assessment** - Security findings with severity ratings
4. **Credential Testing** - Successful authentication attempts
5. **Screenshot Capture** - Visual documentation
6. **Metadata Extraction** - Hidden information discovery
7. **OSINT Intelligence** - Domain and social media reconnaissance

---

## 🔧 Modules Overview

### VulnerabilityScanner
Identifies common security vulnerabilities:
- SQL injection vectors
- Cross-site scripting (XSS)
- Directory traversal flaws
- Default credential usage
- Outdated service versions

### ScreenshotCapture
Visual documentation system:
- Headless browser automation
- Multi-resolution capture
- Organized file management
- Error handling and recovery

### MetadataExtractor
Information leakage detection:
- Image EXIF data analysis
- PDF document properties
- Office document metadata
- Certificate transparency logs

### OSINTCollector
Open source intelligence:
- Subdomain enumeration
- Social media discovery
- Public breach database checks
- Domain reputation analysis

### CredentialTester
Authentication security testing:
- SSH brute force protection
- FTP anonymous access
- Web application login testing
- Multi-protocol support

---

## 🎮 CTF Integration

### Creating Challenges
RedHawk is perfect for CTF challenge creation:

```python
# Hide flags in various locations RedHawk discovers:
# - Image EXIF GPS coordinates
# - PDF metadata author fields
# - HTTP response headers
# - Certificate subject names
# - Social media profile descriptions
# - Default credential combinations
```

### Educational Use Cases
- **Red Team Training**: Comprehensive reconnaissance methodology
- **Blue Team Awareness**: Understanding attacker techniques
- **Security Assessment**: Authorized penetration testing
- **CTF Competitions**: Multi-layered challenge solving

---

## ⚠️ Legal & Ethical Usage

### 🚨 IMPORTANT DISCLAIMER
**RedHawk is designed for educational purposes and authorized security testing only.**

### ✅ Authorized Use Cases
- Personal lab environments
- Systems you own or control
- Authorized penetration testing with written permission
- CTF competitions and challenges
- Educational cybersecurity research

### ❌ Prohibited Uses
- Scanning systems without explicit permission
- Unauthorized network reconnaissance
- Malicious security testing
- Privacy violations
- Any illegal activities

### Legal Requirements
- **Always obtain written authorization** before scanning
- **Respect rate limits** and system resources
- **Follow responsible disclosure** for any findings
- **Comply with local laws** and regulations

---

## 🔒 Security Considerations

### Detection Avoidance
- Implements timing delays to avoid detection
- Respects robots.txt and rate limiting
- Uses legitimate user agents
- Minimal network footprint options

### Safe Testing Practices
- **Limited credential attempts** to prevent account lockouts
- **Timeout mechanisms** to avoid hanging connections
- **Error handling** to prevent crashes
- **Resource cleanup** after execution

---

## 🛠️ Development

### Project Structure
```
redhawk/
├── redhawk.py              # Main executable
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── screenshots/           # Generated screenshots
├── examples/              # Usage examples
└── docs/                  # Additional documentation
```

### Contributing
1. Fork the repository
2. Create feature branch (`git checkout -b feature/new-module`)
3. Commit changes (`git commit -am 'Add new reconnaissance module'`)
4. Push to branch (`git push origin feature/new-module`)
5. Create Pull Request

### Extending RedHawk
```python
# Add new reconnaissance modules
class CustomScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
    
    def scan_custom_service(self):
        # Your custom reconnaissance logic
        pass
```

---

## 📚 Educational Resources

### Learning Path
1. **Network Fundamentals**: TCP/IP, protocols, ports
2. **Web Application Security**: OWASP Top 10
3. **Operating System Internals**: Windows/Linux security
4. **Penetration Testing Methodology**: PTES, OWASP
5. **Red Team Operations**: ATT&CK framework

### Recommended Reading
- **The Web Application Hacker's Handbook**
- **Penetration Testing: A Hands-On Introduction to Hacking**
- **Red Team Development and Operations**
- **OWASP Testing Guide**

### Certification Prep
RedHawk helps prepare for:
- **OSCP** (Offensive Security Certified Professional)
- **CEH** (Certified Ethical Hacker)
- **CRTP** (Certified Red Team Professional)
- **eJPT** (eLearnSecurity Junior Penetration Tester)

---

## 🐛 Troubleshooting

### Common Issues

**ChromeDriver Not Found**
```bash
# Ubuntu/Debian
sudo apt install chromium-chromedriver

# Add to PATH if needed
export PATH=$PATH:/usr/lib/chromium-browser/
```

**Permission Denied Errors**
```bash
# Run with appropriate permissions
sudo python3 redhawk.py 192.168.1.100

# Or adjust firewall rules for your environment
```

**Connection Timeouts**
- Check target system connectivity
- Verify firewall rules
- Increase timeout values in configuration
- Use `--quick` mode for faster scanning

**Missing Dependencies**
```bash
# Install all requirements
pip3 install -r requirements.txt

# Check Python version compatibility
python3 --version  # Should be 3.8+
```

---

## 📈 Performance Optimization

### Scan Speed
- **Multi-threading**: Up to 100 concurrent port scans
- **Smart Timeouts**: Adaptive timing based on response
- **Efficient Algorithms**: Optimized reconnaissance logic
- **Resource Management**: Automatic cleanup and memory management

### Memory Usage
- **Streaming Processing**: Large files processed in chunks
- **Temporary File Cleanup**: Automatic resource management
- **Efficient Data Structures**: Optimized storage and retrieval
- **Garbage Collection**: Proper object lifecycle management

---

## 🏆 Example CTF Challenge

Create a multi-layered CTF challenge using RedHawk:

```bash
# Flag 1: Hidden in port banner
nc -l 8080 "Welcome! Flag: CTF{banner_recon_123}"

# Flag 2: In image EXIF data
exiftool -overwrite_original -Artist="CTF{metadata_hunter_456}" target.jpg

# Flag 3: Default credentials
# Username: admin, Password: CTF{weak_creds_789}

# Flag 4: In certificate subject
# CN=CTF{ssl_detective_321}

# Flag 5: Social media OSINT
# Twitter bio: "Security researcher | CTF{osint_master_654} | InfoSec"
```

---

## 📞 Support & Community

### Getting Help
- **Issues**: Report bugs via GitHub Issues
- **Discussions**: Join the community discussions
- **Documentation**: Check the `/docs` directory
- **Examples**: See `/examples` for usage scenarios

### Contributing
We welcome contributions! Areas needing development:
- Additional vulnerability checks
- New OSINT sources
- Enhanced stealth capabilities
- Mobile/IoT device scanning
- Cloud service reconnaissance

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **OWASP** - Web application security guidance
- **NIST** - Cybersecurity framework standards
- **MITRE ATT&CK** - Threat intelligence methodology
- **CTF Community** - Inspiration and testing feedback
- **Open Source Security Tools** - Foundation and inspiration

---

## ⚖️ Responsible Disclosure

If you discover vulnerabilities using RedHawk:

1. **Verify authorization** before testing
2. **Document findings** professionally
3. **Contact system owners** responsibly
4. **Allow reasonable time** for remediation
5. **Follow coordinated disclosure** practices

---

**Remember: With great power comes great responsibility. Use RedHawk ethically and legally!**

---

*Built with ❤️ for the cybersecurity community*# RedHawk

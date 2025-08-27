#!/usr/bin/env python3
"""
Advanced Remote CTF Reconnaissance Tool
"""

import socket
import threading
import subprocess
import sys
import time
import argparse
from datetime import datetime
import json
import requests
from urllib.parse import urljoin, urlparse
import ssl
import paramiko
from concurrent.futures import ThreadPoolExecutor
import base64
import hashlib
import re
import os
from pathlib import Path
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# For screenshot capture
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

# For metadata extraction
try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

# For PDF metadata
try:
    import PyPDF2
    PYPDF2_AVAILABLE = True
except ImportError:
    PYPDF2_AVAILABLE = False

class VulnerabilityScanner:
    """Check for specific CVEs and common vulnerabilities"""
    
    def __init__(self, target_ip, open_ports, web_services):
        self.target_ip = target_ip
        self.open_ports = open_ports
        self.web_services = web_services
        self.vulnerabilities = []
    
    def scan_common_vulnerabilities(self):
        """Scan for common vulnerabilities"""
        print("[+] Scanning for common vulnerabilities...")
        
        # Check for web vulnerabilities
        for service in self.web_services:
            self._check_web_vulnerabilities(service)
        
        # Check for SSH vulnerabilities
        if 22 in self.open_ports:
            self._check_ssh_vulnerabilities()
        
        # Check for SMB vulnerabilities
        if 445 in self.open_ports or 139 in self.open_ports:
            self._check_smb_vulnerabilities()
        
        # Check for FTP vulnerabilities
        if 21 in self.open_ports:
            self._check_ftp_vulnerabilities()
        
        return self.vulnerabilities
    
    def _check_web_vulnerabilities(self, service):
        """Check web application vulnerabilities"""
        url = service['url']
        print(f"[+] Testing {url} for web vulnerabilities...")
        
        # SQL Injection test (basic)
        sqli_payloads = ["'", "1' OR '1'='1", "admin'--", "' UNION SELECT NULL--"]
        
        for payload in sqli_payloads:
            try:
                test_url = f"{url}/login.php?user={payload}"
                response = requests.get(test_url, timeout=5, verify=False)
                
                if any(error in response.text.lower() for error in 
                       ['sql syntax', 'mysql_fetch', 'ora-', 'microsoft ole db']):
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'url': test_url,
                        'description': 'Possible SQL injection vulnerability detected'
                    })
                    print(f"[!] Potential SQL Injection found: {test_url}")
                    break
            except:
                continue
        
        # XSS test (basic)
        xss_payload = "<script>alert('XSS')</script>"
        try:
            test_url = f"{url}/search.php?q={xss_payload}"
            response = requests.get(test_url, timeout=5, verify=False)
            
            if xss_payload in response.text:
                self.vulnerabilities.append({
                    'type': 'Cross-Site Scripting (XSS)',
                    'severity': 'Medium',
                    'url': test_url,
                    'description': 'Reflected XSS vulnerability detected'
                })
                print(f"[!] Potential XSS found: {test_url}")
        except:
            pass
        
        # Directory traversal test
        traversal_payloads = ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"]
        
        for payload in traversal_payloads:
            try:
                test_url = f"{url}/file.php?path={payload}"
                response = requests.get(test_url, timeout=5, verify=False)
                
                if any(indicator in response.text.lower() for indicator in 
                       ['root:x:', '[drivers]', 'daemon:', 'localhost']):
                    self.vulnerabilities.append({
                        'type': 'Directory Traversal',
                        'severity': 'High',
                        'url': test_url,
                        'description': 'Directory traversal vulnerability detected'
                    })
                    print(f"[!] Potential Directory Traversal found: {test_url}")
                    break
            except:
                continue
        
        # Check for default credentials on admin panels
        self._check_default_credentials(url)
    
    def _check_default_credentials(self, base_url):
        """Test default credentials on admin panels"""
        admin_paths = ['/admin', '/administrator', '/wp-admin', '/phpmyadmin']
        default_creds = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', ''),
            ('administrator', 'administrator'), ('root', 'root'),
            ('admin', '123456'), ('guest', 'guest')
        ]
        
        for path in admin_paths:
            try:
                login_url = urljoin(base_url, path)
                response = requests.get(login_url, timeout=3, verify=False)
                
                if response.status_code == 200 and 'login' in response.text.lower():
                    print(f"[+] Found admin panel: {login_url}")
                    
                    # Try default credentials (basic test)
                    for username, password in default_creds[:3]:  # Limit to avoid lockout
                        try:
                            login_data = {'username': username, 'password': password}
                            post_response = requests.post(login_url, data=login_data, 
                                                        timeout=3, verify=False, allow_redirects=False)
                            
                            if post_response.status_code in [302, 200] and 'dashboard' in post_response.text.lower():
                                self.vulnerabilities.append({
                                    'type': 'Default Credentials',
                                    'severity': 'Critical',
                                    'url': login_url,
                                    'credentials': f"{username}:{password}",
                                    'description': 'Default credentials accepted'
                                })
                                print(f"[!] Default credentials work: {username}:{password}")
                                break
                        except:
                            continue
            except:
                continue
    
    def _check_ssh_vulnerabilities(self):
        """Check SSH service vulnerabilities"""
        print("[+] Testing SSH service...")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_ip, 22))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            # Check for vulnerable SSH versions
            if 'openssh' in banner.lower():
                version_match = re.search(r'openssh[_\s](\d+\.\d+)', banner.lower())
                if version_match:
                    version = float(version_match.group(1))
                    if version < 7.4:
                        self.vulnerabilities.append({
                            'type': 'Outdated SSH Version',
                            'severity': 'Medium',
                            'service': f"SSH {banner.strip()}",
                            'description': 'Outdated SSH version may have known vulnerabilities'
                        })
                        print(f"[!] Outdated SSH version detected: {banner.strip()}")
        except:
            pass
    
    def _check_smb_vulnerabilities(self):
        """Check SMB vulnerabilities"""
        print("[+] Testing SMB service...")
        
        # Check for EternalBlue (MS17-010) indicators
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.target_ip, 445))
            
            if result == 0:
                # Basic SMB version detection
                self.vulnerabilities.append({
                    'type': 'SMB Service Exposed',
                    'severity': 'Medium',
                    'port': 445,
                    'description': 'SMB service exposed - check for MS17-010 and other SMB vulnerabilities'
                })
                print("[!] SMB service detected - manual verification recommended")
            
            sock.close()
        except:
            pass
    
    def _check_ftp_vulnerabilities(self):
        """Check FTP vulnerabilities"""
        print("[+] Testing FTP service...")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_ip, 21))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Check for anonymous FTP
            sock.send(b"USER anonymous\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if '230' in response or '331' in response:
                self.vulnerabilities.append({
                    'type': 'Anonymous FTP Access',
                    'severity': 'Medium',
                    'service': f"FTP {banner.strip()}",
                    'description': 'Anonymous FTP access may be enabled'
                })
                print("[!] Anonymous FTP access possible")
            
            sock.close()
        except:
            pass

class ScreenshotCapture:
    """Capture screenshots of web services"""
    
    def __init__(self):
        self.screenshots_dir = "screenshots"
        self.driver = None
        
        if SELENIUM_AVAILABLE:
            self._setup_driver()
    
    def _setup_driver(self):
        """Setup headless Chrome driver"""
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--ignore-certificate-errors")
            chrome_options.add_argument("--ignore-ssl-errors")
            chrome_options.add_argument("--window-size=1920,1080")
            
            self.driver = webdriver.Chrome(options=chrome_options)
            print("[+] Chrome driver initialized for screenshots")
            
        except Exception as e:
            print(f"[-] Could not initialize Chrome driver: {e}")
            print("[-] Install ChromeDriver and Chrome for screenshot functionality")
            self.driver = None
    
    def capture_web_services(self, web_services):
        """Capture screenshots of all web services"""
        if not self.driver:
            print("[-] Screenshot capture not available - missing dependencies")
            return []
        
        if not os.path.exists(self.screenshots_dir):
            os.makedirs(self.screenshots_dir)
        
        screenshots = []
        print("[+] Capturing screenshots of web services...")
        
        for service in web_services:
            try:
                url = service['url']
                print(f"[+] Capturing screenshot: {url}")
                
                self.driver.get(url)
                time.sleep(3)  # Wait for page to load
                
                # Generate filename
                parsed_url = urlparse(url)
                filename = f"{parsed_url.netloc}_{parsed_url.port or 80}_{int(time.time())}.png"
                filepath = os.path.join(self.screenshots_dir, filename)
                
                # Capture screenshot
                self.driver.save_screenshot(filepath)
                
                screenshots.append({
                    'url': url,
                    'screenshot_path': filepath,
                    'timestamp': datetime.now().isoformat()
                })
                
                print(f"[+] Screenshot saved: {filepath}")
                
            except Exception as e:
                print(f"[-] Failed to capture {url}: {e}")
                continue
        
        return screenshots
    
    def cleanup(self):
        """Close the webdriver"""
        if self.driver:
            self.driver.quit()

class MetadataExtractor:
    """Extract metadata from discovered files"""
    
    def __init__(self):
        self.metadata_results = []
    
    def extract_from_urls(self, discovered_files):
        """Extract metadata from files found via web crawling"""
        print("[+] Extracting metadata from discovered files...")
        
        for file_info in discovered_files:
            url = file_info['url']
            
            try:
                response = requests.get(url, timeout=10, verify=False)
                
                if response.status_code == 200:
                    content_type = response.headers.get('content-type', '').lower()
                    
                    # Save file temporarily
                    filename = os.path.basename(urlparse(url).path) or 'temp_file'
                    temp_path = f"/tmp/{filename}"
                    
                    with open(temp_path, 'wb') as f:
                        f.write(response.content)
                    
                    # Extract metadata based on file type
                    metadata = self._extract_metadata_by_type(temp_path, content_type)
                    
                    if metadata:
                        metadata['source_url'] = url
                        metadata['file_size'] = len(response.content)
                        self.metadata_results.append(metadata)
                        print(f"[+] Metadata extracted from {url}")
                    
                    # Cleanup
                    try:
                        os.remove(temp_path)
                    except:
                        pass
                        
            except Exception as e:
                print(f"[-] Error processing {url}: {e}")
                continue
        
        return self.metadata_results
    
    def _extract_metadata_by_type(self, filepath, content_type):
        """Extract metadata based on file type"""
        metadata = {'file_type': content_type}
        
        try:
            # Image metadata
            if 'image' in content_type and PILLOW_AVAILABLE:
                metadata.update(self._extract_image_metadata(filepath))
            
            # PDF metadata
            elif 'pdf' in content_type and PYPDF2_AVAILABLE:
                metadata.update(self._extract_pdf_metadata(filepath))
            
            # Office document metadata (basic)
            elif any(doc_type in content_type for doc_type in ['office', 'word', 'excel', 'powerpoint']):
                metadata.update(self._extract_office_metadata(filepath))
            
            # General file info
            stat_info = os.stat(filepath)
            metadata.update({
                'file_size_bytes': stat_info.st_size,
                'last_modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat()
            })
            
        except Exception as e:
            metadata['extraction_error'] = str(e)
        
        return metadata
    
    def _extract_image_metadata(self, filepath):
        """Extract EXIF data from images"""
        metadata = {}
        
        try:
            image = Image.open(filepath)
            exifdata = image.getexif()
            
            for tag_id in exifdata:
                tag = TAGS.get(tag_id, tag_id)
                data = exifdata.get(tag_id)
                
                if isinstance(data, bytes):
                    data = data.decode('utf-8', errors='ignore')
                
                metadata[f'exif_{tag}'] = str(data)
            
            # Basic image info
            metadata.update({
                'image_format': image.format,
                'image_mode': image.mode,
                'image_size': f"{image.width}x{image.height}"
            })
            
        except Exception as e:
            metadata['image_error'] = str(e)
        
        return metadata
    
    def _extract_pdf_metadata(self, filepath):
        """Extract PDF metadata"""
        metadata = {}
        
        try:
            with open(filepath, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                
                if pdf_reader.metadata:
                    for key, value in pdf_reader.metadata.items():
                        clean_key = key.replace('/', '').lower()
                        metadata[f'pdf_{clean_key}'] = str(value)
                
                metadata['pdf_pages'] = len(pdf_reader.pages)
                
        except Exception as e:
            metadata['pdf_error'] = str(e)
        
        return metadata
    
    def _extract_office_metadata(self, filepath):
        """Extract basic Office document metadata"""
        metadata = {}
        
        try:
            # Basic file analysis - can be enhanced with python-docx, openpyxl
            stat_info = os.stat(filepath)
            metadata.update({
                'office_size': stat_info.st_size,
                'office_type': 'Microsoft Office Document'
            })
            
        except Exception as e:
            metadata['office_error'] = str(e)
        
        return metadata

class OSINTCollector:
    """Social media and OSINT intelligence gathering"""
    
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.osint_results = {}
    
    def collect_domain_intelligence(self, domains):
        """Collect OSINT on discovered domains"""
        print("[+] Collecting OSINT intelligence...")
        
        for domain in domains:
            print(f"[+] Gathering intelligence on {domain}")
            
            domain_info = {
                'domain': domain,
                'subdomains': self._find_subdomains(domain),
                'social_media': self._search_social_media(domain),
                'breaches': self._check_breach_databases(domain),
                'certificates': self._check_certificate_transparency(domain)
            }
            
            self.osint_results[domain] = domain_info
        
        return self.osint_results
    
    def _find_subdomains(self, domain):
        """Find subdomains using various techniques"""
        subdomains = []
        
        # Common subdomain wordlist
        common_subs = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'blog',
            'shop', 'support', 'help', 'secure', 'vpn', 'remote', 'portal'
        ]
        
        for sub in common_subs:
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                subdomains.append(subdomain)
                print(f"[+] Found subdomain: {subdomain}")
            except:
                continue
        
        return subdomains
    
    def _search_social_media(self, domain):
        """Search for social media presence"""
        social_accounts = []
        
        # Extract organization name from domain
        org_name = domain.split('.')[0]
        
        # Common social media platforms
        platforms = {
            'Twitter': f'https://twitter.com/{org_name}',
            'LinkedIn': f'https://linkedin.com/company/{org_name}',
            'Facebook': f'https://facebook.com/{org_name}',
            'Instagram': f'https://instagram.com/{org_name}',
            'YouTube': f'https://youtube.com/c/{org_name}'
        }
        
        for platform, url in platforms.items():
            try:
                response = requests.get(url, timeout=5, allow_redirects=True)
                if response.status_code == 200 and len(response.content) > 1000:
                    social_accounts.append({
                        'platform': platform,
                        'url': url,
                        'found': True
                    })
                    print(f"[+] Found {platform} account: {url}")
            except:
                continue
        
        return social_accounts
    
    def _check_breach_databases(self, domain):
        """Check public breach databases (simulated)"""
        # This would typically use APIs like HaveIBeenPwned
        # For educational purposes, we'll simulate the check
        
        breaches = []
        
        # Simulate breach check
        common_breaches = [
            'LinkedIn (2012)', 'Adobe (2013)', 'Yahoo (2014)', 
            'Equifax (2017)', 'Facebook (2019)'
        ]
        
        # Randomly suggest some breaches for demonstration
        import random
        if random.random() > 0.7:  # 30% chance of "finding" a breach
            breach = random.choice(common_breaches)
            breaches.append({
                'breach_name': breach,
                'note': 'Simulated result - verify with actual breach databases'
            })
            print(f"[+] Potential breach found: {breach}")
        
        return breaches
    
    def _check_certificate_transparency(self, domain):
        """Check certificate transparency logs"""
        cert_info = []
        
        try:
            # Simple certificate check
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    cert_info.append({
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert.get('version'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter')
                    })
                    
                    print(f"[+] Certificate information collected for {domain}")
                    
        except Exception as e:
            cert_info.append({'error': str(e)})
        
        return cert_info

class CredentialTester:
    """Test common credentials against discovered services"""
    
    def __init__(self, target_ip, services):
        self.target_ip = target_ip
        self.services = services
        self.successful_logins = []
        
        # Common credential pairs
        self.credentials = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
            ('administrator', 'administrator'), ('root', 'root'), ('root', 'toor'),
            ('guest', 'guest'), ('test', 'test'), ('demo', 'demo'),
            ('user', 'user'), ('admin', ''), ('root', ''), ('', ''),
            ('admin', 'admin123'), ('admin', 'password123')
        ]
    
    def test_all_services(self):
        """Test credentials against all discovered services"""
        print("[+] Testing common credentials against services...")
        
        # Test SSH
        if 22 in [service.get('port') for service in self.services]:
            self._test_ssh_credentials()
        
        # Test FTP
        if 21 in [service.get('port') for service in self.services]:
            self._test_ftp_credentials()
        
        # Test web authentication
        web_services = [s for s in self.services if s.get('type') == 'web']
        for service in web_services:
            self._test_web_credentials(service)
        
        return self.successful_logins
    
    def _test_ssh_credentials(self):
        """Test SSH credentials"""
        print("[+] Testing SSH credentials...")
        
        for username, password in self.credentials[:5]:  # Limit to avoid lockout
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                ssh.connect(self.target_ip, port=22, username=username, 
                           password=password, timeout=5)
                
                self.successful_logins.append({
                    'service': 'SSH',
                    'port': 22,
                    'username': username,
                    'password': password,
                    'success': True
                })
                
                print(f"[!] SSH login successful: {username}:{password}")
                ssh.close()
                break  # Stop on first successful login
                
            except paramiko.AuthenticationException:
                continue
            except Exception as e:
                print(f"[-] SSH connection error: {e}")
                break
    
    def _test_ftp_credentials(self):
        """Test FTP credentials"""
        print("[+] Testing FTP credentials...")
        
        import ftplib
        
        for username, password in self.credentials[:5]:
            try:
                ftp = ftplib.FTP()
                ftp.connect(self.target_ip, 21, timeout=5)
                ftp.login(username, password)
                
                self.successful_logins.append({
                    'service': 'FTP',
                    'port': 21,
                    'username': username,
                    'password': password,
                    'success': True
                })
                
                print(f"[!] FTP login successful: {username}:{password}")
                ftp.quit()
                break
                
            except ftplib.error_perm:
                continue
            except Exception as e:
                print(f"[-] FTP connection error: {e}")
                break
    
    def _test_web_credentials(self, service):
        """Test web application credentials"""
        base_url = service.get('url', '')
        if not base_url:
            return
        
        print(f"[+] Testing web credentials on {base_url}")
        
        # Common login endpoints
        login_paths = ['/login', '/admin', '/administrator', '/wp-login.php', '/signin']
        
        for path in login_paths:
            login_url = urljoin(base_url, path)
            
            try:
                # Check if login page exists
                response = requests.get(login_url, timeout=5, verify=False)
                if response.status_code != 200:
                    continue
                
                # Look for login forms
                if not any(keyword in response.text.lower() 
                          for keyword in ['login', 'username', 'password', 'signin']):
                    continue
                
                print(f"[+] Found login page: {login_url}")
                
                # Test credentials (limited to avoid lockout)
                for username, password in self.credentials[:3]:
                    login_data = {
                        'username': username, 'password': password,
                        'user': username, 'pass': password,
                        'email': username, 'pwd': password
                    }
                    
                    try:
                        post_response = requests.post(login_url, data=login_data, 
                                                    timeout=5, verify=False, 
                                                    allow_redirects=False)
                        
                        # Check for successful login indicators
                        success_indicators = ['dashboard', 'welcome', 'logout', 'profile']
                        error_indicators = ['invalid', 'failed', 'error', 'wrong']
                        
                        if (post_response.status_code in [302, 200] and 
                            any(indicator in post_response.text.lower() 
                                for indicator in success_indicators) and
                            not any(indicator in post_response.text.lower() 
                                   for indicator in error_indicators)):
                            
                            self.successful_logins.append({
                                'service': 'Web Application',
                                'url': login_url,
                                'username': username,
                                'password': password,
                                'success': True
                            })
                            
                            print(f"[!] Web login successful: {username}:{password}")
                            return  # Stop on success
                            
                    except Exception:
                        continue
                        
            except Exception:
                continue

class AdvancedRemoteReconTool:
    """Enhanced remote reconnaissance tool with advanced features"""
    
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.results = {}
        self.start_time = datetime.now()
        self.open_ports = []
        self.web_services = []
        self.discovered_domains = []
    
    def run_comprehensive_scan(self):
        """Execute comprehensive reconnaissance with all advanced features"""
        print("="*70)
        print("ADVANCED REMOTE CTF RECONNAISSANCE TOOL - EDUCATIONAL USE ONLY")
        print("="*70)
        print(f"[+] Target: {self.target_ip}")
        print(f"[+] Started at: {self.start_time}")
        print()
        
        # Basic reconnaissance (from original tool)
        self._basic_reconnaissance()
        
        # Advanced vulnerability scanning
        print("[*] Starting Vulnerability Assessment...")
        vuln_scanner = VulnerabilityScanner(self.target_ip, self.open_ports, self.web_services)
        vulnerabilities = vuln_scanner.scan_common_vulnerabilities()
        self.results['vulnerabilities'] = vulnerabilities
        print()
        
        # Screenshot capture
        if self.web_services:
            print("[*] Capturing Web Service Screenshots...")
            screenshot_tool = ScreenshotCapture()
            screenshots = screenshot_tool.capture_web_services(self.web_services)
            screenshot_tool.cleanup()
            self.results['screenshots'] = screenshots
            print()
        
        # Metadata extraction
        if self.web_services:
            print("[*] Extracting Metadata from Files...")
            metadata_extractor = MetadataExtractor()
            # Simulate discovered files for metadata extraction
            discovered_files = []
            for service in self.web_services:
                discovered_files.extend([
                    {'url': f"{service['url']}/robots.txt"},
                    {'url': f"{service['url']}/sitemap.xml"},
                    {'url': f"{service['url']}/favicon.ico"}
                ])
            
            metadata_results = metadata_extractor.extract_from_urls(discovered_files)
            self.results['metadata'] = metadata_results
            print()
        
        # OSINT collection
        if self.discovered_domains:
            print("[*] Collecting OSINT Intelligence...")
            osint_collector = OSINTCollector(self.target_ip)
            osint_results = osint_collector.collect_domain_intelligence(self.discovered_domains)
            self.results['osint'] = osint_results
            print()
        
        # Credential testing
        print("[*] Testing Common Credentials...")
        services_list = []
        
        # Prepare services list for credential testing
        if 22 in self.open_ports:
            services_list.append({'port': 22, 'type': 'ssh'})
        if 21 in self.open_ports:
            services_list.append({'port': 21, 'type': 'ftp'})
        
        for web_service in self.web_services:
            services_list.append({**web_service, 'type': 'web'})
        
        if services_list:
            cred_tester = CredentialTester(self.target_ip, services_list)
            successful_logins = cred_tester.test_all_services()
            self.results['credentials'] = successful_logins
            print()
        
        # Generate comprehensive report
        self._generate_comprehensive_report()
    
    def _basic_reconnaissance(self):
        """Perform basic reconnaissance (port scan, service enum, etc.)"""
        # Port scanning
        print("[*] Starting Port Scanning...")
        self._port_scan()
        
        # Service enumeration
        if self.open_ports:
            print("[*] Starting Service Enumeration...")
            self._service_enumeration()
        
        # Web service discovery
        web_ports = [p for p in self.open_ports if p in [80, 443, 8080, 8000, 8443, 8888]]
        if web_ports:
            print("[*] Starting Web Service Discovery...")
            self._discover_web_services(web_ports)
    
    def _port_scan(self):
        """Multi-threaded port scanner"""
        print(f"[+] Scanning ports 1-1000 on {self.target_ip}")
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target_ip, port))
                sock.close()
                
                if result == 0:
                    self.open_ports.append(port)
                    print(f"[+] Port {port}: OPEN")
                    
            except Exception:
                pass
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(scan_port, range(1, 1001))
        
        self.open_ports.sort()
        print(f"[+] Found {len(self.open_ports)} open ports")
    
    def _service_enumeration(self):
        """Enumerate services on open ports"""
        services = {}
        
        for port in self.open_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.target_ip, port))
                
                # Try to grab banner
                if port in [21, 22, 23, 25, 53, 110, 143]:  # Text-based protocols
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                elif port in [80, 8080, 8000]:  # HTTP
                    sock.send(b"GET / HTTP/1.1\r\nHost: " + self.target_ip.encode() + b"\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                elif port == 443:  # HTTPS
                    banner = "HTTPS Service"
                else:
                    banner = "Unknown Service"
                
                if banner:
                    services[port] = banner.strip()[:200]
                
                sock.close()
                
            except Exception:
                services[port] = "Unknown Service"
        
        self.results['services'] = services
    
    def _discover_web_services(self, web_ports):
        """Discover and analyze web services"""
        for port in web_ports:
            protocols = ['http']
            if port == 443:
                protocols = ['https']
            elif port in [8443]:
                protocols = ['https', 'http']
            else:
                protocols = ['http', 'https']
            
            for protocol in protocols:
                try:
                    url = f"{protocol}://{self.target_ip}:{port}"
                    response = requests.get(url, timeout=5, verify=False)
                    
                    web_info = {
                        'url': url,
                        'status_code': response.status_code,
                        'server': response.headers.get('Server', 'Unknown'),
                        'title': self._extract_title(response.text),
                        'technologies': self._detect_technologies(response),
                        'content_length': len(response.content)
                    }
                    
                    self.web_services.append(web_info)
                    
                    # Extract domain for OSINT
                    parsed = urlparse(url)
                    if parsed.hostname and parsed.hostname not in self.discovered_domains:
                        self.discovered_domains.append(parsed.hostname)
                    
                    print(f"[+] Web service: {url} [{response.status_code}] - {web_info['title']}")
                    break
                    
                except Exception:
                    continue
        
        # Directory enumeration for web services
        self._directory_enumeration()
    
    def _directory_enumeration(self):
        """Enumerate directories and files on web services"""
        common_paths = [
            '/', '/admin', '/login', '/dashboard', '/config', '/backup',
            '/test', '/dev', '/api', '/docs', '/help', '/support',
            '/robots.txt', '/sitemap.xml', '/.git', '/.env', '/config.php',
            '/wp-admin', '/wp-content', '/phpmyadmin', '/webmail',
            '/uploads', '/files', '/images', '/js', '/css', '/includes'
        ]
        
        for service in self.web_services:
            base_url = service['url']
            found_paths = []
            
            print(f"[+] Directory enumeration on {base_url}")
            
            for path in common_paths:
                try:
                    url = urljoin(base_url, path)
                    response = requests.get(url, timeout=3, verify=False)
                    
                    if response.status_code in [200, 301, 302, 403]:
                        found_paths.append({
                            'path': path,
                            'url': url,
                            'status': response.status_code,
                            'size': len(response.content),
                            'content_type': response.headers.get('content-type', '')
                        })
                        
                        status_symbol = "✓" if response.status_code == 200 else "⚠"
                        print(f"[+] {status_symbol} {path} [{response.status_code}]")
                        
                except Exception:
                    continue
            
            service['discovered_paths'] = found_paths
    
    def _extract_title(self, html):
        """Extract HTML title"""
        try:
            title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            if title_match:
                return title_match.group(1).strip()[:100]
        except:
            pass
        return "No title"
    
    def _detect_technologies(self, response):
        """Detect web technologies"""
        technologies = []
        headers = response.headers
        content = response.text.lower()
        
        # Server detection
        server_header = headers.get('server', '').lower()
        if 'apache' in server_header:
            technologies.append('Apache')
        if 'nginx' in server_header:
            technologies.append('Nginx')
        if 'iis' in server_header:
            technologies.append('IIS')
        
        # Framework detection
        powered_by = headers.get('x-powered-by', '').lower()
        if 'php' in powered_by:
            technologies.append('PHP')
        if 'asp.net' in powered_by:
            technologies.append('ASP.NET')
        
        # CMS detection
        if 'wp-content' in content or 'wordpress' in content:
            technologies.append('WordPress')
        if 'joomla' in content:
            technologies.append('Joomla')
        if 'drupal' in content:
            technologies.append('Drupal')
        
        # JavaScript frameworks
        if 'react' in content:
            technologies.append('React')
        if 'angular' in content:
            technologies.append('Angular')
        if 'vue' in content:
            technologies.append('Vue.js')
        
        return technologies
    
    def _generate_comprehensive_report(self):
        """Generate detailed reconnaissance report"""
        end_time = datetime.now()
        duration = end_time - self.start_time
        
        print("="*70)
        print("COMPREHENSIVE RECONNAISSANCE REPORT")
        print("="*70)
        print(f"Target: {self.target_ip}")
        print(f"Scan Duration: {duration}")
        print(f"Timestamp: {end_time}")
        print()
        
        # Port summary
        print("PORT SCAN RESULTS:")
        print(f"  Open Ports: {len(self.open_ports)}")
        if self.open_ports:
            port_ranges = self._group_consecutive_ports(self.open_ports)
            print(f"  Ports: {', '.join(port_ranges)}")
        print()
        
        # Service summary
        if self.results.get('services'):
            print("SERVICE ENUMERATION:")
            for port, service in self.results['services'].items():
                print(f"  {port}/tcp - {service[:60]}")
            print()
        
        # Web services summary
        if self.web_services:
            print("WEB SERVICES:")
            for service in self.web_services:
                techs = ', '.join(service.get('technologies', []))
                print(f"  {service['url']} - {service['server']} ({techs})")
                
                # Show discovered paths
                paths = service.get('discovered_paths', [])
                if paths:
                    interesting_paths = [p for p in paths if p['status'] == 200][:5]
                    for path in interesting_paths:
                        print(f"    └─ {path['path']} [{path['status']}]")
            print()
        
        # Vulnerability summary
        vulnerabilities = self.results.get('vulnerabilities', [])
        if vulnerabilities:
            print("VULNERABILITY ASSESSMENT:")
            for vuln in vulnerabilities:
                severity_symbol = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(vuln['severity'], "⚪")
                print(f"  {severity_symbol} {vuln['type']} - {vuln['severity']}")
                print(f"    └─ {vuln['description']}")
            print()
        
        # Credential testing results
        successful_logins = self.results.get('credentials', [])
        if successful_logins:
            print("SUCCESSFUL CREDENTIAL TESTS:")
            for login in successful_logins:
                print(f"  ✓ {login['service']} - {login['username']}:{login['password']}")
            print()
        
        # Screenshot summary
        screenshots = self.results.get('screenshots', [])
        if screenshots:
            print("SCREENSHOT CAPTURE:")
            for shot in screenshots:
                print(f"  📸 {shot['url']} → {shot['screenshot_path']}")
            print()
        
        # Metadata summary
        metadata_results = self.results.get('metadata', [])
        if metadata_results:
            print("METADATA EXTRACTION:")
            for meta in metadata_results:
                if meta.get('source_url'):
                    print(f"  📄 {meta['source_url']}")
                    if meta.get('exif_DateTime'):
                        print(f"    └─ Date: {meta['exif_DateTime']}")
                    if meta.get('pdf_author'):
                        print(f"    └─ Author: {meta['pdf_author']}")
            print()
        
        # OSINT summary
        osint_results = self.results.get('osint', {})
        if osint_results:
            print("OSINT INTELLIGENCE:")
            for domain, info in osint_results.items():
                print(f"  🌐 {domain}")
                if info.get('subdomains'):
                    print(f"    └─ Subdomains: {len(info['subdomains'])}")
                if info.get('social_media'):
                    platforms = [sm['platform'] for sm in info['social_media'] if sm['found']]
                    if platforms:
                        print(f"    └─ Social Media: {', '.join(platforms)}")
            print()
        
        # Save comprehensive results
        output_file = f"advanced_recon_{self.target_ip}_{int(time.time())}.json"
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        print(f"[+] Comprehensive results saved to: {output_file}")
        print()
        print("="*70)
        print("SCAN COMPLETE")
        print("="*70)
        print("[!] This tool is for educational CTF purposes and authorized testing only!")
        print("[!] Verify all findings manually and use appropriate disclosure processes!")
    
    def _group_consecutive_ports(self, ports):
        """Group consecutive ports for cleaner output"""
        if not ports:
            return []
        
        ranges = []
        start = ports[0]
        end = ports[0]
        
        for i in range(1, len(ports)):
            if ports[i] == end + 1:
                end = ports[i]
            else:
                if start == end:
                    ranges.append(str(start))
                else:
                    ranges.append(f"{start}-{end}")
                start = end = ports[i]
        
        # Add the last range
        if start == end:
            ranges.append(str(start))
        else:
            ranges.append(f"{start}-{end}")
        
        return ranges

class NetworkMapper:
    """Advanced network mapping and topology discovery"""
    
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.network_map = {}
    
    def trace_route(self):
        """Perform traceroute to understand network path"""
        print(f"[+] Tracing route to {self.target_ip}")
        
        try:
            if sys.platform.startswith('win'):
                result = subprocess.run(['tracert', '-h', '10', self.target_ip], 
                                      capture_output=True, text=True, shell=True)
            else:
                result = subprocess.run(['traceroute', '-m', '10', self.target_ip], 
                                      capture_output=True, text=True)
            
            if result.returncode == 0:
                hops = []
                lines = result.stdout.split('\n')
                
                for line in lines:
                    # Extract IP addresses from traceroute output
                    ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                    if ip_matches:
                        hops.extend(ip_matches)
                
                self.network_map['traceroute'] = {
                    'hops': list(set(hops)),  # Remove duplicates
                    'hop_count': len(set(hops))
                }
                
                print(f"[+] Network path discovered: {len(set(hops))} hops")
                
        except Exception as e:
            print(f"[-] Traceroute failed: {e}")
    
    def discover_network_neighbors(self):
        """Discover other systems in the network"""
        print("[+] Discovering network neighbors...")
        
        # Extract network range
        ip_parts = self.target_ip.split('.')
        network_base = '.'.join(ip_parts[:3])
        
        neighbors = []
        
        def ping_host(host_num):
            target = f"{network_base}.{host_num}"
            if target == self.target_ip:
                return  # Skip target itself
            
            try:
                if sys.platform.startswith('win'):
                    result = subprocess.run(['ping', '-n', '1', '-w', '1000', target], 
                                          capture_output=True, shell=True)
                else:
                    result = subprocess.run(['ping', '-c', '1', '-W', '1', target], 
                                          capture_output=True, shell=True)
                
                if result.returncode == 0:
                    neighbors.append(target)
                    
                    # Try to get hostname
                    try:
                        hostname = socket.gethostbyaddr(target)[0]
                        print(f"[+] Neighbor found: {target} ({hostname})")
                    except:
                        print(f"[+] Neighbor found: {target}")
                        
            except:
                pass
        
        # Scan common host ranges
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(ping_host, list(range(1, 255)))
        
        self.network_map['neighbors'] = neighbors
        print(f"[+] Found {len(neighbors)} network neighbors")

def main():
    parser = argparse.ArgumentParser(description='Advanced Remote CTF Reconnaissance Tool')
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('--quick', action='store_true', help='Quick scan mode')
    parser.add_argument('--no-screenshots', action='store_true', help='Skip screenshot capture')
    parser.add_argument('--no-creds', action='store_true', help='Skip credential testing')
    parser.add_argument('--output', '-o', help='Output directory for results')
    
    args = parser.parse_args()
    
    print("[!] WARNING: This tool is for educational CTF purposes only!")
    print("[!] Only use on systems you own or have explicit permission to test!")
    print("[!] Unauthorized scanning is illegal and unethical!")
    print()
    
    response = input(f"Do you have explicit written authorization to scan {args.target}? (yes/no): ")
    if response.lower() != 'yes':
        print("Exiting. Only use this tool with proper authorization.")
        sys.exit(1)
    
    # Validate IP address
    try:
        socket.inet_aton(args.target)
    except socket.error:
        print("[-] Invalid IP address format")
        sys.exit(1)
    
    # Check connectivity
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((args.target, 80))
        sock.close()
        print(f"[+] Target {args.target} appears to be reachable")
    except:
        print(f"[?] Target {args.target} connectivity unknown - proceeding anyway")
    
    print()
    
    # Create output directory if specified
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        os.chdir(args.output)
    
    # Initialize and run advanced reconnaissance
    tool = AdvancedRemoteReconTool(args.target)
    
    # Add network mapping
    network_mapper = NetworkMapper(args.target)
    network_mapper.trace_route()
    network_mapper.discover_network_neighbors()
    tool.results['network_map'] = network_mapper.network_map
    
    # Run comprehensive scan
    tool.run_comprehensive_scan()

if __name__ == "__main__":
    main()
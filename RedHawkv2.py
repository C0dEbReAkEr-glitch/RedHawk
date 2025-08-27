#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RedHawk — Advanced CTF Reconnaissance Tool
Educational tool for Capture The Flag competitions and authorized security testing.
"""

import os
import sys
import platform
import subprocess
import socket
import threading
import json
import sqlite3
import base64
import hashlib
import re
import urllib.request
import urllib.parse
import ssl
import argparse
import time
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from typing import List, Dict, Any, Optional
import math

# =========================
# Terminal Colors & Banner
# =========================

class Colors:
    HEADER = '\033[95m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    RED    = '\033[91m'
    ENDC   = '\033[0m'
    BOLD   = '\033[1m'

def print_banner():
    banner = f"""
{Colors.RED}
██████╗ ███████╗██████╗ ██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
██╔══██╗██╔════╝██╔══██╗██║  ██║██╔══██╗██║    ██║██║ ██╔╝
██████╔╝█████╗  ██████╔╝███████║███████║██║ █╗ ██║█████╔╝ 
██╔══██╗██╔══╝  ██╔══██╗██╔══██║██╔══██║██║███╗██║██╔═██╗ 
██║  ██║███████╗██████╔╝██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝
{Colors.ENDC}
{Colors.BOLD}RedHawk — Advanced CTF Recon Tool v2.0{Colors.ENDC}
"""
    print(banner)

# =========================
# System Enumeration
# =========================

class SystemEnum:
    def __init__(self):
        self.results: Dict[str, Any] = {}

    def get_system_info(self) -> Dict[str, Any]:
        print(f"{Colors.HEADER}[*] Gathering System Information{Colors.ENDC}")
        info = {
            'hostname': socket.gethostname(),
            'platform': platform.platform(),
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version()
        }
        if platform.system() == 'Windows':
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
                info['windows_build'] = winreg.QueryValueEx(key, "BuildLab")[0]
                winreg.CloseKey(key)
            except Exception:
                pass
        self.results['system_info'] = info
        return info

    def get_running_processes(self) -> List[Dict[str, Any]]:
        print(f"{Colors.BLUE}[*] Enumerating Running Processes{Colors.ENDC}")
        processes: List[Dict[str, Any]] = []
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['tasklist', '/fo', 'csv'], capture_output=True, text=True)
                lines = result.stdout.strip().splitlines()[1:]
                for line in lines:
                    parts = [p.strip('"') for p in line.split('","')]
                    if len(parts) >= 2:
                        processes.append({'name': parts[0], 'pid': parts[1]})
            else:
                result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
                lines = result.stdout.strip().splitlines()[1:]
                for line in lines:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        processes.append({'user': parts[0], 'pid': parts[1], 'command': parts[10]})
        except Exception as e:
            print(f"{Colors.RED}[-] Error getting processes: {e}{Colors.ENDC}")
        self.results['processes'] = processes
        return processes

    def get_installed_software(self) -> List[Dict[str, Any]]:
        print(f"{Colors.BLUE}[*] Enumerating Installed Software{Colors.ENDC}")
        software: List[Dict[str, Any]] = []
        try:
            if platform.system() == 'Windows':
                import winreg
                key_paths = [
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                ]
                for key_path in key_paths:
                    try:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                        for i in range(winreg.QueryInfoKey(key)[0]):
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                subkey = winreg.OpenKey(key, subkey_name)
                                try:
                                    name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                    version = None
                                    try:
                                        version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                    except Exception:
                                        version = "Unknown"
                                    software.append({'name': name, 'version': version})
                                except Exception:
                                    pass
                                winreg.CloseKey(subkey)
                            except Exception:
                                continue
                        winreg.CloseKey(key)
                    except Exception:
                        continue
            else:
                # Try common Linux/BSD package managers
                candidates = [
                    (['dpkg', '-l'], 'dpkg'),
                    (['rpm', '-qa'], 'rpm'),
                    (['pacman', '-Q'], 'pacman')
                ]
                for cmd, manager in candidates:
                    try:
                        result = subprocess.run(cmd, capture_output=True, text=True)
                        if result.returncode == 0:
                            for ln in result.stdout.splitlines():
                                ln = ln.strip()
                                if not ln:
                                    continue
                                if manager == 'dpkg':
                                    parts = ln.split()
                                    if len(parts) >= 3 and parts[0].startswith('ii'):
                                        software.append({'name': parts[1], 'version': parts[2], 'manager': manager})
                                elif manager == 'rpm':
                                    # name-version-release
                                    software.append({'name': ln, 'version': 'rpm', 'manager': manager})
                                elif manager == 'pacman':
                                    parts = ln.split()
                                    if len(parts) >= 2:
                                        software.append({'name': parts[0], 'version': parts[1], 'manager': manager})
                            break
                    except Exception:
                        continue
        except Exception as e:
            print(f"{Colors.RED}[-] Error getting installed software: {e}{Colors.ENDC}")
        self.results['software'] = software[:100]
        return software[:100]

# =========================
# Network Discovery / Scan
# =========================

class NetworkDiscovery:
    def __init__(self):
        self.results: Dict[str, Any] = {}
        self.common_ports = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1723,3306,3389,5432,5900,6379,8080,27017]

    def get_network_interfaces(self) -> List[Dict[str, Any]]:
        print(f"{Colors.CYAN}[*] Enumerating Network Interfaces{Colors.ENDC}")
        interfaces: List[Dict[str, Any]] = []
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
                interfaces.append({'info': result.stdout})
            else:
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                if result.returncode != 0:
                    result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
                interfaces.append({'info': result.stdout})
        except Exception as e:
            print(f"{Colors.RED}[-] Error getting network interfaces: {e}{Colors.ENDC}")
        self.results['interfaces'] = interfaces
        return interfaces

    def scan_port(self, host: str, port: int, timeout: float=1.0) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def scan_host(self, host: str, ports: Optional[List[int]] = None) -> List[int]:
        if ports is None: ports = self.common_ports
        open_ports: List[int] = []
        print(f"{Colors.YELLOW}[*] Scanning {host}{Colors.ENDC}")
        for port in ports:
            if self.scan_port(host, port):
                open_ports.append(port)
                print(f"{Colors.GREEN}[+] Port {port} open on {host}{Colors.ENDC}")
        return open_ports

    def discover_local_network(self, limit_threads: int = 128, timeout_per_host: float = 1.0) -> List[str]:
        print(f"{Colors.CYAN}[*] Discovering Local Network (simple /24){Colors.ENDC}")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            local_ip = "127.0.0.1"
        base = '.'.join(local_ip.split('.')[:-1]) + '.'
        alive: List[str] = []
        lock = threading.Lock()

        def ping(ip: str):
            try:
                if platform.system() == 'Windows':
                    r = subprocess.run(['ping','-n','1','-w','750', ip], capture_output=True, text=True)
                else:
                    r = subprocess.run(['ping','-c','1','-W','1', ip], capture_output=True, text=True)
                if r.returncode == 0:
                    with lock:
                        alive.append(ip)
                        print(f"{Colors.GREEN}[+] Host {ip} is alive{Colors.ENDC}")
            except Exception:
                pass

        sem = threading.Semaphore(limit_threads)
        threads = []
        for i in range(1, 255):
            ip = base + str(i)
            sem.acquire()
            t = threading.Thread(target=lambda: (ping(ip), sem.release()))
            t.daemon = True
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=timeout_per_host+0.2)
        self.results['alive_hosts'] = alive
        return alive

# =========================
# Credential Harvester (paths only)
# =========================

class CredentialHarvester:
    def __init__(self):
        self.results: Dict[str, Any] = {}

    def find_browser_profiles(self) -> List[Dict[str, str]]:
        print(f"{Colors.YELLOW}[*] Searching for Browser Profiles{Colors.ENDC}")
        profiles: List[Dict[str, str]] = []
        home = Path.home()
        browser_paths = {
            'Chrome': [
                home / 'AppData/Local/Google/Chrome/User Data',
                home / '.config/google-chrome',
                home / 'Library/Application Support/Google/Chrome'
            ],
            'Firefox': [
                home / 'AppData/Roaming/Mozilla/Firefox/Profiles',
                home / '.mozilla/firefox',
                home / 'Library/Application Support/Firefox/Profiles'
            ],
            'Edge': [home / 'AppData/Local/Microsoft/Edge/User Data']
        }
        for browser, paths in browser_paths.items():
            for p in paths:
                if p.exists():
                    profiles.append({'browser': browser, 'path': str(p)})
                    print(f"{Colors.GREEN}[+] Found {browser} profile at {p}{Colors.ENDC}")
        self.results['browser_profiles'] = profiles
        return profiles

    def find_credential_files(self) -> List[str]:
        print(f"{Colors.YELLOW}[*] Searching for Credential Files{Colors.ENDC}")
        cred_files: List[str] = []
        home = Path.home()
        patterns = [
            '.ssh/id_rsa', '.ssh/id_dsa', '.ssh/id_ecdsa', '.ssh/id_ed25519',
            '.aws/credentials', '.aws/config',
            '.docker/config.json',
            '.gitconfig', '.git-credentials',
            '.netrc',
            'Desktop/*.txt', 'Documents/*.txt', 'Downloads/*.txt'
        ]
        for pat in patterns:
            try:
                for f in home.glob(pat):
                    if f.is_file():
                        cred_files.append(str(f))
                        print(f"{Colors.GREEN}[+] Found credential-like file: {f}{Colors.ENDC}")
            except Exception:
                continue
        self.results['credential_files'] = cred_files
        return cred_files

    def check_saved_wifi(self) -> List[Dict[str, str]]:
        print(f"{Colors.YELLOW}[*] Checking Saved WiFi Networks (names only){Colors.ENDC}")
        wifi = []
        if platform.system() == 'Windows':
            try:
                res = subprocess.run(['netsh', 'wlan', 'show', 'profiles'], capture_output=True, text=True)
                for line in res.stdout.splitlines():
                    if 'All User Profile' in line:
                        profile = line.split(':', 1)[1].strip()
                        wifi.append({'name': profile, 'password': 'Hidden'})
                        print(f"{Colors.GREEN}[+] Found WiFi profile: {profile}{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.RED}[-] Error checking WiFi: {e}{Colors.ENDC}")
        self.results['wifi_networks'] = wifi
        return wifi

# =========================
# Advanced Network Enum
# =========================

class AdvancedNetworkEnum:
    def __init__(self):
        self.results: Dict[str, Any] = {}

    def banner_grab(self, host: str, port: int, timeout: float=3.0) -> Optional[str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            if port in (80, 8080):
                sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nUser-Agent: RedHawk\r\n\r\n")
            else:
                try:
                    sock.send(b"\r\n")
                except Exception:
                    pass
            data = b""
            try:
                data = sock.recv(2048)
            except Exception:
                pass
            finally:
                sock.close()
            banner = data.decode('utf-8', errors='ignore').strip()
            return banner if banner else None
        except Exception:
            return None

    def detect_os_via_ttl(self, host: str) -> str:
        try:
            if platform.system() == 'Windows':
                r = subprocess.run(['ping','-n','1', host], capture_output=True, text=True)
            else:
                r = subprocess.run(['ping','-c','1', host], capture_output=True, text=True)
            m = re.search(r'[Tt][Tt][Ll]=(\d+)', r.stdout)
            if m:
                ttl = int(m.group(1))
                if ttl <= 64: return "Linux/Unix"
                if ttl <= 128: return "Windows"
                if ttl <= 255: return "Network Device/Cisco"
            return "Unknown"
        except Exception:
            return "Unknown"

    def scan_udp_ports(self, host: str, ports: List[int] = [53, 69, 123, 161, 162]) -> List[int]:
        open_udp = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1.5)
                # Minimal probes
                if port == 53:
                    # DNS query for example.com A
                    query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
                    sock.sendto(query, (host, port))
                else:
                    sock.sendto(b'\x00', (host, port))
                data, _ = sock.recvfrom(1024)
                if data:
                    open_udp.append(port)
                sock.close()
            except Exception:
                pass
        return open_udp

    def web_technology_detection(self, host: str, port: int=80) -> Dict[str, Any]:
        technologies: Dict[str, Any] = {}
        try:
            protocol = 'https' if port == 443 else 'http'
            url = f"{protocol}://{host}:{port}"
            req = urllib.request.Request(url, headers={'User-Agent': 'RedHawk/1.0'})
            if port == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                resp = urllib.request.urlopen(req, timeout=5, context=ctx)
            else:
                resp = urllib.request.urlopen(req, timeout=5)
            headers = dict(resp.headers)
            body = resp.read(100000).decode('utf-8', errors='ignore')

            for h, v in headers.items():
                hl = h.lower()
                if 'server' in hl:
                    technologies['server'] = v
                if 'x-powered-by' in hl:
                    technologies['framework'] = v
                if 'x-generator' in hl:
                    technologies['cms'] = v

            patterns = {
                'WordPress': r'wp-content|wp-includes|wordpress',
                'Joomla': r'joomla|/components/com_',
                'Drupal': r'drupal|sites/default/files',
                'Django': r'csrf_token|__admin_media_prefix__',
                'Flask': r'flask|werkzeug',
                'PHP': r'\.php|PHPSESSID',
                'ASP.NET': r'__VIEWSTATE',
                'React': r'react|data-reactroot',
                'Angular': r'ng-version|angular',
                'Vue.js': r'vue(\.js)?|data-v-'
            }
            for tech, pat in patterns.items():
                if re.search(pat, body, re.IGNORECASE):
                    technologies[tech] = 'Detected'
        except Exception as e:
            technologies['error'] = str(e)
        return technologies

# =========================
# Memory Analyzer (safe)
# =========================

class MemoryAnalyzer:
    def __init__(self):
        self.results: Dict[str, Any] = {}

    def analyze_process_memory(self, pid: int) -> Dict[str, Any]:
        try:
            if platform.system() == 'Windows':
                return {'status': 'Windows memory inspection not implemented (requires admin & WinAPI)'}
            maps_file = f"/proc/{pid}/maps"
            if not os.path.exists(maps_file):
                return {'error': 'Process not found or not accessible'}
            regions = 0
            with open(maps_file, 'r') as f:
                for line in f:
                    # readable regions include r--p or rw-p (simple check)
                    if 'r--p' in line or 'rw-p' in line:
                        regions += 1
            return {'pid': pid, 'readable_regions': regions}
        except Exception as e:
            return {'error': str(e)}

    def extract_strings_from_memory(self, pid: int, max_items: int = 50) -> List[str]:
        # Intentionally minimal to avoid invasive behavior.
        try:
            if platform.system() != 'Windows':
                if os.path.exists(f"/proc/{pid}/mem"):
                    return ["(Preview suppressed) Memory string extraction requires elevated privileges."]
        except Exception as e:
            return [f"Error: {e}"]
        return []

# =========================
# Crypto Analyzer
# =========================

class CryptoAnalyzer:
    def __init__(self):
        self.results: Dict[str, Any] = {}
        self.hash_len_map = {
            32: ['MD5', 'NTLM'],
            40: ['SHA1'],
            56: ['SHA-224'],
            64: ['SHA-256', 'SHA3-256'],
            96: ['SHA-384'],
            128: ['SHA-512', 'SHA3-512'],
        }

    def identify_hashes(self, text: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for m in re.finditer(r'\b[a-fA-F0-9]{32,128}\b', text):
            h = m.group(0)
            L = len(h)
            if L in self.hash_len_map:
                findings.append({'hash': h, 'length': L, 'possible_types': self.hash_len_map[L]})
        return findings

    def analyze_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = defaultdict(int)
        for b in data:
            freq[b] += 1
        H = 0.0
        n = len(data)
        for c in freq.values():
            p = c / n
            H -= p * math.log2(p)
        return H

    def detect_encoding(self, data: str) -> List[Dict[str, Any]]:
        enc: List[Dict[str, Any]] = []
        s = data.strip()

        # Base64
        try:
            if re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', s) and len(s) % 4 == 0 and len(s) >= 16:
                decoded = base64.b64decode(s, validate=True)
                enc.append({'type': 'Base64', 'decoded_preview': decoded[:80].decode('utf-8', errors='ignore')})
        except Exception:
            pass

        # Hex
        try:
            if re.fullmatch(r'[A-Fa-f0-9]+', s) and len(s) % 2 == 0 and len(s) >= 16:
                decoded = bytes.fromhex(s)
                enc.append({'type': 'Hexadecimal', 'decoded_preview': decoded[:80].decode('utf-8', errors='ignore')})
        except Exception:
            pass

        # URL encoding
        if '%' in s:
            try:
                dec = urllib.parse.unquote(s)
                if dec != s:
                    enc.append({'type': 'URL Encoding', 'decoded_preview': dec[:120]})
            except Exception:
                pass

        return enc

# =========================
# File Crawler
# =========================

class FileCrawler:
    def __init__(self):
        self.results: Dict[str, Any] = {}
        self.interesting_extensions = [
            '.txt','.cfg','.conf','.ini','.env','.yml','.yaml','.json','.xml',
            '.pem','.key','.crt','.p12','.pfx',
            '.log','.sql','.db','.sqlite','.sqlite3',
            '.py','.sh','.ps1','.bat',
            '.csv','.xlsx','.doc','.docx','.pdf',
            '.zip','.7z','.rar'
        ]
        self.sensitive_keywords = [
            'password','passwd','secret','api_key','apikey','token','private_key',
            'credential','login','auth','key','ssh','access_key','client_secret','jwt'
        ]

    def search_files(self, search_paths: Optional[List[Path]] = None, max_files: int = 100) -> List[Dict[str, Any]]:
        print(f"{Colors.CYAN}[*] Crawling for Sensitive Files{Colors.ENDC}")
        if search_paths is None:
            home = Path.home()
            search_paths = [
                home / 'Desktop',
                home / 'Documents',
                home / 'Downloads',
                Path('/tmp') if platform.system() != 'Windows' else Path('C:/temp'),
                Path('/var/log') if platform.system() != 'Windows' else Path('C:/Windows/temp')
            ]
        results: List[Dict[str, Any]] = []
        count = 0
        for base in search_paths:
            if not base.exists():
                continue
            try:
                for p in base.rglob('*'):
                    if count >= max_files: break
                    if not p.is_file(): continue
                    name = p.name.lower()
                    reason = None
                    if any(name.endswith(ext) for ext in self.interesting_extensions):
                        reason = 'interesting_extension'
                    elif any(k in name for k in self.sensitive_keywords):
                        reason = 'sensitive_keyword'
                    if reason:
                        item = {
                            'path': str(p),
                            'size': p.stat().st_size,
                            'modified': datetime.fromtimestamp(p.stat().st_mtime).isoformat(),
                            'reason': reason
                        }
                        results.append(item)
                        print(f"{Colors.GREEN}[+] Found: {p}{Colors.ENDC}")
                        count += 1
            except PermissionError:
                continue
            except Exception as e:
                print(f"{Colors.RED}[-] Error searching {base}: {e}{Colors.ENDC}")
                continue
        self.results['interesting_files'] = results
        return results

    def analyze_file_metadata(self, path: str) -> Dict[str, Any]:
        try:
            p = Path(path)
            st = p.stat()
            return {
                'path': str(p),
                'size': st.st_size,
                'modified': datetime.fromtimestamp(st.st_mtime).isoformat(),
                'created': datetime.fromtimestamp(st.st_ctime).isoformat() if hasattr(st, 'st_ctime') else None
            }
        except Exception as e:
            return {'path': path, 'error': str(e)}

    def search_file_contents(self, file_paths: List[str], keywords: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        if keywords is None:
            keywords = ['password', 'secret', 'api_key', 'token', 'private_key']
        print(f"{Colors.CYAN}[*] Searching File Contents{Colors.ENDC}")
        matches: List[Dict[str, Any]] = []
        for fp in file_paths:
            try:
                p = Path(fp)
                if not p.exists(): continue
                if p.stat().st_size > 10*1024*1024:  # skip >10MB
                    continue
                with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                lower = content.lower()
                for kw in keywords:
                    idx = lower.find(kw.lower())
                    if idx != -1:
                        snippet = content[max(0, idx-80): idx+80]
                        matches.append({'file': str(p), 'keyword': kw, 'snippet': snippet})
                        print(f"{Colors.YELLOW}[+] Found '{kw}' in {p}{Colors.ENDC}")
                        break
            except Exception:
                continue
        self.results['content_matches'] = matches
        return matches

# =========================
# Database Analyzer
# =========================

class DatabaseAnalyzer:
    def __init__(self):
        self.results: Dict[str, Any] = {}

    def find_database_files(self, search_paths: Optional[List[Path]] = None) -> List[Dict[str, Any]]:
        if search_paths is None:
            home = Path.home()
            search_paths = [home, Path('/var/lib'), Path('/opt')] if platform.system() != 'Windows' else [home, Path('C:/')]
        dbs: List[Dict[str, Any]] = []
        exts = ['.db', '.sqlite', '.sqlite3', '.mdb', '.accdb']
        for base in search_paths:
            if not base.exists(): continue
            try:
                for ext in exts:
                    for f in base.rglob(f"*{ext}"):
                        if f.is_file():
                            dbs.append({'path': str(f), 'type': ext.lstrip('.')})
            except Exception:
                continue
        return dbs

    def analyze_sqlite_db(self, db_path: str) -> Dict[str, Any]:
        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [r[0] for r in cur.fetchall()]
            interesting = {}
            for t in tables:
                sensitive = any(k in t.lower() for k in ['user','password','credential','login','account'])
                info = {'sensitive': sensitive}
                try:
                    cur.execute(f"PRAGMA table_info({t})")
                    cols = [r[1] for r in cur.fetchall()]
                    info['columns'] = cols
                    cur.execute(f"SELECT COUNT(*) FROM {t}")
                    info['rows'] = cur.fetchone()[0]
                    if sensitive:
                        cur.execute(f"SELECT * FROM {t} LIMIT 3")
                        rows = cur.fetchall()
                        info['sample_rows'] = len(rows)
                except Exception:
                    pass
                interesting[t] = info
            conn.close()
            return interesting
        except Exception as e:
            return {'error': str(e)}

# =========================
# Log Analyzer
# =========================

class LogAnalyzer:
    def __init__(self):
        self.results: Dict[str, Any] = {}

    def find_log_files(self, roots: Optional[List[Path]] = None, max_files: int = 50) -> List[str]:
        if roots is None:
            roots = [Path('/var/log')] if platform.system() != 'Windows' else [Path('C:/Windows/Logs')]
        logs: List[str] = []
        for base in roots:
            if not base.exists(): continue
            try:
                for f in base.rglob('*.log'):
                    logs.append(str(f))
                    if len(logs) >= max_files: break
            except Exception:
                continue
        return logs

    def analyze_log_file(self, path: str, max_lines: int = 20000) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        patterns = [
            (r'Failed password for .* from ([0-9\.]+)', 'ssh_failed'),
            (r'Accepted password for .* from ([0-9\.]+)', 'ssh_success'),
            (r'sudo: .*authentication failure', 'sudo_fail'),
            (r'error|critical|alert|panic', 'error')
        ]
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    if i > max_lines: break
                    for pat, tag in patterns:
                        if re.search(pat, line, re.IGNORECASE):
                            findings.append({'tag': tag, 'line': line.strip()[:300]})
        except Exception:
            pass
        return findings

# =========================
# Registry Analyzer (Windows)
# =========================

class RegistryAnalyzer:
    def analyze_registry_security(self) -> Dict[str, Any]:
        if platform.system() != 'Windows':
            return {'status': 'Registry analysis available on Windows only'}
        out: Dict[str, Any] = {}
        try:
            import winreg
            # Example checks (hardening indicators)
            checks = [
                (r"SYSTEM\CurrentControlSet\Control\Lsa", "LimitBlankPasswordUse"),
                (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA"),
            ]
            for key_path, value in checks:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                    v, _ = winreg.QueryValueEx(key, value)
                    out[f"{key_path}\\{value}"] = v
                    winreg.CloseKey(key)
                except Exception:
                    out[f"{key_path}\\{value}"] = 'Unknown'
        except Exception as e:
            out['error'] = str(e)
        return out

# =========================
# Artifact Hunter
# =========================

class ArtifactHunter:
    def __init__(self):
        self.ioc_patterns = {
            'ipv4': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
            'url': re.compile(r'https?://[^\s\'"]+'),
            # Common API key formats (very approximate)
            'aws_access_key': re.compile(r'AKIA[0-9A-Z]{16}'),
            'generic_token': re.compile(r'(?i)\b(token|api[_-]?key|secret)\b.{0,20}[:=]\s*[A-Za-z0-9_\-]{16,}'),
        }

    def hunt_in_file(self, path: str, max_read: int = 2_000_000) -> Dict[str, Any]:
        res: Dict[str, Any] = {}
        try:
            p = Path(path)
            if not p.exists() or not p.is_file():
                return {'error': 'File not found'}
            if p.stat().st_size > max_read:
                return {'skipped': 'File too large'}
            with open(p, 'rb') as f:
                data = f.read()
            text = data.decode('utf-8', errors='ignore')
            for name, rgx in self.ioc_patterns.items():
                matches = rgx.findall(text)
                if matches:
                    res[name] = list(set(matches))[:25]
        except Exception as e:
            res['error'] = str(e)
        return res

# =========================
# RedHawk Core
# =========================

class CTFTool:
    """Advanced RedHawk tool that ties all modules together."""
    def __init__(self):
        self.system_enum        = SystemEnum()
        self.network_discovery  = NetworkDiscovery()
        self.advanced_net       = AdvancedNetworkEnum()
        self.credential_harvester = CredentialHarvester()
        self.file_crawler       = FileCrawler()
        self.memory_analyzer    = MemoryAnalyzer()
        self.crypto_analyzer    = CryptoAnalyzer()
        self.db_analyzer        = DatabaseAnalyzer()
        self.log_analyzer       = LogAnalyzer()
        self.registry_analyzer  = RegistryAnalyzer()
        self.artifact_hunter    = ArtifactHunter()
        self.all_results: Dict[str, Any] = {}
        self.interesting_files: List[Dict[str, Any]] = []

    # -------- Advanced Modules --------

    def advanced_network_scan(self, target_hosts: Optional[List[str]] = None) -> Dict[str, Any]:
        print(f"{Colors.CYAN}[*] Advanced Network Scanning{Colors.ENDC}")
        if not target_hosts:
            target_hosts = self.network_discovery.discover_local_network()[:5]
        results: Dict[str, Any] = {}
        for host in target_hosts:
            print(f"{Colors.YELLOW}[*] Advanced scan of {host}{Colors.ENDC}")
            host_info = {
                'os_detection': self.advanced_net.detect_os_via_ttl(host),
                'open_tcp_ports': self.network_discovery.scan_host(host),
                'open_udp_ports': self.advanced_net.scan_udp_ports(host),
                'service_banners': {},
                'web_technologies': {}
            }
            # Banner grabbing (first 10 TCP ports)
            for port in host_info['open_tcp_ports'][:10]:
                banner = self.advanced_net.banner_grab(host, port)
                if banner:
                    host_info['service_banners'][port] = banner[:200]
            # Web tech
            if 80 in host_info['open_tcp_ports']:
                host_info['web_technologies']['http'] = self.advanced_net.web_technology_detection(host, 80)
            if 443 in host_info['open_tcp_ports']:
                host_info['web_technologies']['https'] = self.advanced_net.web_technology_detection(host, 443)
            results[host] = host_info
        return results

    def analyze_system_memory(self) -> Dict[str, Any]:
        print(f"{Colors.YELLOW}[*] Memory Analysis{Colors.ENDC}")
        mem_results: Dict[str, Any] = {}
        processes = self.system_enum.get_running_processes()
        for proc in processes[:10]:
            pid = proc.get('pid')
            if not pid: continue
            try:
                pid_int = int(pid)
            except Exception:
                continue
            info = self.memory_analyzer.analyze_process_memory(pid_int)
            if info and 'error' not in info:
                mem_results[pid] = info
                strings = self.memory_analyzer.extract_strings_from_memory(pid_int)
                if strings:
                    mem_results[pid]['interesting_strings'] = strings[:20]
        return mem_results

    def perform_crypto_analysis(self) -> Dict[str, Any]:
        print(f"{Colors.CYAN}[*] Cryptographic Analysis{Colors.ENDC}")
        crypto_results: Dict[str, Any] = {}
        if hasattr(self, 'interesting_files'):
            for f in self.interesting_files[:20]:
                path = f['path']
                try:
                    with open(path, 'rb') as fh:
                        raw = fh.read(10000)
                    text = raw.decode('utf-8', errors='ignore')
                    hashes = self.crypto_analyzer.identify_hashes(text)
                    encs = self.crypto_analyzer.detect_encoding(text)
                    ent = self.crypto_analyzer.analyze_entropy(raw)
                    if hashes or encs or ent > 7.5:
                        entry: Dict[str, Any] = {}
                        if hashes: entry['hashes'] = hashes
                        if encs: entry['encodings'] = encs
                        if ent > 7.5: entry['high_entropy'] = round(ent, 3)
                        crypto_results[path] = entry
                except Exception:
                    continue
        return crypto_results

    def analyze_databases(self) -> Dict[str, Any]:
        print(f"{Colors.GREEN}[*] Database Analysis{Colors.ENDC}")
        db_files = self.db_analyzer.find_database_files()
        analysis: Dict[str, Any] = {}
        for db in db_files:
            if db['type'] in ['sqlite','sqlite3','db']:
                res = self.db_analyzer.analyze_sqlite_db(db['path'])
                if res and 'error' not in res:
                    analysis[db['path']] = res
        return {'database_files': db_files, 'analysis': analysis}

    def analyze_logs(self) -> Dict[str, Any]:
        print(f"{Colors.RED}[*] Log Analysis{Colors.ENDC}")
        log_files = self.log_analyzer.find_log_files()
        out: Dict[str, Any] = {}
        for lf in log_files[:10]:
            f = self.log_analyzer.analyze_log_file(lf)
            if f:
                out[lf] = f
                print(f"{Colors.YELLOW}[+] Suspicious activity found in {lf}{Colors.ENDC}")
        return out

    def analyze_registry(self) -> Dict[str, Any]:
        print(f"{Colors.BLUE}[*] Registry Analysis{Colors.ENDC}")
        return self.registry_analyzer.analyze_registry_security()

    def hunt_artifacts(self) -> Dict[str, Any]:
        print(f"{Colors.HEADER}[*] Artifact Hunting{Colors.ENDC}")
        results: Dict[str, Any] = {}
        if hasattr(self, 'interesting_files'):
            for f in self.interesting_files[:30]:
                arts = self.artifact_hunter.hunt_in_file(f['path'])
                if arts and 'error' not in arts and arts:
                    results[f['path']] = arts
        return results

    def generate_timeline(self) -> List[Dict[str, Any]]:
        print(f"{Colors.CYAN}[*] Generating Activity Timeline{Colors.ENDC}")
        events: List[Dict[str, Any]] = []
        if hasattr(self, 'interesting_files'):
            for f in self.interesting_files:
                if 'modified' in f:
                    events.append({'timestamp': f['modified'], 'event': 'File Modified', 'details': f['path']})
        events.sort(key=lambda x: x['timestamp'])
        return events[-50:]

    def perform_steganography_check(self) -> Dict[str, Any]:
        print(f"{Colors.YELLOW}[*] Steganography Detection{Colors.ENDC}")
        out: Dict[str, Any] = {}
        img_exts = {'.jpg','.jpeg','.png','.gif','.bmp'}
        if hasattr(self, 'interesting_files'):
            for f in self.interesting_files:
                p = Path(f['path'])
                if p.suffix.lower() in img_exts:
                    try:
                        with open(p, 'rb') as fh:
                            data = fh.read()
                        # Simple ZIP signature detection inside image
                        if b'PK\x03\x04' in data[64:]:
                            out[str(p)] = {'possible_zip_embedded': True}
                        # Entropy check
                        ent = self.crypto_analyzer.analyze_entropy(data)
                        if ent > 7.8:
                            out.setdefault(str(p), {})['high_entropy'] = round(ent, 3)
                        # Suspicious long base64-like substrings
                        b64_like = re.findall(rb'[A-Za-z0-9+/]{20,}={0,2}', data)
                        if len(b64_like) > 10:
                            out.setdefault(str(p), {})['suspicious_strings'] = len(b64_like)
                    except Exception:
                        continue
        return out

    # -------- Orchestration --------

    def run_comprehensive_scan(self):
        print(f"{Colors.BOLD}[*] Starting Comprehensive Advanced Scan{Colors.ENDC}\n")
        # File crawl first; other modules reuse it
        self.interesting_files = self.file_crawler.search_files()

        # System
        self.all_results['system'] = {
            'info': self.system_enum.get_system_info(),
            'processes': self.system_enum.get_running_processes()[:30],
            'software': self.system_enum.get_installed_software()
        }

        # Network
        self.all_results['network'] = {
            'interfaces': self.network_discovery.get_network_interfaces(),
            'basic_discovery': self.network_discovery.discover_local_network(),
            'advanced_scan': self.advanced_network_scan()
        }

        # Memory
        self.all_results['memory'] = self.analyze_system_memory()

        # Credentials
        self.all_results['credentials'] = {
            'browser_profiles': self.credential_harvester.find_browser_profiles(),
            'credential_files': self.credential_harvester.find_credential_files(),
            'wifi_networks': self.credential_harvester.check_saved_wifi()
        }

        # Files
        content_matches = self.file_crawler.search_file_contents([f['path'] for f in self.interesting_files[:20]])
        self.all_results['files'] = {
            'interesting_files': self.interesting_files,
            'content_matches': content_matches,
            'metadata_analysis': [self.file_crawler.analyze_file_metadata(f['path']) for f in self.interesting_files[:10]]
        }

        # Crypto
        self.all_results['crypto'] = self.perform_crypto_analysis()

        # Databases
        self.all_results['databases'] = self.analyze_databases()

        # Logs
        self.all_results['logs'] = self.analyze_logs()

        # Registry
        self.all_results['registry'] = self.analyze_registry()

        # Artifacts
        self.all_results['artifacts'] = self.hunt_artifacts()

        # Timeline
        self.all_results['timeline'] = self.generate_timeline()

        # Steganography
        self.all_results['steganography'] = self.perform_steganography_check()

    # -------- Reports / Export --------

    def assess_risk_level(self, category: str, key: str, value: Any) -> str:
        high_ind = ['password','secret','private_key','api_key','credential','token']
        med_ind  = ['admin','config','database','backup','login']
        k = str(key).lower()
        v = str(value).lower()
        if any(x in k or x in v for x in high_ind): return 'HIGH'
        if any(x in k or x in v for x in med_ind): return 'MEDIUM'
        return 'LOW'

    def get_section_risk_class(self, category: str, data: Any) -> str:
        risk_categories = {
            'credentials': 'high-risk',
            'crypto': 'high-risk',
            'artifacts': 'high-risk',
            'memory': 'medium-risk',
            'registry': 'medium-risk',
            'databases': 'medium-risk'
        }
        return risk_categories.get(category, 'low-risk')

    def generate_html_report(self) -> str:
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>RedHawk Advanced Recon Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f7fb; }}
.header {{ background: #a11; color: #fff; padding: 20px; border-radius: 10px; }}
.section {{ background: #fff; margin: 20px 0; padding: 20px; border-radius: 12px; box-shadow: 0 2px 6px rgba(0,0,0,.06); }}
.high-risk {{ border-left: 6px solid #e74c3c; }}
.medium-risk {{ border-left: 6px solid #f39c12; }}
.low-risk {{ border-left: 6px solid #27ae60; }}
.finding {{ margin: 10px 0; padding: 10px; background: #f0f3f7; border-radius: 8px; }}
pre {{ background: #1f2937; color: #e5e7eb; padding: 10px; border-radius: 8px; overflow-x: auto; }}
h1, h2 {{ margin: 0 0 10px 0; }}
small {{ color: #eee; }}
</style></head><body>
<div class="header">
  <h1>🛡️ RedHawk — Advanced Recon Report</h1>
  <small>Generated on: {ts}</small>
</div>
"""
        for category, data in self.all_results.items():
            if not data:
                continue
            risk_class = self.get_section_risk_class(category, data)
            html += f'<div class="section {risk_class}"><h2>📊 {category.title()} Analysis</h2>'
            if isinstance(data, dict):
                for k, v in data.items():
                    snippet = json.dumps(v, indent=2, default=str)
                    if len(snippet) > 2000:
                        snippet = snippet[:2000] + "...\n(truncated)"
                    html += f'<div class="finding"><strong>{k}:</strong><pre>{snippet}</pre></div>'
            else:
                snippet = json.dumps(data, indent=2, default=str)
                if len(snippet) > 2000:
                    snippet = snippet[:2000] + "...\n(truncated)"
                html += f'<div class="finding"><pre>{snippet}</pre></div>'
            html += '</div>'
        html += "</body></html>"
        return html

    def export_results(self, fmt: str = 'json', filename: Optional[str] = None):
        if not filename:
            filename = f"redhawk_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        try:
            if fmt.lower() == 'json':
                with open(f"{filename}.json", 'w', encoding='utf-8') as f:
                    json.dump(self.all_results, f, indent=2, default=str)
                print(f"{Colors.GREEN}[+] Results exported to {filename}.json{Colors.ENDC}")
            elif fmt.lower() == 'html':
                html = self.generate_html_report()
                with open(f"{filename}.html", 'w', encoding='utf-8') as f:
                    f.write(html)
                print(f"{Colors.GREEN}[+] HTML report generated: {filename}.html{Colors.ENDC}")
            elif fmt.lower() == 'csv':
                import csv
                with open(f"{filename}.csv", 'w', newline='', encoding='utf-8') as f:
                    w = csv.writer(f)
                    w.writerow(['Category','Item','Details','Risk Level'])
                    for cat, data in self.all_results.items():
                        if isinstance(data, dict):
                            for k, v in data.items():
                                risk = self.assess_risk_level(cat, k, v)
                                w.writerow([cat, k, str(v)[:500], risk])
                print(f"{Colors.GREEN}[+] CSV report generated: {filename}.csv{Colors.ENDC}")
            else:
                print(f"{Colors.YELLOW}[!] Unknown export format: {fmt}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}[-] Error exporting results: {e}{Colors.ENDC}")

    def print_advanced_summary(self):
        print(f"\n{Colors.HEADER}{'='*60}")
        print(f"🔍 ADVANCED RECONNAISSANCE SUMMARY")
        print(f"{'='*60}{Colors.ENDC}")

        total_findings = 0
        high_risk_findings = 0

        # System
        if 'system' in self.all_results:
            sysd = self.all_results['system']
            print(f"{Colors.BLUE}🖥️  SYSTEM INTELLIGENCE:{Colors.ENDC}")
            print(f"   • OS: {sysd.get('info', {}).get('platform', 'Unknown')}")
            print(f"   • Processes Analyzed: {len(sysd.get('processes', []))}")
            print(f"   • Software Packages: {len(sysd.get('software', []))}")
            total_findings += len(sysd.get('processes', []))

        # Network
        if 'network' in self.all_results:
            net = self.all_results['network']
            print(f"{Colors.CYAN}🌐 NETWORK INTELLIGENCE:{Colors.ENDC}")
            print(f"   • Live Hosts Discovered: {len(net.get('basic_discovery', []))}")
            print(f"   • Advanced Scans: {len(net.get('advanced_scan', {}))}")
            ports = 0
            for hdata in net.get('advanced_scan', {}).values():
                ports += len(hdata.get('open_tcp_ports', []))
            print(f"   • Total Open Ports: {ports}")
            total_findings += ports

        # Credentials
        if 'credentials' in self.all_results:
            cred = self.all_results['credentials']
            cred_count = len(cred.get('browser_profiles', [])) + len(cred.get('credential_files', [])) + len(cred.get('wifi_networks', []))
            print(f"{Colors.YELLOW}🔐 CREDENTIAL INTELLIGENCE:{Colors.ENDC}")
            print(f"   • Browser Profiles: {len(cred.get('browser_profiles', []))}")
            print(f"   • Credential Files: {len(cred.get('credential_files', []))}")
            print(f"   • WiFi Networks: {len(cred.get('wifi_networks', []))}")
            high_risk_findings += cred_count
            total_findings += cred_count

        # Files
        if 'files' in self.all_results:
            fil = self.all_results['files']
            print(f"{Colors.GREEN}📁 FILE INTELLIGENCE:{Colors.ENDC}")
            print(f"   • Interesting Files: {len(fil.get('interesting_files', []))}")
            print(f"   • Content Matches: {len(fil.get('content_matches', []))}")
            print(f"   • Metadata Analyzed: {len(fil.get('metadata_analysis', []))}")
            total_findings += len(fil.get('interesting_files', []))

        # Crypto
        if 'crypto' in self.all_results:
            c = self.all_results['crypto']
            print(f"{Colors.RED}🔒 CRYPTOGRAPHIC INTELLIGENCE:{Colors.ENDC}")
            print(f"   • Files with Crypto Indicators: {len(c)}")
            high_risk_findings += len([v for v in c.values() if isinstance(v, dict) and ('hashes' in v or 'high_entropy' in v)])

        # Databases
        if 'databases' in self.all_results:
            db = self.all_results['databases']
            print(f"{Colors.HEADER}🗄️  DATABASE INTELLIGENCE:{Colors.ENDC}")
            print(f"   • Database Files Found: {len(db.get('database_files', []))}")
            print(f"   • Databases Analyzed: {len(db.get('analysis', {}))}")

        # Memory
        if 'memory' in self.all_results:
            mem = self.all_results['memory']
            print(f"{Colors.BLUE}🧠 MEMORY INTELLIGENCE:{Colors.ENDC}")
            print(f"   • Processes Analyzed: {len(mem)}")

        # Artifacts
        if 'artifacts' in self.all_results:
            arts = self.all_results['artifacts']
            count = sum(len(v) for v in arts.values() if isinstance(v, dict))
            print(f"{Colors.YELLOW}🔍 ARTIFACT INTELLIGENCE:{Colors.ENDC}")
            print(f"   • Files Hunted: {len(arts)}")
            print(f"   • Artifacts Found: {count}")
            high_risk_findings += count

        # Logs
        if 'logs' in self.all_results:
            logs = self.all_results['logs']
            susp = sum(len(v) for v in logs.values())
            print(f"{Colors.RED}📋 LOG INTELLIGENCE:{Colors.ENDC}")
            print(f"   • Log Files Analyzed: {len(logs)}")
            print(f"   • Suspicious Events: {susp}")
            high_risk_findings += susp

        # Stego
        if 'steganography' in self.all_results:
            stego = self.all_results['steganography']
            print(f"{Colors.CYAN}🖼️  STEGANOGRAPHY DETECTION:{Colors.ENDC}")
            print(f"   • Images Analyzed: {len(stego)}")
            print(f"   • Suspicious Images: {len([v for v in stego.values() if v])}")

        # Risk
        print(f"\n{Colors.HEADER}⚠️  RISK ASSESSMENT:{Colors.ENDC}")
        risk = "HIGH" if high_risk_findings > 10 else ("MEDIUM" if high_risk_findings > 5 else "LOW")
        col = Colors.RED if risk == "HIGH" else (Colors.YELLOW if risk == "MEDIUM" else Colors.GREEN)
        print(f"   • Total Findings: {total_findings}")
        print(f"   • High-Risk Items: {high_risk_findings}")
        print(f"   • Overall Risk Level: {col}{risk}{Colors.ENDC}")

        print(f"\n{Colors.GREEN}✅ Comprehensive scan completed successfully!{Colors.ENDC}")
        print(f"{Colors.BLUE}💡 Use --export json/html/csv to save detailed results{Colors.ENDC}")

# =========================
# CLI
# =========================

def main():
    parser = argparse.ArgumentParser(description='RedHawk — Advanced CTF Recon Tool')
    parser.add_argument('-c', '--comprehensive', action='store_true', help='Run comprehensive advanced scan')
    parser.add_argument('-s', '--system', action='store_true', help='System enumeration')
    parser.add_argument('-n', '--network', action='store_true', help='Network discovery')
    parser.add_argument('--advanced-net', action='store_true', help='Advanced network analysis')
    parser.add_argument('--credentials', action='store_true', help='Credential paths & files')
    parser.add_argument('-f', '--files', action='store_true', help='File crawling')
    parser.add_argument('--memory', action='store_true', help='Memory analysis')
    parser.add_argument('--crypto', action='store_true', help='Cryptographic analysis')
    parser.add_argument('--database', action='store_true', help='Database analysis')
    parser.add_argument('--logs', action='store_true', help='Log analysis')
    parser.add_argument('--registry', action='store_true', help='Registry analysis (Windows)')
    parser.add_argument('--artifacts', action='store_true', help='Artifact hunting (IOCs, keys)')
    parser.add_argument('--steganography', action='store_true', help='Steganography checks (images)')
    parser.add_argument('--export', choices=['json','html','csv'], help='Export format')
    parser.add_argument('-o', '--output', help='Output filename (without extension)')
    parser.add_argument('--host', help='Target host for network scanning')
    args = parser.parse_args()

    print_banner()
    print(f"{Colors.RED}[!] This tool is for educational and authorized testing only!{Colors.ENDC}")
    print(f"{Colors.RED}[!] Only use on systems you own or have explicit permission to test.{Colors.ENDC}")
    print(f"{Colors.YELLOW}[!] Some features may require elevated privileges.{Colors.ENDC}\n")

    tool = CTFTool()

    # Default to comprehensive if nothing selected
    if not any([
        args.comprehensive, args.system, args.network, args.advanced_net,
        args.credentials, args.files, args.memory, args.crypto, args.database,
        args.logs, args.registry, args.artifacts, args.steganography
    ]):
        args.comprehensive = True

    try:
        if args.comprehensive:
            tool.run_comprehensive_scan()
            tool.print_advanced_summary()
        else:
            # Targeted runs
            if args.system:
                tool.system_enum.get_system_info()
                tool.system_enum.get_running_processes()
                tool.system_enum.get_installed_software()

            if args.network:
                tool.network_discovery.get_network_interfaces()
                if args.host:
                    tool.network_discovery.scan_host(args.host)
                else:
                    tool.network_discovery.discover_local_network()

            if args.advanced_net:
                hosts = [args.host] if args.host else None
                adv = tool.advanced_network_scan(hosts)
                print(json.dumps(adv, indent=2, default=str))

            if args.credentials:
                tool.credential_harvester.find_browser_profiles()
                tool.credential_harvester.find_credential_files()
                tool.credential_harvester.check_saved_wifi()

            if args.files:
                tool.interesting_files = tool.file_crawler.search_files()
                tool.file_crawler.search_file_contents([f['path'] for f in tool.interesting_files[:20]])

            if args.memory:
                res = tool.analyze_system_memory()
                print(json.dumps(res, indent=2, default=str))

            if args.crypto:
                # ensure file list
                if not tool.interesting_files:
                    tool.interesting_files = tool.file_crawler.search_files()
                res = tool.perform_crypto_analysis()
                print(json.dumps(res, indent=2, default=str))

            if args.database:
                res = tool.analyze_databases()
                print(json.dumps(res, indent=2, default=str))

            if args.logs:
                res = tool.analyze_logs()
                print(json.dumps(res, indent=2, default=str))

            if args.registry:
                res = tool.analyze_registry()
                print(json.dumps(res, indent=2, default=str))

            if args.artifacts:
                if not tool.interesting_files:
                    tool.interesting_files = tool.file_crawler.search_files()
                res = tool.hunt_artifacts()
                print(json.dumps(res, indent=2, default=str))

            if args.steganography:
                if not tool.interesting_files:
                    tool.interesting_files = tool.file_crawler.search_files()
                res = tool.perform_steganography_check()
                print(json.dumps(res, indent=2, default=str))

        # Export
        if args.export:
            tool.export_results(args.export, args.output)
        elif args.comprehensive:
            # Auto-save JSON for comprehensive run
            tool.export_results('json')
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Interrupted by user{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.RED}[-] Error: {e}{Colors.ENDC}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()

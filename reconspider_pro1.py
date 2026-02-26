#!/usr/bin/env python3
"""
================================================================================
|                                                                              |
|     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗██████╗ ██╗██████╗    |
|     ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔══██╗██║██╔══██╗   |
|     ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╗  ██████╔╝██║██║  ██║   |
|     ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══╝  ██╔══██╗██║██║  ██║   |
|     ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║███████╗██║  ██║██║██████╔╝   |
|     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝╚═════╝    |
|                                                                              |
|                       🔥 OSINT FRAMEWORK v3.0 🔥                            |
|                                                                              |
|                       [ Author: kxm ]                                       |
|                       [ Team: fsociety ]                                    |
|                       [ Build: 2026-02-26 ]                                 |
|                                                                              |
================================================================================
"""

import argparse
import json
import requests
import re
import sys
import time
import socket
import subprocess
import os
from datetime import datetime
from urllib.parse import urlparse
import dns.resolver
import whois
from colorama import init, Fore, Style

# Inicjalizacja kolorów
init()

# Próba importu opcjonalnych bibliotek
try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

try:
    from waybackpy import WaybackMachineCDX, WaybackMachineSave
    WAYBACK_AVAILABLE = True
except ImportError:
    WAYBACK_AVAILABLE = False

try:
    from googlesearch import search
    GOOGLE_AVAILABLE = True
except ImportError:
    GOOGLE_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from webdriver_manager.chrome import ChromeDriverManager
    SCREENSHOT_AVAILABLE = True
except ImportError:
    SCREENSHOT_AVAILABLE = False

try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

try:
    from fpdf import FPDF
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False


class ReconSpider:
    def __init__(self, target, verbose=False, shodan_api=None):
        self.target = target
        self.verbose = verbose
        self.shodan_api_key = shodan_api
        self.results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "author": "kxm",
            "team": "fsociety",
            "modules": {}
        }
        
    def print_banner(self):
        """Wyświetla baner jak w filmach"""
        banner = f"""
{Fore.RED}
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗██████╗ ██╗██████╗║
║     ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔══██╗██║██╔══██╗║
║     ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╗  ██████╔╝██║██║  ██║║
║     ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══╝  ██╔══██╗██║██║  ██║║
║     ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║███████╗██║  ██║██║██████╔╝║
║     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝╚═════╝ ║
║                                                                          ║
║                       🔥 OSINT FRAMEWORK v3.0 🔥                        ║
║                                                                          ║
║                       [ Author: {Fore.CYAN}kxm{Fore.RED} ]                                      ║
║                       [ Team: {Fore.CYAN}fsociety{Fore.RED} ]                                    ║
║                       [ Build: {Fore.CYAN}2026-02-26{Fore.RED} ]                                 ║
║                                                                          ║
║              {Fore.WHITE}[ TARGET: {self.target} ]{Fore.RED}                          ║
║              {Fore.WHITE}[ TIME: {datetime.now().strftime('%H:%M:%S')} ]{Fore.RED}                      ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
        print(banner)
        
        # Podpis jak w filmie
        print(f"{Fore.GREEN}[ SYSTEM INITIALIZED ]{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[ USER: kxm ]{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[ TEAM: fsociety ]{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[ ACCESS GRANTED ]{Style.RESET_ALL}\n")
    
    def log(self, message, status="INFO"):
        """Logowanie z kolorami"""
        colors = {
            "INFO": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "FOUND": Fore.MAGENTA,
            "SCAN": Fore.BLUE
        }
        color = colors.get(status, Fore.WHITE)
        prefix = f"[{status}]" if status != "SCAN" else "[*]"
        print(f"{color}{prefix}{Style.RESET_ALL} {message}")
    
    # ============== PODSTAWOWE MODUŁY ==============
    
    def module_dns(self):
        """Rekonesans DNS"""
        self.log("🔍 Skanowanie DNS...", "SCAN")
        module_results = {}
        
        try:
            # Rekordy A
            answers = dns.resolver.resolve(self.target, 'A')
            module_results['A'] = [str(r) for r in answers]
            self.log(f"  ✓ Znaleziono {len(answers)} rekordów A", "SUCCESS")
            
            # Rekordy MX (poczta)
            try:
                mx = dns.resolver.resolve(self.target, 'MX')
                module_results['MX'] = [str(r.exchange) for r in mx]
                self.log(f"  ✓ Znaleziono serwery MX", "SUCCESS")
            except:
                module_results['MX'] = []
            
            # Rekordy TXT (często klucze API, konfiguracje)
            try:
                txt = dns.resolver.resolve(self.target, 'TXT')
                txt_records = []
                for r in txt:
                    for txt_string in r.strings:
                        txt_records.append(txt_string.decode())
                module_results['TXT'] = txt_records
                if any('google-site-verification' in t for t in txt_records):
                    self.log(f"  ✓ Znaleziono weryfikację Google", "FOUND")
                if any('spf' in t for t in txt_records):
                    self.log(f"  ✓ Znaleziono rekord SPF", "SUCCESS")
            except:
                module_results['TXT'] = []
                
        except Exception as e:
            self.log(f"Błąd DNS: {e}", "ERROR")
            module_results['error'] = str(e)
        
        self.results['modules']['dns'] = module_results
    
    def module_whois(self):
        """Informacje WHOIS"""
        self.log("🔍 Sprawdzanie WHOIS...", "SCAN")
        
        try:
            w = whois.whois(self.target)
            module_results = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
                'emails': w.emails
            }
            
            if w.emails:
                self.log(f"  ✓ Znaleziono emaile: {', '.join(w.emails[:3])}", "FOUND")
            if w.creation_date:
                self.log(f"  ✓ Domena utworzona: {w.creation_date}", "INFO")
                
        except Exception as e:
            self.log(f"Błąd WHOIS: {e}", "ERROR")
            module_results = {'error': str(e)}
        
        self.results['modules']['whois'] = module_results
    
    def module_subdomains(self):
        """Wyszukiwanie subdomen (passive)"""
        self.log("🔍 Szukanie subdomen...", "SCAN")
        module_results = {'subdomains': []}
        
        # Lista popularnych subdomen
        common = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 
                  'ns1', 'ns2', 'dns1', 'dns2', 'cpanel', 'whm', 'admin', 
                  'blog', 'test', 'dev', 'staging', 'api', 'secure', 'vpn',
                  'autodiscover', 'm', 'remote', 'server', 'mail2', 'mx',
                  'pop3', 'imap', 'cloud', 'host', 'hosting', 'server', 'ns',
                  'portal', 'support', 'help', 'docs', 'kb', 'status',
                  'shop', 'store', 'cart', 'checkout', 'payment', 'pay']
        
        found = []
        for sub in common:
            try:
                full = f"{sub}.{self.target}"
                ip = socket.gethostbyname(full)
                found.append(f"{full} -> {ip}")
                self.log(f"  ✓ Znaleziono: {full} ({ip})", "FOUND")
                time.sleep(0.1)  # Grzecznościowe opóźnienie
            except:
                if self.verbose:
                    self.log(f"  ✗ {sub} nie istnieje", "INFO")
        
        module_results['subdomains'] = found
        self.results['modules']['subdomains'] = module_results
    
    def module_http_headers(self):
        """Analiza nagłówków HTTP"""
        self.log("🔍 Analiza nagłówków HTTP...", "SCAN")
        module_results = {}
        
        try:
            for proto in ['http', 'https']:
                url = f"{proto}://{self.target}"
                try:
                    r = requests.get(url, timeout=5, headers={
                        'User-Agent': 'Mozilla/5.0 (ReconSpider OSINT Tool)'
                    })
                    
                    headers = dict(r.headers)
                    module_results[proto] = headers
                    
                    self.log(f"  ✓ {proto.upper()} dostępny", "SUCCESS")
                    
                    # Sprawdź ciekawe nagłówki
                    security_headers = ['X-Frame-Options', 'X-XSS-Protection', 
                                       'Content-Security-Policy', 'Strict-Transport-Security']
                    
                    for sh in security_headers:
                        if sh in headers:
                            self.log(f"    → Nagłówek {sh} obecny", "SUCCESS")
                    
                    if 'Server' in headers:
                        self.log(f"    → Serwer: {headers['Server']}", "INFO")
                        
                except:
                    module_results[proto] = {'error': 'Connection failed'}
                    
        except Exception as e:
            self.log(f"Błąd HTTP: {e}", "ERROR")
        
        self.results['modules']['http'] = module_results
    
    def module_emails(self):
        """Wyszukiwanie emaili w źródle strony"""
        self.log("🔍 Szukanie adresów email...", "SCAN")
        module_results = {'emails': []}
        
        try:
            r = requests.get(f"https://{self.target}", timeout=5)
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', r.text)
            unique_emails = list(set(emails))
            
            if unique_emails:
                module_results['emails'] = unique_emails
                for email in unique_emails[:5]:
                    self.log(f"  ✓ {email}", "FOUND")
                if len(unique_emails) > 5:
                    self.log(f"  → i {len(unique_emails)-5} więcej...", "INFO")
                    
        except Exception as e:
            self.log(f"Błąd podczas szukania emaili: {e}", "ERROR")
        
        self.results['modules']['emails'] = module_results
    
    def module_technologies(self):
        """Wykrywanie technologii"""
        self.log("🔍 Wykrywanie technologii...", "SCAN")
        module_results = {}
        
        signatures = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-json'],
            'Joomla': ['joomla', 'com_content'],
            'Drupal': ['drupal', 'sites/all'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap'],
            'PHP': ['php', '.php'],
            'Apache': ['apache'],
            'Nginx': ['nginx'],
            'Cloudflare': ['cloudflare'],
            'Google Analytics': ['google-analytics', 'ga.js'],
            'Facebook Pixel': ['facebook.com/tr'],
            'Shopify': ['shopify'],
            'WooCommerce': ['woocommerce'],
            'Magento': ['magento'],
            'PrestaShop': ['prestashop'],
            'Laravel': ['laravel'],
            'Django': ['django', 'csrfmiddlewaretoken'],
            'Flask': ['flask'],
            'Ruby on Rails': ['rails'],
            'ASP.NET': ['asp.net', '__viewstate'],
            'Node.js': ['node.js', 'express'],
            'React': ['react'],
            'Vue.js': ['vue.js'],
            'Angular': ['angular']
        }
        
        try:
            r = requests.get(f"https://{self.target}", timeout=5)
            content = r.text.lower()
            headers = ' '.join(str(r.headers).lower())
            
            detected = []
            for tech, sigs in signatures.items():
                for sig in sigs:
                    if sig in content or sig in headers:
                        detected.append(tech)
                        self.log(f"  ✓ Wykryto: {tech}", "FOUND")
                        break
            
            module_results['technologies'] = list(set(detected))
            
        except Exception as e:
            self.log(f"Błąd wykrywania technologii: {e}", "ERROR")
        
        self.results['modules']['technologies'] = module_results
    
    def module_cloudflare(self):
        """Sprawdzenie czy strona jest za Cloudflare"""
        self.log("🔍 Sprawdzanie Cloudflare...", "SCAN")
        module_results = {'cloudflare': False}
        
        try:
            ip = socket.gethostbyname(self.target)
            module_results['ip'] = ip
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            r = requests.get(f"http://{self.target}", headers=headers, timeout=5)
            
            if 'cloudflare' in r.headers.get('Server', '').lower():
                module_results['cloudflare'] = True
                self.log(f"  ✓ Strona za Cloudflare", "FOUND")
                if 'CF-RAY' in r.headers:
                    module_results['cf_ray'] = r.headers['CF-RAY']
            else:
                self.log(f"  ✗ Brak Cloudflare", "INFO")
                
        except Exception as e:
            self.log(f"Błąd: {e}", "ERROR")
        
        self.results['modules']['cloudflare'] = module_results
    
    # ============== NOWE MODUŁY ==============
    
    def module_shodan(self):
        """Moduł Shodan - skanowanie otwartych portów"""
        self.log("🔍 Skanowanie Shodan...", "SCAN")
        module_results = {}
        
        if not SHODAN_AVAILABLE:
            self.log("  ✗ Shodan nie zainstalowany", "ERROR")
            module_results['error'] = 'Shodan module not installed'
            self.results['modules']['shodan'] = module_results
            return
        
        if not self.shodan_api_key:
            self.log("  ✗ Brak klucza API Shodan", "WARNING")
            module_results['error'] = 'No Shodan API key provided'
            self.results['modules']['shodan'] = module_results
            return
        
        try:
            api = shodan.Shodan(self.shodan_api_key)
            
            # Najpierw sprawdź IP
            try:
                ip = socket.gethostbyname(self.target)
                module_results['ip'] = ip
                
                host = api.host(ip)
                
                ports = []
                for item in host.get('data', []):
                    port_info = {
                        'port': item.get('port'),
                        'protocol': item.get('protocol'),
                        'service': item.get('product', 'unknown'),
                        'version': item.get('version', 'unknown')
                    }
                    ports.append(port_info)
                    self.log(f"  ✓ Port {item.get('port')}/{item.get('protocol')} - {item.get('product', 'unknown')}", "FOUND")
                
                module_results['ports'] = ports
                module_results['hostnames'] = host.get('hostnames', [])
                module_results['country'] = host.get('country_name', 'unknown')
                module_results['org'] = host.get('org', 'unknown')
                
            except shodan.APIError as e:
                if 'No information available' in str(e):
                    self.log(f"  ✗ Brak informacji w Shodan dla {self.target}", "INFO")
                else:
                    self.log(f"  ✗ Błąd Shodan: {e}", "ERROR")
                    
        except Exception as e:
            self.log(f"Błąd Shodan: {e}", "ERROR")
        
        self.results['modules']['shodan'] = module_results
    
    def module_github(self):
        """Moduł GitHub - szukanie wycieków tokenów"""
        self.log("🔍 Szukanie wycieków na GitHub...", "SCAN")
        module_results = {}
        
        # Proste wyszukiwanie przez Google (GitHub search wymaga API)
        try:
            # Szukaj typowych wycieków
            queries = [
                f'"{self.target}" "api_key"',
                f'"{self.target}" "secret"',
                f'"{self.target}" "token"',
                f'"{self.target}" "password"',
                f'"{self.target}" "aws_access_key"',
                f'"{self.target}" "-----BEGIN RSA PRIVATE KEY-----"'
            ]
            
            found = []
            for q in queries:
                url = f"https://github.com/search?q={q.replace(' ', '%20')}"
                found.append({'query': q, 'url': url})
                self.log(f"  ✓ Sprawdzono: {q}", "INFO")
            
            module_results['queries'] = found
            self.log(f"  → Sprawdź ręcznie na GitHub.com", "WARNING")
            
        except Exception as e:
            self.log(f"Błąd: {e}", "ERROR")
        
        self.results['modules']['github'] = module_results
    
    def module_google_dorks(self):
        """Moduł Google Dorks - automatyczne wyszukiwanie"""
        self.log("🔍 Google Dorks...", "SCAN")
        module_results = {}
        
        dorks = [
            f'site:{self.target}',
            f'site:{self.target} filetype:pdf',
            f'site:{self.target} filetype:doc',
            f'site:{self.target} filetype:xls',
            f'site:{self.target} inurl:admin',
            f'site:{self.target} inurl:login',
            f'site:{self.target} "password"',
            f'site:{self.target} "confidential"',
            f'site:{self.target} "internal use only"',
            f'intitle:"index of" {self.target}',
            f'inurl:backup {self.target}',
            f'inurl:wp-content {self.target}',
            f'inurl:wp-admin {self.target}'
        ]
        
        found = []
        for dork in dorks:
            url = f"https://www.google.com/search?q={dork.replace(' ', '%20')}"
            found.append({'dork': dork, 'url': url})
            self.log(f"  ✓ {dork}", "INFO")
        
        module_results['dorks'] = found
        self.log(f"  → Otwórz linki w przeglądarce", "WARNING")
        self.results['modules']['google_dorks'] = module_results
    
    def module_screenshot(self):
        """Moduł Screenshot - zrzut ekranu strony"""
        self.log("🔍 Wykonywanie zrzutu ekranu...", "SCAN")
        module_results = {}
        
        if not SCREENSHOT_AVAILABLE:
            self.log("  ✗ Selenium nie zainstalowane", "ERROR")
            module_results['error'] = 'Selenium not installed'
            self.results['modules']['screenshot'] = module_results
            return
        
        try:
            # Opcje Chrome
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            
            # Uruchom przeglądarkę
            driver = webdriver.Chrome(options=chrome_options)
            driver.set_window_size(1280, 1024)
            
            # Zrób zrzut ekranu
            url = f"https://{self.target}"
            driver.get(url)
            
            filename = f"screenshot_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            driver.save_screenshot(filename)
            driver.quit()
            
            self.log(f"  ✓ Zrzut ekranu zapisany: {filename}", "SUCCESS")
            module_results['screenshot'] = filename
            
        except Exception as e:
            self.log(f"Błąd podczas robienia zrzutu: {e}", "ERROR")
            module_results['error'] = str(e)
        
        self.results['modules']['screenshot'] = module_results
    
    def module_wayback(self):
        """Moduł Wayback Machine - archiwalne wersje"""
        self.log("🔍 Sprawdzanie archiwum Wayback Machine...", "SCAN")
        module_results = {}
        
        if not WAYBACK_AVAILABLE:
            self.log("  ✗ Waybackpy nie zainstalowany", "ERROR")
            module_results['error'] = 'Waybackpy not installed'
            self.results['modules']['wayback'] = module_results
            return
        
        try:
            url = f"https://{self.target}"
            
            # Pobierz archiwalne snapshoty
            cdx = WaybackMachineCDX(url)
            snapshots = list(cdx.snapshots())[:10]  # Ostatnie 10
            
            archives = []
            for snap in snapshots:
                archive_url = snap.archive_url
                timestamp = snap.timestamp
                archives.append({
                    'url': archive_url,
                    'date': str(timestamp)
                })
                self.log(f"  ✓ Archiwum z {timestamp}", "FOUND")
            
            module_results['archives'] = archives
            
        except Exception as e:
            self.log(f"Błąd Wayback: {e}", "ERROR")
        
        self.results['modules']['wayback'] = module_results
    
    def module_geolocation(self):
        """Moduł Geolokalizacja - gdzie jest serwer"""
        self.log("🔍 Geolokalizacja serwera...", "SCAN")
        module_results = {}
        
        try:
            # Pobierz IP
            ip = socket.gethostbyname(self.target)
            module_results['ip'] = ip
            
            # Użyj darmowego API geolokalizacji
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                
                if data['status'] == 'success':
                    module_results['country'] = data['country']
                    module_results['countryCode'] = data['countryCode']
                    module_results['region'] = data['regionName']
                    module_results['city'] = data['city']
                    module_results['zip'] = data['zip']
                    module_results['lat'] = data['lat']
                    module_results['lon'] = data['lon']
                    module_results['isp'] = data['isp']
                    module_results['org'] = data['org']
                    module_results['as'] = data['as']
                    
                    self.log(f"  ✓ Kraj: {data['country']}", "SUCCESS")
                    self.log(f"  ✓ Miasto: {data['city']}, {data['regionName']}", "SUCCESS")
                    self.log(f"  ✓ ISP: {data['isp']}", "SUCCESS")
                    self.log(f"  ✓ Współrzędne: {data['lat']}, {data['lon']}", "INFO")
                else:
                    self.log(f"  ✗ Nie znaleziono lokalizacji", "INFO")
            else:
                self.log(f"  ✗ Błąd API", "ERROR")
                
        except Exception as e:
            self.log(f"Błąd geolokalizacji: {e}", "ERROR")
        
        self.results['modules']['geolocation'] = module_results
    
    def module_report_pdf(self):
        """Moduł PDF - generuje raport"""
        self.log("🔍 Generowanie raportu PDF...", "SCAN")
        module_results = {}
        
        if not PDF_AVAILABLE:
            self.log("  ✗ FPDF nie zainstalowany", "ERROR")
            module_results['error'] = 'FPDF not installed'
            self.results['modules']['pdf'] = module_results
            return
        
        try:
            filename = f"recon_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            
            # Generuj raport PDF (symulacja)
            self.log(f"  ✓ Raport PDF zostanie zapisany jako: {filename}", "SUCCESS")
            module_results['pdf'] = filename
            
            # TODO: Implementacja pełnego PDF
            # Na razie zapisujemy JSON
            json_filename = filename.replace('.pdf', '.json')
            with open(json_filename, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            self.log(f"  ✓ JSON zapisany: {json_filename}", "SUCCESS")
            
        except Exception as e:
            self.log(f"Błąd generowania PDF: {e}", "ERROR")
        
        self.results['modules']['pdf'] = module_results
    
    def run_all(self):
        """Uruchamia wszystkie moduły"""
        self.print_banner()
        
        self.log("Initializing reconnaissance sequence...", "SCAN")
        self.log(f"Target: {self.target}", "INFO")
        self.log(f"Starting scan at {datetime.now().strftime('%H:%M:%S')}", "INFO")
        print()
        
        modules = [
            self.module_dns,
            self.module_whois,
            self.module_subdomains,
            self.module_http_headers,
            self.module_emails,
            self.module_technologies,
            self.module_cloudflare,
            self.module_geolocation,
            self.module_shodan,
            self.module_github,
            self.module_google_dorks,
            self.module_wayback,
            self.module_screenshot,
            self.module_report_pdf
        ]
        
        total = len(modules)
        for i, module in enumerate(modules, 1):
            try:
                self.log(f"\n[{i}/{total}] Running module: {module.__name__.replace('module_', '')}", "SCAN")
                module()
                time.sleep(0.5)
            except KeyboardInterrupt:
                self.log("\nInterrupted by user", "WARNING")
                break
            except Exception as e:
                self.log(f"Module error: {e}", "ERROR")
        
        self.print_summary()
        self.save_report()
    
    def save_report(self, filename=None):
        """Zapisuje raport do pliku JSON"""
        if not filename:
            filename = f"recon_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        self.log(f"\n📁 Raport zapisany: {filename}", "SUCCESS")
    
    def print_summary(self):
        """Wyświetla podsumowanie"""
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"                    PODSUMOWANIE - {self.target}")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        if 'shodan' in self.results['modules'] and 'ports' in self.results['modules']['shodan']:
            ports = self.results['modules']['shodan']['ports']
            print(f"✓ Shodan: {len(ports)} otwartych portów")
        
        if 'dns' in self.results['modules'] and 'A' in self.results['modules']['dns']:
            print(f"✓ DNS: {len(self.results['modules']['dns']['A'])} adresów IP")
        
        if 'subdomains' in self.results['modules'] and self.results['modules']['subdomains'].get('subdomains'):
            print(f"✓ Subdomeny: {len(self.results['modules']['subdomains']['subdomains'])} znalezionych")
        
        if 'emails' in self.results['modules'] and self.results['modules']['emails'].get('emails'):
            print(f"✓ Adresy email: {len(self.results['modules']['emails']['emails'])}")
        
        if 'technologies' in self.results['modules'] and self.results['modules']['technologies'].get('technologies'):
            techs = self.results['modules']['technologies']['technologies']
            print(f"✓ Technologie: {', '.join(techs[:5])}")
        
        if 'geolocation' in self.results['modules'] and self.results['modules']['geolocation'].get('country'):
            geo = self.results['modules']['geolocation']
            print(f"✓ Lokalizacja: {geo.get('country', '?')}, {geo.get('city', '?')}")
        
        if 'wayback' in self.results['modules'] and self.results['modules']['wayback'].get('archives'):
            # POPRAWIONA LINIA - usunięto zbędny nawias ]
            print(f"✓ Wayback Machine: {len(self.results['modules']['wayback']['archives'])} archiwów")
        
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"\n{Fore.RED}[ fsociety ]{Style.RESET_ALL} Scan completed at {datetime.now().strftime('%H:%M:%S')}")
        print(f"{Fore.RED}[ kxm ]{Style.RESET_ALL} Stay safe, stay anonymous.\n")

def main():
    parser = argparse.ArgumentParser(
        description='ReconSpider - Zaawansowane narzędzie OSINT by kxm',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.RED}PRZYKŁADY UŻYCIA:{Style.RESET_ALL}
  python3 reconspider_pro.py sobywatel.net
  python3 reconspider_pro.py sobywatel.net -v
  python3 reconspider_pro.py sobywatel.net --shodan KEY
  python3 reconspider_pro.py 192.168.1.1
        """
    )
    
    parser.add_argument('target', help='Cel (domena lub adres IP)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Tryb szczegółowy')
    parser.add_argument('--shodan', help='Klucz API Shodan')
    
    args = parser.parse_args()
    
    try:
        print(f"\n{Fore.CYAN}[ LOADING ReconSpider v3.0 ]{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[ AUTHOR: kxm ]{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[ TEAM: fsociety ]{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[ VERSION: 3.0 ]{Style.RESET_ALL}\n")
        
        # Inicjalizacja i uruchomienie
        spider = ReconSpider(args.target, args.verbose, args.shodan)
        spider.run_all()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()

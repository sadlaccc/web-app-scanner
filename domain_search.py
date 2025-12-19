import streamlit as st
import dns.resolver
import socket
import requests
import ssl
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import time
import re
import ipaddress
from bs4 import BeautifulSoup
import whois
import nmap

# Common subdomains to check
COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'blog', 'shop', 'app',
    'secure', 'portal', 'login', 'remote', 'vpn', 'webmail', 'cpanel', 'whm',
    'autodiscover', 'owa', 'exchange', 'm', 'mobile', 'staging', 'beta', 'demo',
    'support', 'help', 'docs', 'wiki', 'forum', 'community', 'news', 'store',
    'download', 'upload', 'files', 'images', 'cdn', 'static', 'assets', 'media',
    'video', 'audio', 'stream', 'live', 'chat', 'status', 'monitor', 'logs',
    'backup', 'db', 'database', 'sql', 'mysql', 'postgres', 'redis', 'mongo',
    'jenkins', 'gitlab', 'github', 'bitbucket', 'jira', 'confluence', 'slack',
    'teams', 'zoom', 'meet', 'webex', 'gotomeeting', 'outlook', 'gmail',
    'drive', 'docs', 'sheets', 'slides', 'calendar', 'photos', 'maps', 'search',
    'translate', 'youtube', 'vimeo', 'twitch', 'netflix', 'hulu', 'amazon',
    'ebay', 'paypal', 'stripe', 'shopify', 'wordpress', 'drupal', 'joomla',
    'magento', 'prestashop', 'opencart', 'woocommerce', 'bigcommerce', 'squarespace',
    'wix', 'weebly', 'godaddy', 'hostgator', 'bluehost', 'siteground', 'dreamhost',
    'aws', 'azure', 'gcp', 'heroku', 'digitalocean', 'linode', 'vultr', 'ovh',
]

def generate_additional_subdomains(base_list):
    """Generate additional subdomains using common patterns."""
    additional = set()
    
    # Add numbered variations
    for sub in base_list[:20]:  # Only for first 20 to avoid explosion
        for num in ['01', '1', '2', '3', 'dev', 'test', 'staging', 'prod']:
            additional.add(f"{sub}{num}")
            additional.add(f"{num}{sub}")
    
    # Add common prefixes
    prefixes = ['dev-', 'test-', 'staging-', 'prod-', 'api-', 'app-', 'web-', 'admin-', 'secure-', 'ssl-']
    for prefix in prefixes:
        for sub in base_list[:30]:
            additional.add(f"{prefix}{sub}")
    
    # Add common suffixes
    suffixes = ['-dev', '-test', '-staging', '-prod', '-api', '-app', '-web', '-admin']
    for suffix in suffixes:
        for sub in base_list[:30]:
            additional.add(f"{sub}{suffix}")
    
    return list(additional)

def check_subdomain(subdomain, domain, timeout=5):
    """Aggressively check if a subdomain exists using multiple methods."""
    full_domain = f"{subdomain}.{domain}"
    
    # Method 1: DNS resolution for multiple record types
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV']
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(full_domain, record_type)
            if answers:
                return full_domain, True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            continue
        except Exception:
            continue
    
    # Method 2: Socket connection with timeout
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(full_domain)
        return full_domain, True
    except (socket.gaierror, socket.timeout):
        pass
    
    # Method 3: HTTP/HTTPS requests to verify accessibility
    for protocol in ['https://', 'http://']:
        try:
            url = f"{protocol}{full_domain}"
            response = requests.head(url, timeout=timeout, allow_redirects=True)
            if response.status_code < 500:  # Consider it exists if not server error
                return full_domain, True
        except (requests.exceptions.RequestException, requests.exceptions.Timeout):
            continue
    
    return full_domain, False

def scan_subdomains(domain, subdomains, progress_placeholder, status_placeholder, scan_mode="Normal", max_workers=50, timeout=5, retry_count=2):
    """Aggressively scan for existing subdomains with enhanced methods."""
    found = []
    
    progress_bar = progress_placeholder.progress(0)
    status_text = status_placeholder.empty()
    
    # Increase thread pool for more aggressive scanning
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit tasks with retry logic
        futures = []
        for sub in subdomains:
            # Submit multiple attempts for critical subdomains
            if sub in ['www', 'mail', 'ftp', 'admin']:
                for _ in range(retry_count):  # Retry based on mode
                    futures.append(executor.submit(check_subdomain, sub, domain, timeout=timeout))
            else:
                futures.append(executor.submit(check_subdomain, sub, domain, timeout=timeout))
        
        completed = 0
        for future in as_completed(futures):
            try:
                full_domain, exists = future.result(timeout=timeout*2)  # Timeout for the future itself
                if exists and full_domain not in found:
                    found.append(full_domain)
            except Exception as e:
                # Log errors but continue
                pass
            
            completed += 1
            progress_bar.progress(completed / len(futures))
            status_text.markdown(f"🔥 {scan_mode} Scan: **{completed}/{len(futures)}** checks completed | Found: **{len(found)}** subdomains")
    
    progress_bar.empty()
    status_text.empty()
    return sorted(list(set(found)))  # Remove duplicates and sort

def check_security_headers(url):
    """Check security headers for a given URL."""
    try:
        response = requests.head(url, timeout=10, allow_redirects=True)
        headers = response.headers
        
        security_checks = {
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Missing'),
            'Content-Security-Policy': headers.get('Content-Security-Policy', 'Missing'),
            'X-Frame-Options': headers.get('X-Frame-Options', 'Missing'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Missing'),
            'X-XSS-Protection': headers.get('X-XSS-Protection', 'Missing'),
            'Referrer-Policy': headers.get('Referrer-Policy', 'Missing'),
            'Permissions-Policy': headers.get('Permissions-Policy', 'Missing'),
            'Server': headers.get('Server', 'Not disclosed'),
            'X-Powered-By': headers.get('X-Powered-By', 'Not disclosed')
        }
        
        return security_checks, response.status_code
    except Exception as e:
        return {'Error': str(e)}, None

def check_ssl_certificate(domain):
    """Check SSL certificate information."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                cert_info = {
                    'Subject': dict(x[0] for x in cert.get('subject', [])),
                    'Issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'Version': cert.get('version'),
                    'Serial Number': str(cert.get('serialNumber')),
                    'Not Before': cert.get('notBefore'),
                    'Not After': cert.get('notAfter'),
                    'Signature Algorithm': cert.get('signatureAlgorithm'),
                }
                
                # Check if certificate is expired
                import datetime
                not_after = datetime.datetime.strptime(cert_info['Not After'], '%Y%m%d%H%M%SZ')
                cert_info['Expired'] = not_after < datetime.datetime.now()
                
                return cert_info
    except Exception as e:
        return {'Error': str(e)}

def check_open_ports(domain, ports=[80, 443, 8080, 8443, 3000, 5000, 8000, 9000]):
    """Check for open ports on the domain."""
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((domain, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

def check_common_files(domain):
    """Check for common sensitive files and directories."""
    common_paths = [
        '/robots.txt', '/sitemap.xml', '/.git/', '/.env', '/.htaccess', '/.htpasswd',
        '/admin/', '/administrator/', '/wp-admin/', '/wp-login.php', '/phpmyadmin/',
        '/adminer/', '/phpinfo.php', '/server-status', '/server-info', '/.well-known/',
        '/backup/', '/backups/', '/config/', '/configuration/', '/db/', '/database/',
        '/logs/', '/tmp/', '/temp/', '/test/', '/testing/', '/dev/', '/development/'
    ]
    
    found_paths = []
    for path in common_paths:
        try:
            url = f"https://{domain}{path}"
            response = requests.head(url, timeout=5, allow_redirects=False)
            if response.status_code < 400:
                found_paths.append({'path': path, 'status': response.status_code, 'url': url})
        except:
            pass
    
    return found_paths

def detect_technology(url):
    """Try to detect the technology stack."""
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        content = response.text.lower()
        
        technologies = []
        
        # Check headers
        if 'server' in headers:
            server = headers['server'].lower()
            if 'nginx' in server:
                technologies.append('Nginx')
            elif 'apache' in server:
                technologies.append('Apache')
            elif 'iis' in server:
                technologies.append('IIS')
        
        if 'x-powered-by' in headers:
            powered_by = headers['x-powered-by'].lower()
            if 'php' in powered_by:
                technologies.append('PHP')
            elif 'asp.net' in powered_by:
                technologies.append('ASP.NET')
            elif 'nodejs' in powered_by:
                technologies.append('Node.js')
        
        # Check content
        if 'wp-content' in content or 'wordpress' in content:
            technologies.append('WordPress')
        if 'jquery' in content:
            technologies.append('jQuery')
        if 'bootstrap' in content:
            technologies.append('Bootstrap')
        if 'react' in content:
            technologies.append('React')
        if 'angular' in content:
            technologies.append('Angular')
        if 'vue' in content:
            technologies.append('Vue.js')
        
        return technologies if technologies else ['Unknown']
    except:
        return ['Unable to detect']

def calculate_security_score(security_headers, ssl_info, open_ports, found_files):
    """Calculate a security score based on various checks."""
    score = 100
    
    # Security headers (40 points)
    critical_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options']
    for header in critical_headers:
        if header not in security_headers or security_headers[header] == 'Missing':
            score -= 10
    
    # SSL certificate (30 points)
    if 'Error' in ssl_info:
        score -= 30
    elif ssl_info.get('Expired', False):
        score -= 20
    
    # Open ports (20 points)
    dangerous_ports = [21, 23, 25, 53, 110, 143, 993, 995]  # FTP, Telnet, SMTP, etc.
    for port in open_ports:
        if port in dangerous_ports:
            score -= 5
    
    # Sensitive files (10 points)
    sensitive_files = ['/.env', '/.git/', '/phpmyadmin/', '/adminer/', '/phpinfo.php']
    for file_info in found_files:
        if file_info['path'] in sensitive_files:
            score -= 5
    
    return max(0, min(100, score))

def get_whois_info(domain):
    """Get WHOIS information for a domain."""
    try:
        w = whois.whois(domain)
        whois_info = {
            'Domain Name': w.domain_name,
            'Registrar': w.registrar,
            'Creation Date': str(w.creation_date),
            'Expiration Date': str(w.expiration_date),
            'Name Servers': w.name_servers,
            'Status': w.status,
            'Registrant': w.name if w.name else 'Not disclosed',
            'Organization': w.org if w.org else 'Not disclosed',
            'Country': w.country if w.country else 'Not disclosed'
        }
        return whois_info
    except Exception as e:
        return {'Error': str(e)}

def discover_api_endpoints(domain):
    """Discover potential API endpoints."""
    api_endpoints = []
    common_endpoints = [
        '/api', '/api/v1', '/api/v2', '/api/v3', '/rest', '/graphql',
        '/swagger', '/swagger-ui', '/api/docs', '/api/swagger',
        '/v1', '/v2', '/v3', '/api/auth', '/api/users', '/api/admin'
    ]
    
    for endpoint in common_endpoints:
        try:
            url = f"https://{domain}{endpoint}"
            response = requests.head(url, timeout=5, allow_redirects=False)
            if response.status_code < 400:
                api_endpoints.append({
                    'endpoint': endpoint,
                    'status': response.status_code,
                    'url': url
                })
        except:
            continue
    
    return api_endpoints

def check_backup_files(domain):
    """Check for common backup files and sensitive files."""
    backup_files = []
    common_backups = [
        '/backup.zip', '/backup.tar.gz', '/backup.sql', '/db.sql', '/database.sql',
        '/wp-config.php.bak', '/config.php.bak', '/.env.bak', '/settings.php.bak',
        '/admin.php.bak', '/index.php.bak', '/backup/', '/backups/', '/old/',
        '/archive.zip', '/site.tar.gz', '/data.zip', '/files.zip'
    ]
    
    for backup in common_backups:
        try:
            url = f"https://{domain}{backup}"
            response = requests.head(url, timeout=5, allow_redirects=False)
            if response.status_code < 400:
                backup_files.append({
                    'file': backup,
                    'status': response.status_code,
                    'url': url,
                    'risk': 'High' if any(ext in backup.lower() for ext in ['.sql', '.zip', '.tar.gz', '.bak']) else 'Medium'
                })
        except:
            continue
    
    return backup_files

def test_directory_traversal(domain):
    """Test for directory traversal vulnerabilities."""
    traversal_payloads = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
        '....//....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
    ]
    
    vulnerable_endpoints = []
    
    for payload in traversal_payloads:
        try:
            url = f"https://{domain}/?file={payload}"
            response = requests.get(url, timeout=5)
            
            # Check for signs of successful traversal
            if any(indicator in response.text.lower() for indicator in ['root:', 'boot', 'system32', 'passwd']):
                vulnerable_endpoints.append({
                    'payload': payload,
                    'url': url,
                    'response_length': len(response.text),
                    'status': response.status_code
                })
        except:
            continue
    
    return vulnerable_endpoints

def advanced_dns_analysis(domain):
    """Perform advanced DNS analysis."""
    dns_info = {}
    
    try:
        # A records
        a_records = dns.resolver.resolve(domain, 'A')
        dns_info['A_Records'] = [str(rdata) for rdata in a_records]
    except:
        dns_info['A_Records'] = []
    
    try:
        # AAAA records
        aaaa_records = dns.resolver.resolve(domain, 'AAAA')
        dns_info['AAAA_Records'] = [str(rdata) for rdata in aaaa_records]
    except:
        dns_info['AAAA_Records'] = []
    
    try:
        # MX records
        mx_records = dns.resolver.resolve(domain, 'MX')
        dns_info['MX_Records'] = [str(rdata) for rdata in mx_records]
    except:
        dns_info['MX_Records'] = []
    
    try:
        # TXT records (SPF, DKIM, etc.)
        txt_records = dns.resolver.resolve(domain, 'TXT')
        dns_info['TXT_Records'] = [str(rdata) for rdata in txt_records]
    except:
        dns_info['TXT_Records'] = []
    
    try:
        # NS records
        ns_records = dns.resolver.resolve(domain, 'NS')
        dns_info['NS_Records'] = [str(rdata) for rdata in ns_records]
    except:
        dns_info['NS_Records'] = []
    
    # Check for SPF record
    spf_found = any('v=spf1' in txt.lower() for txt in dns_info.get('TXT_Records', []))
    dns_info['SPF_Configured'] = spf_found
    
    return dns_info

def enhanced_technology_detection(url):
    """Enhanced technology stack detection."""
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        content = response.text.lower()
        
        technologies = []
        
        # Web servers
        server = headers.get('server', '').lower()
        if 'nginx' in server:
            technologies.append('Nginx')
        elif 'apache' in server:
            technologies.append('Apache')
        elif 'iis' in server:
            technologies.append('IIS')
        elif 'cloudflare' in server:
            technologies.append('Cloudflare')
        
        # Programming languages
        if 'x-powered-by' in headers:
            powered_by = headers['x-powered-by'].lower()
            if 'php' in powered_by:
                technologies.append('PHP')
                # Try to detect PHP version
                version_match = re.search(r'php/(\d+\.\d+)', powered_by)
                if version_match:
                    technologies.append(f'PHP {version_match.group(1)}')
            elif 'asp.net' in powered_by:
                technologies.append('ASP.NET')
            elif 'nodejs' in powered_by:
                technologies.append('Node.js')
        
        # CMS detection
        if 'wp-content' in content or 'wordpress' in content:
            technologies.append('WordPress')
        if 'drupal' in content:
            technologies.append('Drupal')
        if 'joomla' in content:
            technologies.append('Joomla')
        if 'magento' in content:
            technologies.append('Magento')
        
        # Frameworks
        if 'jquery' in content:
            technologies.append('jQuery')
        if 'bootstrap' in content:
            technologies.append('Bootstrap')
        if 'react' in content:
            technologies.append('React')
        if 'angular' in content:
            technologies.append('Angular')
        if 'vue' in content:
            technologies.append('Vue.js')
        if 'laravel' in content:
            technologies.append('Laravel')
        if 'django' in content:
            technologies.append('Django')
        
        # JavaScript libraries
        if 'lodash' in content:
            technologies.append('Lodash')
        if 'moment.js' in content:
            technologies.append('Moment.js')
        
        # Analytics
        if 'google-analytics' in content or 'gtag' in content:
            technologies.append('Google Analytics')
        if 'facebook' in content and 'pixel' in content:
            technologies.append('Facebook Pixel')
        
        return list(set(technologies)) if technologies else ['Unable to detect']
    except:
        return ['Unable to detect']

def basic_vulnerability_scan(domain):
    """Perform basic vulnerability scanning."""
    vulnerabilities = []
    
    # Test for common vulnerabilities
    test_urls = [
        f"https://{domain}/admin",
        f"https://{domain}/administrator",
        f"https://{domain}/wp-admin",
        f"https://{domain}/phpmyadmin",
        f"https://{domain}/admin.php",
        f"https://{domain}/login.php",
        f"https://{domain}/test.php",
        f"https://{domain}/phpinfo.php"
    ]
    
    for url in test_urls:
        try:
            response = requests.get(url, timeout=5, allow_redirects=False)
            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'Exposed Admin Panel',
                    'url': url,
                    'severity': 'Medium',
                    'description': f'Potential admin panel found at {url}'
                })
        except:
            continue
    
    # Check for directory listing
    try:
        response = requests.get(f"https://{domain}/backup/", timeout=5)
        if 'index of' in response.text.lower():
            vulnerabilities.append({
                'type': 'Directory Listing',
                'url': f"https://{domain}/backup/",
                'severity': 'High',
                'description': 'Directory listing is enabled'
            })
    except:
        pass
    
    return vulnerabilities

# Streamlit app
st.set_page_config(
    page_title="Web Application Security Scanner",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'About': "Advanced Web Application Security Scanner with subdomain enumeration and vulnerability assessment."
    }
)

# Custom CSS for modern styling
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
    @import url('https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css');
    
    :root {
        --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        --secondary-gradient: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        --success-gradient: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        --warning-gradient: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
        --danger-gradient: linear-gradient(135deg, #ff6b6b 0%, #ffa726 100%);
        --glass-bg: rgba(255, 255, 255, 0.9);
        --glass-border: rgba(0, 0, 0, 0.1);
        --shadow-light: 0 4px 20px rgba(0, 0, 0, 0.1);
        --shadow-dark: 0 8px 32px rgba(0, 0, 0, 0.15);
        --border-radius: 16px;
        --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        /* Light theme colors for black text readability */
        --text-primary: #000000;
        --text-secondary: #374151;
        --text-muted: #6b7280;
        --text-accent: #667eea;
        --bg-primary: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 50%, #cbd5e1 100%);
        --bg-card: rgba(255, 255, 255, 0.95);
    }
    
    * {
        font-family: 'Inter', sans-serif;
    }
    
    .main {
        background: var(--bg-primary);
        min-height: 100vh;
        color: var(--text-secondary);
    }
    
    .main-header {
        background: var(--primary-gradient);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        font-size: 3.5rem;
        font-weight: 800;
        text-align: center;
        margin-bottom: 1rem;
        text-shadow: 0 4px 8px rgba(0,0,0,0.3);
        animation: fadeInUp 1s ease-out;
    }
    
    .subtitle {
        font-size: 1.3rem;
        color: var(--text-secondary);
        text-align: center;
        margin-bottom: 2rem;
        font-weight: 400;
        opacity: 0.9;
        animation: fadeInUp 1s ease-out 0.2s both;
    }
    
    .modern-card {
        background: var(--bg-card);
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        border: 1px solid var(--glass-border);
        border-radius: var(--border-radius);
        padding: 2.5rem;
        margin: 1.5rem 0;
        box-shadow: var(--shadow-light);
        transition: var(--transition);
        animation: slideInUp 0.6s ease-out;
    }
    
    .modern-card:hover {
        transform: translateY(-2px);
        box-shadow: var(--shadow-dark);
    }
    
    .input-container {
        background: var(--bg-card);
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        border-radius: var(--border-radius);
        padding: 2rem;
        margin: 1.5rem 0;
        box-shadow: var(--shadow-light);
        border: 1px solid var(--glass-border);
        transition: var(--transition);
    }
    
    .input-container:hover {
        transform: translateY(-1px);
        box-shadow: var(--shadow-dark);
    }
    
    .stTextInput > div > div > input {
        border-radius: 12px;
        border: 2px solid var(--glass-border);
        padding: 1rem 1.25rem;
        font-size: 1.1rem;
        transition: var(--transition);
        background: rgba(255, 255, 255, 0.8);
        color: var(--text-primary);
        backdrop-filter: blur(5px);
    }
    
    .stTextInput > div > div > input:focus {
        border-color: #667eea;
        box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.2);
        background: rgba(255, 255, 255, 0.95);
    }
    
    .stTextInput > div > div > input::placeholder {
        color: var(--text-muted);
    }
    
    .stTextInput > div > div > input::placeholder {
        color: rgba(255, 255, 255, 0.6);
    }
    
    .stTextArea > div > div > textarea {
        border-radius: 12px;
        border: 2px solid var(--glass-border);
        padding: 1rem 1.25rem;
        font-size: 1rem;
        transition: var(--transition);
        background: rgba(255, 255, 255, 0.8);
        color: var(--text-primary);
        backdrop-filter: blur(5px);
        min-height: 120px;
    }
    
    .stTextArea > div > div > textarea:focus {
        border-color: #667eea;
        box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.2);
        background: rgba(255, 255, 255, 0.95);
    }
    
    .stTextArea > div > div > textarea::placeholder {
        color: var(--text-muted);
    }
    
    .stTextArea > div > div > textarea::placeholder {
        color: rgba(255, 255, 255, 0.6);
    }
    
    .stButton > button {
        background: var(--primary-gradient);
        color: white;
        border: none;
        border-radius: 12px;
        padding: 1rem 2.5rem;
        font-size: 1.1rem;
        font-weight: 600;
        cursor: pointer;
        transition: var(--transition);
        box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        text-transform: uppercase;
        letter-spacing: 0.5px;
        position: relative;
        overflow: hidden;
    }
    
    .stButton > button::before {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
        transition: left 0.5s;
    }
    
    .stButton > button:hover::before {
        left: 100%;
    }
    
    .stButton > button:hover {
        transform: translateY(-3px);
        box-shadow: 0 8px 25px rgba(102, 126, 234, 0.5);
    }
    
    .stButton > button:active {
        transform: translateY(-1px);
    }
    
    .result-card {
        background: var(--success-gradient);
        color: var(--text-primary);
        border-radius: var(--border-radius);
        padding: 2rem;
        margin: 1.5rem 0;
        box-shadow: var(--shadow-light);
        position: relative;
        overflow: hidden;
    }
    
    .result-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grain" width="100" height="100" patternUnits="userSpaceOnUse"><circle cx="25" cy="25" r="1" fill="rgba(255,255,255,0.1)"/><circle cx="75" cy="75" r="1" fill="rgba(255,255,255,0.1)"/><circle cx="50" cy="10" r="0.5" fill="rgba(255,255,255,0.1)"/></pattern></defs><rect width="100" height="100" fill="url(%23grain)"/></svg>');
        opacity: 0.1;
    }
    
    .subdomain-item {
        background: rgba(255,255,255,0.15);
        backdrop-filter: blur(10px);
        border-radius: 10px;
        padding: 0.75rem 1.25rem;
        margin: 0.5rem 0;
        border: 1px solid rgba(255,255,255,0.2);
        transition: var(--transition);
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    
    .subdomain-item:hover {
        transform: translateX(5px);
        background: rgba(255,255,255,0.25);
    }
    
    .progress-container {
        background: var(--bg-card);
        backdrop-filter: blur(5px);
        border-radius: var(--border-radius);
        padding: 1.5rem;
        margin: 1.5rem 0;
        box-shadow: var(--shadow-light);
        border: 1px solid var(--glass-border);
    }
    
    .footer {
        text-align: center;
        color: var(--text-muted);
        font-size: 0.95rem;
        margin-top: 3rem;
        padding-top: 2rem;
        border-top: 1px solid var(--glass-border);
        background: var(--bg-card);
        backdrop-filter: blur(5px);
        border-radius: var(--border-radius);
        padding: 2rem;
        margin: 2rem 0;
    }
    
    .sidebar-content {
        background: var(--bg-card);
        color: var(--text-primary);
        padding: 1.5rem;
        border-radius: var(--border-radius);
        margin-bottom: 1.5rem;
        box-shadow: var(--shadow-light);
        backdrop-filter: blur(5px);
        border: 1px solid var(--glass-border);
    }
    
    .sidebar-content h1 {
        color: var(--text-primary);
        font-size: 1.5rem;
        margin-bottom: 1rem;
    }
    
    .stRadio > div {
        background: var(--bg-card);
        backdrop-filter: blur(5px);
        border-radius: 12px;
        padding: 1rem;
        border: 1px solid var(--glass-border);
    }
    
    .stRadio > div > div > div > div {
        color: var(--text-primary);
    }
    
    .stSelectbox > div > div {
        background: rgba(255, 255, 255, 0.8);
        border: 1px solid var(--glass-border);
        border-radius: 12px;
        backdrop-filter: blur(5px);
    }
    
    .stSelectbox > div > div > div > div {
        color: var(--text-primary);
    }
    
    .stCheckbox > div > div > div > div {
        background-color: transparent !important;
        border-radius: 6px;
    }
    
    .stCheckbox > div > div > div > div > div {
        border-radius: 6px;
        background: rgba(255, 255, 255, 0.8);
    }
    
    .stCheckbox > div > div > div > label {
        color: var(--text-secondary) !important;
    }
    
    .stSuccess, .stInfo, .stWarning, .stError {
        border-radius: 12px;
        border: none;
        box-shadow: var(--shadow-light);
        backdrop-filter: blur(10px);
        color: var(--text-primary) !important;
    }
    
    .stSuccess {
        background: linear-gradient(135deg, rgba(34, 197, 94, 0.2), rgba(34, 197, 94, 0.1));
        border-left: 4px solid #22c55e;
    }
    
    .stError {
        background: linear-gradient(135deg, rgba(239, 68, 68, 0.2), rgba(239, 68, 68, 0.1));
        border-left: 4px solid #ef4444;
    }
    
    .stWarning {
        background: linear-gradient(135deg, rgba(245, 158, 11, 0.2), rgba(245, 158, 11, 0.1));
        border-left: 4px solid #f59e0b;
    }
    
    .stInfo {
        background: linear-gradient(135deg, rgba(59, 130, 246, 0.2), rgba(59, 130, 246, 0.1));
        border-left: 4px solid #3b82f6;
    }
    
    .stProgress > div > div > div {
        background: var(--primary-gradient);
        border-radius: 10px;
    }
    
    .stDownloadButton > button {
        background: var(--success-gradient);
        border: none;
        border-radius: 12px;
        padding: 1rem 2rem;
        font-weight: 600;
        transition: var(--transition);
        box-shadow: 0 4px 15px rgba(79, 172, 254, 0.4);
    }
    
    .stDownloadButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 25px rgba(79, 172, 254, 0.5);
    }
    
    @keyframes fadeInUp {
        from {
            opacity: 0;
            transform: translateY(30px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    @keyframes slideInUp {
        from {
            opacity: 0;
            transform: translateY(50px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    @keyframes pulse {
        0%, 100% {
            opacity: 1;
        }
        50% {
            opacity: 0.7;
        }
    }
    
    .pulse {
        animation: pulse 2s infinite;
    }
    
    .glow {
        box-shadow: 0 0 20px rgba(102, 126, 234, 0.3);
    }
    
    /* Ensure all text has proper contrast */
    .stMarkdown, .stText, p, span, div {
        color: var(--text-secondary) !important;
    }
    
    .stMarkdown h1, .stMarkdown h2, .stMarkdown h3, .stMarkdown h4, .stMarkdown h5, .stMarkdown h6 {
        color: var(--text-primary) !important;
    }
    
    /* Override any default white text */
    * {
        color: var(--text-secondary);
    }
    
    /* Ensure form labels are readable */
    label {
        color: var(--text-secondary) !important;
    }
    
    /* Responsive Design */
    @media (max-width: 768px) {
        .main-header {
            font-size: 2.5rem;
            margin-bottom: 1rem;
        }
        
        .subtitle {
            font-size: 1.1rem;
            margin-bottom: 1.5rem;
        }
        
        .modern-card {
            padding: 1.5rem;
            margin: 1rem 0;
        }
        
        .input-container {
            padding: 1.5rem;
            margin: 1rem 0;
        }
        
        .stTextInput > div > div > input {
            padding: 0.75rem 1rem;
            font-size: 1rem;
        }
        
        .stButton > button {
            padding: 0.75rem 1.5rem;
            font-size: 1rem;
        }
        
        .sidebar-content {
            padding: 1rem;
        }
        
        .footer {
            padding: 1.5rem;
            margin: 1rem 0;
        }
        
        /* Stack columns on mobile */
        .stColumns {
            flex-direction: column !important;
        }
        
        .stColumns > div {
            width: 100% !important;
            margin-bottom: 1rem;
        }
        
        /* Adjust subdomain display for mobile */
        .subdomain-item {
            padding: 0.5rem 0.75rem;
            margin: 0.25rem 0;
            font-size: 0.9rem;
        }
        
        /* Make tables responsive */
        .stDataFrame, .stTable {
            overflow-x: auto;
            max-width: 100%;
        }
        
        /* Adjust progress bars for mobile */
        .stProgress {
            height: 8px;
        }
    }
    
    @media (max-width: 480px) {
        .main-header {
            font-size: 2rem;
        }
        
        .subtitle {
            font-size: 1rem;
        }
        
        .modern-card {
            padding: 1rem;
        }
        
        .input-container {
            padding: 1rem;
        }
        
        .stTextInput > div > div > input {
            padding: 0.5rem 0.75rem;
            font-size: 0.9rem;
        }
        
        .stButton > button {
            padding: 0.5rem 1rem;
            font-size: 0.9rem;
        }
        
        .sidebar-content {
            padding: 0.75rem;
        }
        
        .footer {
            padding: 1rem;
        }
        
        /* Smaller icons and text on very small screens */
        .subdomain-item {
            padding: 0.4rem 0.6rem;
            font-size: 0.8rem;
        }
    }
    
    /* Tablet adjustments */
    @media (min-width: 769px) and (max-width: 1024px) {
        .main-header {
            font-size: 3rem;
        }
        
        .modern-card {
            padding: 2rem;
        }
        
        .input-container {
            padding: 1.75rem;
        }
    }
    
    /* Ensure proper spacing on all devices */
    .stMarkdown {
        margin-bottom: 1rem;
    }
    
    /* Responsive grid for subdomain display */
    @media (max-width: 768px) {
        .stColumns:has(.subdomain-item) {
            grid-template-columns: 1fr !important;
        }
    }
    
    /* Better mobile navigation */
    @media (max-width: 768px) {
        .stSidebar {
            width: 280px !important;
        }
        
        .stSidebar > div {
            padding: 1rem;
        }
        
        /* Improve radio button layout on mobile */
        .stRadio > div {
            padding: 0.75rem !important;
        }
        
        .stRadio > div > div {
            flex-direction: column !important;
            gap: 0.5rem !important;
        }
        
        /* Better selectbox on mobile */
        .stSelectbox > div > div {
            min-height: 40px !important;
        }
        
        /* Improve button spacing on mobile */
        .stButton {
            margin-bottom: 0.5rem;
        }
        
        /* Make JSON displays scrollable on mobile */
        .stJson {
            max-height: 300px;
            overflow-y: auto;
            font-size: 0.8rem;
        }
        
        /* Better spacing for alerts on mobile */
        .stAlert {
            margin-bottom: 1rem;
            padding: 0.75rem;
        }
        
        /* Responsive download buttons */
        .stDownloadButton > button {
            width: 100% !important;
            margin-bottom: 0.5rem;
        }
        
        /* Responsive text area */
        .stTextArea > div > div > textarea {
            min-height: 100px !important;
            font-size: 0.9rem !important;
        }
    }
</style>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.markdown('<div class="sidebar-content">', unsafe_allow_html=True)
    st.markdown('<h1 style="margin-bottom: 1.5rem;"><i class="fas fa-cogs"></i> Control Panel</h1>', unsafe_allow_html=True)
    
    # Initialize session state for custom subdomains
    if 'custom_subs' not in st.session_state:
        st.session_state.custom_subs = ""
    
    st.markdown('<h3 style="margin-bottom: 1rem;"><i class="fas fa-tachometer-alt"></i> Scan Configuration</h3>', unsafe_allow_html=True)
    scan_mode = st.selectbox(
        "Scan Intensity:",
        ["Normal", "Aggressive", "Brutal"],
        index=0,  # Default to Normal
        help="Normal: Basic checks | Aggressive: Multiple methods | Brutal: Maximum coverage"
    )
    
    st.markdown('<div style="margin: 1rem 0;">', unsafe_allow_html=True)
    use_common = st.checkbox("🔍 Use common subdomains list", value=True, help="Scan 100+ common subdomains")
    generate_variations = st.checkbox("🎯 Generate subdomain variations", value=True, help="Create additional subdomains with prefixes/suffixes")
    st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown('<h3 style="margin-bottom: 1rem;"><i class="fas fa-edit"></i> Custom Subdomains</h3>', unsafe_allow_html=True)
    custom_subs = st.text_area("Add custom subdomains (one per line):", height=150, placeholder="api\nadmin\ntest\ndev\nstaging\n\n💡 Tip: Common subdomains like 'www', 'api', 'mail' are already included", help="Enter additional subdomains to check", value=st.session_state.custom_subs)
    
    # Update session state when user types in text area
    st.session_state.custom_subs = custom_subs
    
    st.markdown('<hr style="border-color: rgba(255,255,255,0.3); margin: 1.5rem 0;">', unsafe_allow_html=True)
    st.markdown('<h3 style="margin-bottom: 1rem;"><i class="fas fa-info-circle"></i> About</h3>', unsafe_allow_html=True)
    st.markdown('<p style="font-size: 0.9rem; line-height: 1.5;">This advanced security scanner combines subdomain enumeration with comprehensive vulnerability assessment. Features include WHOIS lookup, API endpoint discovery, backup file detection, directory traversal testing, and advanced DNS analysis.</p>', unsafe_allow_html=True)
    st.markdown('<p style="font-size: 0.8rem; color: rgba(255,255,255,0.7); margin-top: 1rem;"><i class="fas fa-shield-alt"></i> Use responsibly and only on domains you own or have permission to test.</p>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

# Main content
st.markdown('<h1 class="main-header"><i class="fas fa-shield-alt"></i> Web Application Security Scanner</h1>', unsafe_allow_html=True)
st.markdown('<p class="subtitle"><i class="fas fa-search"></i> Comprehensive security testing for web applications through subdomain enumeration and vulnerability assessment</p>', unsafe_allow_html=True)

# Mode selector with modern styling
st.markdown('<div class="modern-card">', unsafe_allow_html=True)
mode = st.radio("**Select Testing Mode:**", ["🔍 Subdomain Discovery", "🛡️ Security Assessment"], horizontal=True, help="Choose between subdomain enumeration or full security testing", label_visibility="visible")
st.markdown('</div>', unsafe_allow_html=True)

if mode == "🔍 Subdomain Discovery":
    st.markdown("### 🔍 Subdomain Discovery Mode")
    st.markdown("Discover hidden subdomains using aggressive scanning techniques with multiple DNS record types and HTTP verification.")
    
    # Input section with modern styling
    with st.container():
        st.markdown('<div class="input-container">', unsafe_allow_html=True)
        # Responsive columns: stack on mobile, side-by-side on desktop
        col1, col2 = st.columns([3, 1])
        with col1:
            domain = st.text_input("**Target Domain:**", placeholder="example.com", help="Enter the domain you want to scan (without www)")
        with col2:
            scan_button = st.button("🚀 **Start Discovery**", use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

else:  # Security Assessment
    st.markdown("### 🛡️ Advanced Security Assessment Mode")
    st.markdown("Perform comprehensive security testing including SSL analysis, vulnerability scanning, API discovery, and advanced reconnaissance.")
    
    # Security testing input
    with st.container():
        st.markdown('<div class="input-container">', unsafe_allow_html=True)
        # Responsive columns: stack on mobile, side-by-side on desktop
        col1, col2 = st.columns([3, 1])
        with col1:
            security_domain = st.text_input("**Target Domain:**", placeholder="example.com", help="Enter the domain you want to assess")
        with col2:
            security_button = st.button("🔒 **Start Assessment**", use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Assessment type selector
    if 'assessment_type' not in st.session_state:
        st.session_state.assessment_type = "Full Assessment"
    
    assessment_type = st.selectbox(
        "**Assessment Type:**",
        ["Full Assessment", "Quick Scan", "Vulnerability Only", "Recon Only"],
        index=["Full Assessment", "Quick Scan", "Vulnerability Only", "Recon Only"].index(st.session_state.assessment_type),
        help="Choose the type of security assessment to perform"
    )
    st.session_state.assessment_type = assessment_type

if mode == "🔍 Subdomain Discovery" and scan_button:
    if not domain.strip():
        st.error("⚠️ Please enter a domain name.")
    else:
        # Calculate scan parameters based on mode
        if scan_mode == "Normal":
            max_workers = 20
            timeout = 8
            retry_count = 1
        elif scan_mode == "Aggressive":
            max_workers = 50
            timeout = 5
            retry_count = 2
        else:  # Brutal
            max_workers = 100
            timeout = 3
            retry_count = 3
        
        # Prepare subdomain list based on scan mode
        subdomains_to_check = []
        
        if use_common:
            subdomains_to_check.extend(COMMON_SUBDOMAINS)
        
        if generate_variations:
            base_subs = COMMON_SUBDOMAINS if use_common else []
            if custom_subs.strip():
                custom_list = [s.strip() for s in custom_subs.split('\n') if s.strip()]
                base_subs.extend(custom_list[:20])  # Limit to avoid explosion
            
            additional_subs = generate_additional_subdomains(base_subs)
            subdomains_to_check.extend(additional_subs)
            
            # Add more variations based on scan mode
            if scan_mode == "Aggressive":
                # Add some common patterns
                for sub in base_subs[:50]:
                    subdomains_to_check.extend([f"www{sub}", f"{sub}1", f"{sub}2", f"{sub}-prod"])
            elif scan_mode == "Brutal":
                # Maximum coverage
                for sub in base_subs[:30]:
                    subdomains_to_check.extend([
                        f"www{sub}", f"{sub}1", f"{sub}2", f"{sub}-prod", f"{sub}-dev",
                        f"dev{sub}", f"test{sub}", f"staging{sub}", f"prod{sub}"
                    ])
        
        if custom_subs.strip():
            custom_list = [s.strip() for s in custom_subs.split('\n') if s.strip()]
            subdomains_to_check.extend(custom_list)
        
        # Add quick add subdomains
        if 'quick_web' in st.session_state and st.session_state.quick_web:
            web_subs = ['www', 'api', 'app', 'web', 'secure', 'ssl', 'cdn', 'static']
            subdomains_to_check.extend(web_subs)
            del st.session_state.quick_web
        
        if 'quick_email' in st.session_state and st.session_state.quick_email:
            email_subs = ['mail', 'email', 'smtp', 'imap', 'pop', 'webmail', 'owa', 'exchange']
            subdomains_to_check.extend(email_subs)
            del st.session_state.quick_email
        
        if not subdomains_to_check:
            st.error("❌ No subdomains to check. Enable common list or add custom subdomains.")
        else:
            # Remove duplicates
            subdomains_to_check = list(set(subdomains_to_check))
            
            st.markdown('<div class="modern-card">', unsafe_allow_html=True)
            st.markdown(f"### � **{scan_mode}** scanning {len(subdomains_to_check)} subdomains for **{domain}**")
            st.markdown(f"**Mode Details:** {max_workers} threads, {timeout}s timeout, {retry_count} retries for critical subdomains")
            
            # Progress section
            progress_placeholder = st.empty()
            status_placeholder = st.empty()
            
            found_subdomains = scan_subdomains(domain, subdomains_to_check, progress_placeholder, status_placeholder, scan_mode, max_workers, timeout, retry_count)
            
            if found_subdomains:
                st.markdown('<div class="result-card">', unsafe_allow_html=True)
                st.markdown(f"### 🎉 Found {len(found_subdomains)} subdomains!")
                st.markdown('</div>', unsafe_allow_html=True)
                
                st.markdown("### 📋 Discovered Subdomains:")
                # Responsive: 2 columns on desktop, 1 column on mobile
                cols = st.columns(2)
                for i, sub in enumerate(sorted(found_subdomains)):
                    with cols[i % 2]:
                        st.markdown(f'<div class="subdomain-item">🔗 {sub}</div>', unsafe_allow_html=True)
                
                # Download section
                st.markdown("---")
                result_text = "\n".join(sorted(found_subdomains))
                st.download_button(
                    label="📥 Download Results",
                    data=result_text,
                    file_name=f"subdomains_{domain}.txt",
                    mime="text/plain",
                    use_container_width=True
                )
            else:
                st.warning("🔍 No subdomains found for this domain.")
            
            st.markdown('</div>', unsafe_allow_html=True)

elif mode == "🛡️ Security Assessment" and security_button:
    if not security_domain.strip():
        st.error("⚠️ Please enter a domain name for security assessment.")
    else:
        st.markdown('<div class="modern-card">', unsafe_allow_html=True)
        st.markdown(f'<h2 style="color: #000000; margin-bottom: 1rem;"><i class="fas fa-shield-alt"></i> Security Assessment for <strong>{security_domain}</strong></h2>', unsafe_allow_html=True)
        st.markdown(f'<p style="color: #374151; font-size: 1rem;">🔍 {assessment_type} in progress...</p>', unsafe_allow_html=True)
        
        with st.spinner(f"🔍 Performing {assessment_type.lower()}..."):
            assessment_results = {}
            
            # Conditional execution based on assessment type
            if assessment_type in ["Full Assessment", "Quick Scan"]:
                # 1. Check SSL Certificate
                st.markdown('<h3 style="color: #000000; margin: 2rem 0 1rem 0;"><i class="fas fa-lock"></i> SSL/TLS Certificate Analysis</h3>', unsafe_allow_html=True)
                ssl_info = check_ssl_certificate(security_domain)
                if 'Error' in ssl_info:
                    st.error(f"SSL Certificate Error: {ssl_info['Error']}")
                    assessment_results['SSL'] = {'status': 'Error', 'details': ssl_info['Error']}
                else:
                    if ssl_info.get('Expired', False):
                        st.error("❌ Certificate is EXPIRED!")
                    else:
                        st.success("✅ Certificate is valid")
                    
                    st.json(ssl_info)
                    assessment_results['SSL'] = {'status': 'Valid' if not ssl_info.get('Expired', False) else 'Expired', 'details': ssl_info}
                
                # 2. Check Security Headers
                st.markdown('<h3 style="color: #000000; margin: 2rem 0 1rem 0;"><i class="fas fa-shield-alt"></i> Security Headers Analysis</h3>', unsafe_allow_html=True)
                security_headers, status_code = check_security_headers(f"https://{security_domain}")
                if status_code:
                    st.info(f"Response Status: {status_code}")
                
                header_score = 0
                for header, value in security_headers.items():
                    if value != 'Missing':
                        st.success(f"✅ {header}: {value}")
                        header_score += 1
                    else:
                        st.error(f"❌ {header}: Missing")
                
                assessment_results['Security_Headers'] = {'score': header_score, 'total': len(security_headers), 'details': security_headers}
                
                # 3. Check Open Ports
                st.markdown("#### 🔌 Open Ports Scan")
                open_ports = check_open_ports(security_domain)
                if open_ports:
                    st.warning(f"⚠️ Open ports found: {', '.join(map(str, open_ports))}")
                    # Check for dangerous ports
                    dangerous_ports = [21, 23, 25, 53, 110, 143, 993, 995]
                    dangerous_found = [p for p in open_ports if p in dangerous_ports]
                    if dangerous_found:
                        st.error(f"🚨 Dangerous open ports: {', '.join(map(str, dangerous_found))}")
                else:
                    st.success("✅ No common web ports open (or blocked by firewall)")
                
                assessment_results['Open_Ports'] = {'ports': open_ports}
                
                # 4. Check Common Files
                st.markdown("#### 📁 Sensitive Files Check")
                found_files = check_common_files(security_domain)
                if found_files:
                    st.warning(f"⚠️ Found {len(found_files)} potentially sensitive files/directories:")
                    for file_info in found_files:
                        if file_info['status'] < 300:
                            st.error(f"🚨 {file_info['path']} (Status: {file_info['status']})")
                        else:
                            st.info(f"ℹ️ {file_info['path']} (Status: {file_info['status']})")
                else:
                    st.success("✅ No common sensitive files found")
                
                assessment_results['Sensitive_Files'] = {'count': len(found_files), 'files': found_files}
            
            if assessment_type in ["Full Assessment", "Recon Only"]:
                # 5. WHOIS Information
                st.markdown('<h3 style="color: #000000; margin: 2rem 0 1rem 0;"><i class="fas fa-info-circle"></i> WHOIS Information</h3>', unsafe_allow_html=True)
                whois_info = get_whois_info(security_domain)
                if 'Error' in whois_info:
                    st.error(f"WHOIS lookup failed: {whois_info['Error']}")
                else:
                    st.json(whois_info)
                    assessment_results['WHOIS'] = whois_info
                
                # 6. Advanced DNS Analysis
                st.markdown('<h3 style="color: #000000; margin: 2rem 0 1rem 0;"><i class="fas fa-network-wired"></i> Advanced DNS Analysis</h3>', unsafe_allow_html=True)
                dns_info = advanced_dns_analysis(security_domain)
                st.json(dns_info)
                assessment_results['DNS_Analysis'] = dns_info
                
                # 7. API Endpoints Discovery
                st.markdown('<h3 style="color: #000000; margin: 2rem 0 1rem 0;"><i class="fas fa-plug"></i> API Endpoints Discovery</h3>', unsafe_allow_html=True)
                api_endpoints = discover_api_endpoints(security_domain)
                if api_endpoints:
                    st.success(f"Found {len(api_endpoints)} potential API endpoints:")
                    for endpoint in api_endpoints:
                        st.info(f"🔗 {endpoint['url']} (Status: {endpoint['status']})")
                else:
                    st.info("No common API endpoints found")
                assessment_results['API_Endpoints'] = api_endpoints
                
                # 8. Backup Files Check
                st.markdown('<h3 style="color: #000000; margin: 2rem 0 1rem 0;"><i class="fas fa-file-archive"></i> Backup Files Detection</h3>', unsafe_allow_html=True)
                backup_files = check_backup_files(security_domain)
                if backup_files:
                    st.warning(f"⚠️ Found {len(backup_files)} potential backup files:")
                    for backup in backup_files:
                        risk_color = "🔴" if backup['risk'] == 'High' else "🟡"
                        st.error(f"{risk_color} {backup['file']} (Risk: {backup['risk']}) - {backup['url']}")
                else:
                    st.success("✅ No backup files detected")
                assessment_results['Backup_Files'] = backup_files
            
            if assessment_type in ["Full Assessment", "Vulnerability Only"]:
                # 9. Technology Detection
                st.markdown('<h3 style="color: #000000; margin: 2rem 0 1rem 0;"><i class="fas fa-cogs"></i> Technology Stack Detection</h3>', unsafe_allow_html=True)
                try:
                    technologies = enhanced_technology_detection(f"https://{security_domain}")
                    if technologies and technologies[0] != 'Unable to detect':
                        st.info(f"Detected technologies: {', '.join(technologies)}")
                    else:
                        st.warning("Unable to detect technology stack")
                    
                    assessment_results['Technology'] = {'detected': technologies}
                except Exception as e:
                    st.error(f"Technology detection failed: {e}")
                    assessment_results['Technology'] = {'error': str(e)}
                
                # 10. Directory Traversal Test
                st.markdown('<h3 style="color: #000000; margin: 2rem 0 1rem 0;"><i class="fas fa-folder-open"></i> Directory Traversal Vulnerability Test</h3>', unsafe_allow_html=True)
                traversal_vulns = test_directory_traversal(security_domain)
                if traversal_vulns:
                    st.error(f"🚨 Found {len(traversal_vulns)} potential directory traversal vulnerabilities:")
                    for vuln in traversal_vulns:
                        st.error(f"💀 Payload: {vuln['payload']} - Response length: {vuln['response_length']}")
                else:
                    st.success("✅ No directory traversal vulnerabilities detected")
                assessment_results['Directory_Traversal'] = traversal_vulns
                
                # 11. Basic Vulnerability Scan
                st.markdown('<h3 style="color: #000000; margin: 2rem 0 1rem 0;"><i class="fas fa-bug"></i> Basic Vulnerability Scan</h3>', unsafe_allow_html=True)
                vulnerabilities = basic_vulnerability_scan(security_domain)
                if vulnerabilities:
                    st.warning(f"⚠️ Found {len(vulnerabilities)} potential vulnerabilities:")
                    for vuln in vulnerabilities:
                        severity_color = "🔴" if vuln['severity'] == 'High' else "🟡" if vuln['severity'] == 'Medium' else "🟢"
                        st.error(f"{severity_color} [{vuln['severity']}] {vuln['type']}: {vuln['description']}")
                else:
                    st.success("✅ No basic vulnerabilities detected")
                assessment_results['Vulnerabilities'] = vulnerabilities
            
            # Security Score Calculation (only for Full Assessment and Quick Scan)
            if assessment_type in ["Full Assessment", "Quick Scan"]:
                st.markdown('<h3 style="color: #000000; margin: 2rem 0 1rem 0;"><i class="fas fa-chart-line"></i> Security Score</h3>', unsafe_allow_html=True)
                security_score = calculate_security_score(security_headers, ssl_info, open_ports, found_files)
                
                if security_score >= 80:
                    st.success(f"🟢 **Security Score: {security_score}/100** - Good security posture")
                elif security_score >= 60:
                    st.warning(f"🟡 **Security Score: {security_score}/100** - Moderate security posture")
                else:
                    st.error(f"🔴 **Security Score: {security_score}/100** - Poor security posture")
                
                assessment_results['Security_Score'] = security_score
            
            # Generate Report
            st.markdown('<h3 style="color: #000000; margin: 2rem 0 1rem 0;"><i class="fas fa-file-alt"></i> Security Report</h3>', unsafe_allow_html=True)
            report_data = {
                'Domain': security_domain,
                'Assessment_Type': assessment_type,
                'Assessment_Date': time.strftime('%Y-%m-%d %H:%M:%S'),
                'Findings': assessment_results
            }
            
            if assessment_type in ["Full Assessment", "Quick Scan"]:
                report_data['Security_Score'] = security_score
            
            st.download_button(
                label="📥 Download Security Report",
                data=json.dumps(report_data, indent=2),
                file_name=f"security_report_{security_domain}_{assessment_type.lower().replace(' ', '_')}.json",
                mime="application/json",
                use_container_width=True
            )
        
        st.markdown('</div>', unsafe_allow_html=True)

# Footer
st.markdown('<div class="footer">', unsafe_allow_html=True)
st.markdown('<h3 style="color: #000000; margin-bottom: 1rem;"><i class="fas fa-info-circle"></i> About This Tool</h3>', unsafe_allow_html=True)
st.markdown('<p style="margin-bottom: 0.5rem;"><strong><i class="fas fa-shield-alt"></i> Advanced Security Testing:</strong> Comprehensive web application security assessment including SSL analysis, security headers, port scanning, WHOIS lookup, API discovery, backup file detection, and advanced vulnerability scanning.</p>', unsafe_allow_html=True)
st.markdown('<p style="margin-bottom: 0.5rem;"><strong><i class="fas fa-search"></i> Multiple Assessment Types:</strong> Choose from Full Assessment, Quick Scan, Vulnerability Only, or Recon Only based on your security testing needs.</p>', unsafe_allow_html=True)
st.markdown('<p style="margin-bottom: 0.5rem;"><strong><i class="fas fa-rocket"></i> Vigorous Scanning:</strong> Uses multiple DNS record types, HTTP verification, pattern generation, and advanced reconnaissance for maximum coverage.</p>', unsafe_allow_html=True)
st.markdown('<p style="margin-bottom: 1rem;"><strong><i class="fas fa-lightbulb"></i> Pro Tip:</strong> Use \'Subdomain Discovery\' first to find targets, then \'Security Assessment\' with your preferred assessment type for detailed analysis.</p>', unsafe_allow_html=True)
st.markdown('<p style="text-align: center; font-size: 0.9rem; color: #6b7280;"><i class="fas fa-heart"></i> Built with love using Streamlit</p>', unsafe_allow_html=True)
st.markdown('</div>', unsafe_allow_html=True)

# Web Application Security Scanner

A comprehensive security testing tool for web applications that combines aggressive subdomain enumeration with detailed vulnerability assessment and security analysis. Features a modern, dark-themed UI with glassmorphism design and smooth animations.

## Features

### 🎨 Modern UI/UX
- **Dark Theme**: Beautiful dark mode with glassmorphism effects
- **Smooth Animations**: CSS transitions and micro-interactions
- **Responsive Design**: Works perfectly on desktop and mobile
- **Interactive Elements**: Hover effects and visual feedback
- **Modern Typography**: Clean Inter font with proper hierarchy

### 🔍 Subdomain Discovery
- **Multiple Scan Modes**: Normal, Aggressive, and Brutal scanning intensities
- **Advanced DNS Checking**: Tests A, AAAA, CNAME, MX, TXT, and SRV records
- **HTTP Verification**: Confirms subdomains are actually accessible via HTTP/HTTPS
- **Pattern Generation**: Automatically creates subdomain variations with prefixes/suffixes
- **High-Concurrency Scanning**: Up to 100 parallel threads for maximum speed
- **Retry Logic**: Multiple attempts for critical subdomains
- **Custom Subdomain Support**: Add your own subdomains to check

### 🛡️ Security Assessment
- **SSL/TLS Certificate Analysis**: Check certificate validity, expiration, and issuer details
- **Security Headers Analysis**: Comprehensive check for security headers (CSP, HSTS, X-Frame-Options, etc.)
- **Open Ports Scanning**: Detect open ports and identify dangerous services
- **Sensitive Files Detection**: Scan for exposed configuration files, backups, and admin panels
- **Technology Stack Detection**: Identify web frameworks, CMS, and server software
- **Security Score Calculation**: Automated scoring based on security posture
- **Detailed Security Reports**: Export comprehensive JSON reports

### Scan Modes

- **Normal**: Basic DNS checks with 20 threads
- **Aggressive**: Multiple verification methods with 50 threads (recommended)
- **Brutal**: Maximum coverage with 100 threads and extensive pattern generation

### Installation

1. Ensure you have Python installed.
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

### Usage

Run the vigorous subdomain scanner with:
```
streamlit run domain_search.py
```

1. Enter a domain name (e.g., example.com)
2. Choose your scan intensity in the sidebar
3. Enable common subdomains and/or pattern generation
4. Add custom subdomains if desired
5. Click "🚀 Start Scan" and watch the aggressive scanning in action!

### Performance Tips

- **Aggressive mode** provides the best balance of speed and thoroughness
- **Brutal mode** may take longer but finds the most subdomains
- Enable "Generate subdomain variations" for maximum coverage
- The scanner automatically retries failed checks for critical subdomains

## Obfuscation and Deobfuscation App

This is a simple Streamlit application that allows you to obfuscate and deobfuscate text using various encoding methods.

### Features

- **Obfuscate**: Convert plain text into obfuscated text using Base64 or ROT13 encoding.
- **Deobfuscate**: Convert obfuscated text back to plain text.
- Supports two methods: Base64 and ROT13.

### Usage

Run the application with:
```
streamlit run main.py
```

Open the provided URL in your browser to use the app.

Select the obfuscation method from the dropdown, enter your text, and click the appropriate button.

### Notes

- Base64: Standard base64 encoding/decoding.
- ROT13: A simple letter substitution cipher that shifts letters by 13 positions.
- Ensure the obfuscated text matches the selected method for deobfuscation to work.
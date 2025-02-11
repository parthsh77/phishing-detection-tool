import re
import requests
import whois
import ssl
import socket
from datetime import datetime

with open("blacklist.txt", "r") as f:
    BLACKLIST = set(line.strip() for line in f)

def is_suspicious_url(url):
   
    suspicious_patterns = [
        r"https?://[^\s]+@[^\s]+", 
        r"https?://\d+\.\d+\.\d+\.\d+", 
        r"https?://[^\s]+\.[^\s]+\.[^\s]+",  
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, url):
            return True
    return False

def check_blacklist(url):
   
    domain = re.findall(r"https?://([^/]+)", url)[0]
    return domain in BLACKLIST

def check_ssl_certificate(url):
  
    domain = re.findall(r"https?://([^/]+)", url)[0]
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                if expiry_date > datetime.now():
                    return True
    except Exception as e:
        print(f"SSL Certificate Error: {e}")
    return False

def check_domain_reputation(url):
   
    domain = re.findall(r"https?://([^/]+)", url)[0]
    api_key = "YOUR_VIRUSTOTAL_API_KEY" 
    api_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return data["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0
    except Exception as e:
        print(f"Error checking domain reputation: {e}")
    return False

def analyze_url(url):
    
    print(f"Analyzing URL: {url}")
    if is_suspicious_url(url):
        print("Suspicious URL pattern detected!")
    if check_blacklist(url):
        print("Domain is in the phishing blacklist!")
    if not check_ssl_certificate(url):
        print("Invalid or expired SSL certificate!")
    if check_domain_reputation(url):
        print("Domain has a bad reputation!")
    if not (is_suspicious_url(url) or check_blacklist(url) or check_domain_reputation(url)):
        print("URL appears to be safe.")

if __name__ == "__main__":
    url = input("Enter the URL to analyze: ")
    analyze_url(url)

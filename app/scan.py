import requests, re, html
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from urllib.parse import parse_qsl, urlencode, urlsplit, urlparse
from sql_scanner import is_sqli_vulnerable
from xss_scanner import is_xss_vulnerable



def scan_website(url):
    results = {
        'scanned_url': url,
        'vulnerabilities': []
    }

    # Scan the given URL for vulnerabilities
    vulnerabilities = scan_url(url)
    if vulnerabilities:
        results['vulnerabilities'] = vulnerabilities

    return results


def scan_url(url):
    vulnerabilities = {}

    # Step 1: Perform vulnerability scans using a vulnerability scanner or custom checks

    # Example: Check for SQL injection vulnerability
    if is_sqli_vulnerable(url):
        vulnerabilities["SQL injection vulnerability"] = "Injecting SQL code into input fields"

    # Example: Check for cross-site scripting (XSS) vulnerability
    if is_xss_vulnerable(url):
        vulnerabilities["Cross-site scripting (XSS) vulnerability"] = "Injecting malicious scripts into input fields"
    
    #Example: Check for command injection vulnerability
    if is_cmdi_vulnerable(url):
        vulnerabilities["Command injection vulnerability"] = "Injecting commands into input fields"
    
    # Step 2: Perform additional vulnerability checks or manual code review

    # Example: Check for insecure server configuration
    if has_insecure_configuration(url):
        vulnerabilities["Insecure server configuration"] = "Exploiting insecure communication protocols"

    return vulnerabilities

def is_cmdi_vulnerable(url):
        payload =';echo ADD-CMD$((80+20))$(echo 0xsolo)0xsolo'
        poc = "ADD-CMD1000xsolo0xsolo"
        param = dict(parse_qsl(urlsplit(url).query))
        tainted_params = {x: payload for x in param}
        #logs.create_log(logs_des,"Params : "+str(tainted_params))
        if len(tainted_params) > 0:
                attack_url = urlsplit(url).geturl() + urlencode(tainted_params)
                response = requests.post(url=attack_url, data = payload)
                #print(response.text)
                if response.status_code == 200:
                        if poc in response.text:
                                attack_encode=html.escape(attack_url)
                                #logs.create_log(logs_des,"HTML Injection Found : "+str(attack_url))
                                return True
                        else:
                                #logs.create_log(logs_des,"No HTML Injection Found  : "+str(url))
                                return False
                            
def has_insecure_configuration(url):
    # Perform checks for insecure server configuration
    # Example: Check if the website uses HTTP instead of HTTPS
    if not url.startswith("https"):
        return True
    return False

# Get user input for the website URL
#url = input("Enter the URL of the website to scan: ")
#scan_website(url)

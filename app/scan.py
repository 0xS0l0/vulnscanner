import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from cmd_scanner import is_cmdi_vulnerable
from sql_scanner import is_sql_injection_vulnerable
from xss_scanner import is_xss_vulnerable


def scan_website(url):
    results = {
        'discovered_urls': [],
        'vulnerabilities': {}
    }

    # Step 1: Discover URLs on the website
    discovered_urls = discover_urls(url)
    results['discovered_urls'] = discovered_urls

    # Step 2: Scan discovered URLs for vulnerabilities
    for page_url in discovered_urls:
        vulnerabilities = scan_url(page_url)
        if vulnerabilities:
            results['vulnerabilities'][page_url] = vulnerabilities

    return results

def discover_urls(url):
    discovered_urls = []

    # Send a GET request to the given URL
    response = requests.get(url)
    if response.status_code == 200:
        # Parse the HTML content of the response
        soup = BeautifulSoup(response.text, "html.parser")

        # Find all anchor tags and extract URLs
        for anchor_tag in soup.find_all("a"):
            href = anchor_tag.get("href")
            if href:
                absolute_url = urljoin(url, href)
                # Filter out non-HTTP(S) URLs and other invalid URLs
                if absolute_url.startswith("http://") or absolute_url.startswith("https://"):
                    discovered_urls.append(absolute_url)

    return discovered_urls



def scan_url(url):
    vulnerabilities = {}

    # Step 1: Perform vulnerability scans using a vulnerability scanner or custom checks

    # Example: Check for SQL injection vulnerability
    if is_sql_injection_vulnerable(url):
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

    
def has_insecure_configuration(url):
    # Perform checks for insecure server configuration
    # Example: Check if the website uses HTTP instead of HTTPS
    if not url.startswith("https"):
        return True
    return False

# Get user input for the website URL
#url = input("Enter the URL of the website to scan: ")
#scan_website(url)

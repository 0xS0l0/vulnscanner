import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin


def scan_website(url):
    # Step 1: Discover URLs on the website
    discovered_urls = discover_urls(url)
    print(f"Discovered {len(discovered_urls)} URLs on {url}:\n")
    for i, discovered_url in enumerate(discovered_urls, start=1):
        print(f"{i}. {discovered_url}")

    # Step 2: Scan discovered URLs for vulnerabilities
    for page_url in discovered_urls:
        vulnerabilities = scan_url(page_url)
        if vulnerabilities:
            print(f"\nVulnerabilities found on {page_url}:")
            for vulnerability, attack_method in vulnerabilities.items():
                print(f"\nVulnerability: {vulnerability}")
                print(f"Attack Method: {attack_method}")


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


def is_sql_injection_vulnerable(url):
    # Perform checks for SQL injection vulnerability
    # Example: Send a malicious SQL query and check the response
    payload = "' OR '1'='1"
    response = requests.get(url + "?id=" + payload)
    if re.search(r"error|warning", response.text, re.IGNORECASE):
        return True
    return False


def is_xss_vulnerable(url):
    # Perform checks for cross-site scripting (XSS) vulnerability
    # Example: Inject a script tag and check if it gets executed
    payload = "<script>alert('XSS')</script>"
    response = requests.get(url + "?input=" + payload)
    if payload in response.text:
        return True
    return False


def is_cmdi_vulnerable(url):
    # Perform checks for command injection vulnerability
    # Example: Send commands and check the response
    response = requests.get(url)

    payloads = [";ls", ";whoami", ";id"]  # Add more payloads as needed

    # Iterate over each payload
    for payload in payloads:
        # Inject the payload into the URL
        injected_url = url + f"?param={payload}"

        # Make a request with the injected URL
        injected_response = requests.get(injected_url)

        # Check if the payload resulted in any changes
        if injected_response.text != response.text:
            return True  # Vulnerability detected

    return False  # No vulnerability detected

    
    
def has_insecure_configuration(url):
    # Perform checks for insecure server configuration
    # Example: Check if the website uses HTTP instead of HTTPS
    if not url.startswith("https"):
        return True
    return False


# Get user input for the website URL
url = input("Enter the URL of the website to scan: ")
scan_website(url)

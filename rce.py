import requests

def rce_scan(url, payloads):
    for payload in payloads:
        target_url = url + payload
        response = requests.get(target_url)
        if response.status_code == 200:
            # Check if response contains a specific string indicating successful code execution
            if "Successful RCE" in response.text:
                print(f"Potential RCE found: {target_url}")

# Example payloads to test for RCE
payloads = [
    "?cmd=ls",
    "?cmd=whoami",
    # Add more payloads as needed
]

# URL to scan for RCE vulnerability
target_url = "http://example.com/page.php"

rce_scan(target_url, payloads)
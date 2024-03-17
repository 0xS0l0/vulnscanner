from urllib.parse import urlparse,urljoin
import requests
from bs4 import BeautifulSoup

def discover_urls(url):
    discovered_urls = []

    # Parse the given URL to extract the host
    parsed_url = urlparse(url)
    host = parsed_url.netloc

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
                # Parse the absolute URL to extract the host
                parsed_absolute_url = urlparse(absolute_url)
                absolute_host = parsed_absolute_url.netloc
                # Check if the host of the absolute URL matches the host of the given URL
                if absolute_host == host:
                    discovered_urls.append(absolute_url)

    return discovered_urls

url = input("enter the url : ")
print(discover_urls(url))

	

    
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

def get_certificate_details(url):
    # Extract hostname from URL
    hostname = urlparse(url).hostname
    
    if not hostname:
        raise ValueError(f"Invalid URL: {url}")

    # Establish SSL connection
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    
    try:
        # Connect to the server
        conn.connect((hostname, 443))
        
        # Get the certificate
        cert = conn.getpeercert()

        # Extract issuer
        issuer = dict(x[0] for x in cert['issuer'])

        # Extract issue and expiry dates
        not_before = cert['notBefore']
        not_after = cert['notAfter']

        # Convert date strings to datetime objects
        not_before_dt = datetime.strptime(not_before, '%b %d %H:%M:%S %Y GMT')
        not_after_dt = datetime.strptime(not_after, '%b %d %H:%M:%S %Y GMT')
        
        return {
            'issuer': issuer,
            'issue_date': not_before_dt.isoformat(),
            'expiry_date': not_after_dt.isoformat()
        }
    
    finally:
        conn.close()

def get_certificates_details(url_list):
    details = {}
    for url in url_list:
        try:
            cert_details = get_certificate_details(url)
            details[url] = cert_details
        except Exception as e:
            details[url] = str(e)
    
    return details

# Example usage
urls = [
    'https://www.example.com',
    'https://www.google.com',
    'https://www.yahoo.com'
]

certificates_details = get_certificates_details(urls)
for url, details in certificates_details.items():
    print(f'URL: {url}')
    print(f'Issuer: {details.get("issuer")}')
    print(f'Issue Date: {details.get("issue_date")}')
    print(f'Expiry Date: {details.get("expiry_date")}\n')

#!/usr/bin/env python
import ssl
import csv
import socket
import argparse
from alive_progress import alive_bar
from ssl import SSLCertVerificationError
from urllib.parse import urlparse
from datetime import datetime

def get_one_cert(url, timeout):
    """
    Retrieves the certificate details for a given URL.

    Args:
        url (str): The URL to retrieve the certificate details from.
        timeout (int): The timeout value in seconds for the connection.

    Returns:
        dict: A dictionary containing the following certificate details:
            - issuer (dict): The issuer of the certificate.
            - issue_date (str): The issue date of the certificate in ISO format.
            - expiry_date (str): The expiry date of the certificate in ISO format.

    Raises:
        ValueError: If the URL is invalid.
        SSLCertVerificationError: If certificate verification fails.
        ConnectionResetError: If the connection is reset.
        TimeoutError: If the connection times out.

    """
    # Extract hostname from URL
    hostname = urlparse(url).hostname
    
    if not hostname:
        raise ValueError(f"Invalid URL: {url}")

    # Establish SSL connection
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    conn.settimeout(timeout) # Add custom timeout value

    try:
        # Connect to the server
        conn.connect((hostname, 443))
        
        # Get the certificate
        cert = conn.getpeercert()

        # Extract issuer
        issuer = {}
        for item in cert['issuer']:
            issuer.update({x:y for x,y in item})

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
    except SSLCertVerificationError:
        return 'SSL Verification Error'
    except ConnectionResetError:
        return 'Connection Reset by Origin'
    except TimeoutError:
        return 'Connection Timeout'
    except Exception as e:
        return f'Unexpected Error: {e}'
    
    finally:
        conn.close()

def get_all_certs(url_list, timeout):
    """
    Retrieves the details of certificates for a given list of URLs.

    Args:
        url_list (list): A list of URLs for which to retrieve certificate details.

    Returns:
        tuple: A tuple containing two dictionaries. The first dictionary maps each URL to its corresponding certificate details.
               The second dictionary contains the list of URLs for which certificate details could not be retrieved due to SSL failures.
    """
    details = {}
    ssl_failed = []
    with alive_bar(len(url_list), title='Requesting Certificate Details', bar='classic') as bar:
        for url in url_list:
            cert_details = get_one_cert(url, timeout)
            if isinstance(cert_details, str):
                ssl_failed.append(f'{url}: {cert_details}')
            else:
                details[url] = cert_details
            bar()
    return details, ssl_failed

def generate_url_list_from_csv(csv_input):
    """
    Generates a list of URLs from a CSV file.

    Args:
        csv_input (str): The path to the CSV file.

    Returns:
        list: A list of URLs with the 'https://' prefix added.
    """
    urls = []
    with open(csv_input, 'r') as data:
        # Read the CSV file using columns variable to select columns and create a list of hostnames if protocol value is SSL or HTTPS
        reader = csv.DictReader(data, delimiter=",")
        with alive_bar(title='Reading Log Data', bar='classic') as bar:
            for row in reader:
                if row['protocol'] == 'SSL' or row['protocol'] == 'HTTPS':
                    urls.append('https://' + row['hostname'])
                    bar()
    return urls

def generate_url_list_from_txt(txt_input):
    """
    Generates a list of URLs from a text file.

    Args:
        txt_input (str): The path to the text file.

    Returns:
        list: A list of URLs with the 'https://' prefix added.
    """
    urls = []
    with open(txt_input, 'r') as data:
        # Read the text file and create a list of hostnames
        with alive_bar(title='Reading Text File Input', bar='classic') as bar:
            for line in data:
                urls.append('https://' + line.rstrip())
                bar()
    return urls

def write_results(certificates_details: dict, csv_output: str):
    """
    Writes the certificate details to a CSV file.

    Args:
        certificates_details (dict): A dictionary containing the certificate details for each URL.
        csv_output (str): The path to the CSV file to write the results to.

    Returns:
        None
    """
    fieldnames=['URL', 'Issuer Country Name','Issuer Organization Name','Issuer Common Name','Issue Date', 'Expiry Date']
    with open(csv_output, 'w') as file:
        writer = csv.writer(file)
        writer.writerow(fieldnames)
        with alive_bar(len(certificates_details), title='Writing Results', bar='classic') as bar:
            for url, details in certificates_details.items():
                if not details:
                    continue
                writer.writerow([f'{url}',f'{details["issuer"]["countryName"]}',f'{details["issuer"]["organizationName"]}',f'{details["issuer"]["commonName"]}',f'{details["issue_date"]}',f'{details["expiry_date"]}'])
                bar()
                
def write_errors(failed_urls: list, error_log: str):
    """
    Writes a list of failed URLs to an error log file.

    Args:
        failed_urls (list): A list of URLs that failed.
        error_log (str): The path to the error log file.

    Returns:
        None
    """
    if not failed_urls:
        return
    with open(error_log, 'w') as file:
        file.write('********** ERROR DESCRIPTION **********\n')
        file.write('SSL Verification Error: Likely using self-signed certificate or HSTS with cert pinning\n')
        file.write('Connection Reset by Origin: Server reset the connection\n')
        file.write('Connection Timeout: Connection timed-out without a response\n') 
        file.write('Unexpected Error: <error_str>\n')
        file.write('************** ERROR LOG **************\n')
        with alive_bar(len(failed_urls), title='Writing Error Log', bar='classic') as bar:
            for item in failed_urls:
                file.write(f'{item.replace("https://", "")}\n')
                bar()
            
def generate_target_root_list(target_roots):
    """
    Generates a list of target roots by reading the contents of the `target_roots` file.

    Parameters:
        target_roots (str): The path to the file containing the target roots.

    Returns:
        list: A list of target roots, each represented as a string.
    """
    roots = []
    with open(target_roots, 'r') as file:
        for line in file:
            roots.append(line.replace('\n', ''))
    print(roots)
    return roots

def evaluate_target_root_list(targets: list, certificates_details: dict):
    """
    Evaluate the target root list based on the provided targets and certificate details.

    Parameters:
        targets (list): A list of target roots to evaluate.
        certificates_details (dict): A dictionary containing certificate details for each URL.

    Returns:
        dict: A dictionary of target URLs that match the provided targets.
    """
    target_urls = {}
    for url, details in certificates_details.items():
        if details["issuer"]["commonName"] in targets:
            target_urls.update(certificates_details)
    return target_urls
                    
def main(csv_input: str, csv_output: str, error_log: str, txt_input: str, timeout: float, target_roots: str, target_output: str):
    """
    The main function that takes in four parameters:

    Args:
        csv_input (str): The path to the input CSV file.
        csv_output (str): The path to the output CSV file.
        error_log (str): The path to the error log file.
        txt_input (str): The path to the input text file.
        timeout (float): The timeout value in seconds for the connection.
        target_roots (str): The path to the file containing the trusted root certificates.
        target_output (str): The path to the output file containing the target URLs.

    This function reads the input CSV or text file to generate a list of URLs.
    It then calls the get_certificates_details function to retrieve the certificate details
    for each URL. The function writes the certificate details to the output CSV file
    and the failed URLs to the error log file.
    """
    # Generate a list of URLs from CSV or text file
    if txt_input:
        urls = list(set(generate_url_list_from_txt(txt_input)))  # Remove duplicates from the list
    else:
        urls = list(set(generate_url_list_from_csv(csv_input)))

    # Get certificate details for each URL
    certificates_details, failed_urls = get_all_certs(urls, timeout)

    # If target roots are provided, filter the certificates based on the target roots
    if target_roots:
        targets = generate_target_root_list(target_roots)
        target_urls = evaluate_target_root_list(targets, certificates_details)
        write_results(target_urls, target_output)

    # Write certificate details to output CSV file
    write_results(certificates_details, csv_output)

    # Write failed URLs to error log file
    write_errors(failed_urls, error_log)

if __name__ == '__main__':
    argParser = argparse.ArgumentParser(prog='cert_audit.py',
                    description='''
                    This utility will audit the certificates used by a list of origin servers. The input file must be in CSV format and is anticipated to be an export of log data.
                    The CSV file must contain a column with the hostname and a column with the protocol. The protocol must be SSL or HTTPS for hostname's to be selected for audit.
                    The hostname should be formatted as host.example.com (Must not include leading https:// or trailing /path).
                    ''',
                    epilog='''
                    Default input file is 'input.csv', default output file is 'output.csv', default error log is error.log, default timeout is 3 seconds
                    If '--text_input' is provided it will override the CSV input file. Text input option should be formatted as a plain text file formatted with one hostname per line.
                    ''')
    argParser.add_argument("--timeout", "-t", default=3, type=float, help="Set timeout in seconds for connection to origin servers")
    argParser.add_argument("--input_file", "-i", default='input.csv', type=str, help="CSV formatted log data used as input")
    argParser.add_argument("--output_file", "-o", default='output.csv', type=str, help="CSV formatted audit results to be output")
    argParser.add_argument("--text_input", "-x", default='', type=str, help="Alternate input file formatted as a flat text file with fqdns only")
    argParser.add_argument("--error_log", "-e", default='errors.log', type=str, help="Error log file")
    argParser.add_argument("--target_roots", "-r", default='', type=str, help="Explicit root servers of interest")
    argParser.add_argument("--target_file", "-f", default='target_output.csv', type=str, help="Output of servers that match with targeted roots")
    args = argParser.parse_args()
    INPUT_FILE = args.input_file
    OUTPUT_FILE = args.output_file
    TEXT_INPUT = args.text_input
    ERROR_LOG = args.error_log
    TIMEOUT = args.timeout
    TARGET_ROOTS = args.target_roots
    TARGET_FILE = args.target_file
    main(INPUT_FILE, OUTPUT_FILE, ERROR_LOG, TEXT_INPUT, TIMEOUT, TARGET_ROOTS, TARGET_FILE)
    
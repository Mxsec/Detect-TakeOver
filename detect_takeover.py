#!/usr/bin/env python3
"""
Detect TakeOver Tool
Author: Mateus
Description: A tool for detecting subdomain takeover vulnerabilities.
"""

import sys
import argparse
import dns.resolver
import requests

# List of vulnerable providers (based on can-i-take-over-xyz)
VULNERABLE_PROVIDERS = {
    "azurewebsites.net": "Azure (Websites)",
    "cloudapp.net": "Azure (Cloud App)",
    "herokuapp.com": "Heroku",
    "s3.amazonaws.com": "Amazon S3",
    "github.io": "GitHub Pages",
    "wordpress.com": "WordPress",
    "bitbucket.io": "Bitbucket",
    "pantheon.io": "Pantheon",
    "fastly.net": "Fastly",
    "ghost.io": "Ghost",
    "surge.sh": "Surge.sh",
    "render.com": "Render",
    "unbouncepages.com": "Unbounce",
    "tilda.ws": "Tilda",
    "akamaized.net": "Akamai",
    "netlify.com": "Netlify",
    "readthedocs.io": "ReadTheDocs",
    "shopify.com": "Shopify",
    "smugmug.com": "SmugMug",
    "stackpathcdn.com": "StackPath CDN",
    "datocms.com": "DatoCMS",
    "thinkific.com": "Thinkific",
    "zendesk.com": "Zendesk",

    # Add more providers as needed
}

def display_banner():
    """
    Displays the "TAKE OVER" banner.
    """
    print("""
████████╗ █████╗ ██╗  ██╗███████╗     ██████╗ ██╗   ██╗███████╗██████╗  
╚══██╔══╝██╔══██╗██║ ██╔╝██╔════╝    ██╔═══██╗██║   ██║██╔════╝██╔══██╗ 
   ██║   ███████║█████╔╝ █████╗      ██║   ██║██║   ██║█████╗  ██████╔╝ 
   ██║   ██╔══██║██╔═██╗ ██╔══╝      ██║   ██║██║   ██║██╔══╝  ██╔═══╝  
   ██║   ██║  ██║██║  ██║███████╗    ╚██████╔╝╚██████╔╝███████╗██║  ██╗ 
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝     ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝ 
                                                                         
                      === Detect TakeOver Tool ===
    """)

def log(message, level="INFO"):
    """
    Logs messages with different levels.
    """
    levels = {
        "INFO": "\033[94m[INFO]\033[0m",
        "ALERT": "\033[93m[ALERT]\033[0m",
        "SUCCESS": "\033[92m[SUCCESS]\033[0m",
        "ERROR": "\033[91m[ERROR]\033[0m",
    }
    print(f"{levels.get(level, '[INFO]')} {message}")

def check_cname(subdomain):
    """
    Checks the CNAME record for a subdomain.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['1.1.1.1', '8.8.8.8']  # Cloudflare and Google DNS
        resolver.lifetime = 10
        answers = resolver.resolve(subdomain, 'CNAME')
        for rdata in answers:
            cname = str(rdata.target).strip('.')
            log(f"CNAME for {subdomain}: {cname}")
            return cname
    except dns.resolver.NoAnswer:
        log(f"No CNAME record found for {subdomain}.", "INFO")
    except dns.resolver.NXDOMAIN:
        log(f"The domain {subdomain} does not exist.", "ERROR")
    except Exception as e:
        log(f"Failed to check CNAME for {subdomain}: {e}", "ERROR")
    return None

def check_cname_provider(cname):
    """
    Checks if the CNAME matches a known vulnerable provider.
    """
    for provider, name in VULNERABLE_PROVIDERS.items():
        if provider in cname:
            log(f"Vulnerable provider detected: {name} ({provider})", "ALERT")
            return name
    log("No vulnerable provider detected for this CNAME.", "INFO")
    return None

def check_http_response(subdomain):
    """
    Checks the HTTP response of the subdomain for signs of vulnerability.
    """
    urls = [f"http://{subdomain}/", f"https://{subdomain}/"]
    for url in urls:
        try:
            response = requests.get(url, timeout=5)
            status_code = response.status_code
            log(f"{url} responded with HTTP {status_code}")
            if status_code in [403, 404, 401, 500]:
                log(f"Subdomain responded with HTTP {status_code}: {url}", "ALERT")
                return True
        except requests.exceptions.ConnectionError:
            log(f"Could not connect to {url}", "ERROR")
        except Exception as e:
            log(f"Failed to check {url}: {e}", "ERROR")
    return False

def process_subdomain(subdomain):
    """
    Processes a single subdomain for potential takeover vulnerabilities.
    """
    log(f"Checking {subdomain}", "INFO")
    cname = check_cname(subdomain)
    if cname:
        provider = check_cname_provider(cname)
        is_vulnerable = check_http_response(subdomain)
        if provider and is_vulnerable:
            log(f"Potential takeover detected: {subdomain} (Provider: {provider})", "SUCCESS")
        else:
            log(f"Subdomain appears safe: {subdomain}", "INFO")
    else:
        log(f"No CNAME record found or no takeover risk detected for {subdomain}", "INFO")

def main():
    """
    Main function to execute the tool.
    """
    display_banner()
    parser = argparse.ArgumentParser(
        description="Detect TakeOver Tool - A script for identifying subdomain takeover vulnerabilities."
    )
    parser.add_argument("-d", "--domain", help="Single subdomain to check (e.g., -d example.com)")
    parser.add_argument("-l", "--list", help="File containing a list of subdomains (e.g., -l subdomains.txt)")
    args = parser.parse_args()

    if args.domain:
        process_subdomain(args.domain)
    elif args.list:
        try:
            with open(args.list, "r") as f:
                subdomains = [line.strip() for line in f.readlines()]
                for subdomain in subdomains:
                    process_subdomain(subdomain)
        except FileNotFoundError:
            log(f"File {args.list} not found.", "ERROR")
    else:
        log("You must specify either -d <domain> or -l <list>", "ERROR")
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()

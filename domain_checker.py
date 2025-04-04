import base64
import requests
import logging
import os
from typing import Tuple
from dotenv import load_dotenv


# Load environment variables if using .env file
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
ISMALICIOUS_API_KEY = os.getenv('ISMALICIOUS_API_KEY')
ISMALICIOUS_API_SECRET = os.getenv('ISMALICIOUS_API_SECRET')

log_level = logging.INFO
logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def check_ip_ismalicious(domain: str) -> Tuple[int, int]:
    """
    Checks if a domain is listed as malicious or suspicious by IsMalicious.com.

    ARGS:
        domain: Domain name to be checked with IsMalicious API

    Returns:
         Tuple[malware score, suspicion score]
    """
    if not ISMALICIOUS_API_KEY or not ISMALICIOUS_API_SECRET:
        logger.warning("IsMalicious API key or SECRET key not configured. Skipping check.")
        return 0,0
    if not domain:
        return 0,0

    api_url = f"https://ismalicious.com/api/check/reputation?query={domain}"

    auth_string = f"{ISMALICIOUS_API_KEY}:{ISMALICIOUS_API_SECRET}"
    auth_bytes = auth_string.encode('utf-8')  # Encode the string to bytes
    base64_bytes = base64.b64encode(auth_bytes)  # Perform Base64 encoding
    base64_string = base64_bytes.decode('utf-8')  # Decode the bytes back to a string

    headers = {
        'Accept': 'application/json',
        "X-API-KEY": base64_string
    }

    try:
        response = requests.get(api_url, headers=headers, timeout=3)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)  # TODO: implement in a better way

        data = response.json()

        reputation_data = data.get('reputation', {})

        malicious_count = reputation_data.get('malicious', 0)  # Get malicious count, default 0
        suspicious_count = reputation_data.get('suspicious', 0)  # Get suspicious count, default 0

        if suspicious_count > 0:
            logger.warning(f"[!] isMalicious check: [{domain}] flagged as SUSPICIOUS with score {suspicious_count}")
        if malicious_count > 0:
            logger.warning(f"[!!!] isMalicious check: [{domain}] flagged as MALICIOUS with score {malicious_count}")

        return malicious_count, suspicious_count

    except requests.exceptions.Timeout:
        logger.error(f"Error checking {domain} with IsMalicious: Request timed out.")
        return 0,0 # Treat timeout as non-malicious for safety, or handle differently
    except requests.exceptions.RequestException as e:
        logger.error(f"Error checking {domain} with IsMalicious: {e}")
        return 0,0 # Treat errors as non-malicious for safety
    except Exception as e:
        logger.error(f"Unexpected error checking {domain} with IsMalicious: {e}")
        return 0,0

def check_ip_virustotal(domain: str) -> Tuple[int, int]:
    """
    Checks if a domain is listed as malicious or suspicious by VirusTotal API v3.

    ARGS:
        domain: URL to be checked with VirusTotal API v3

    Returns:
         Tuple[malware score, suspicion score]
    """

    if not VIRUSTOTAL_API_KEY:
        logger.warning("VirusTotal API key not configured. Skipping check.")
        return 0,0
    if not domain:
        return 0,0

    # General option for URL check
    #domain_id = base64.urlsafe_b64encode(domain.encode()).decode().strip("=")
    #api_url = f"https://www.virustotal.com/api/v3/urls/{domain_id}"

    api_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        response = requests.get(api_url, headers=headers, timeout=3)
        response.raise_for_status()

        data = response.json()

        malicious_count = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
        suspicious_count = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('suspicious', 0)

        if suspicious_count > 0:
            logger.warning(f"[!] VirusTotal check: [{domain}] flagged as SUSPICIOUS with score {suspicious_count}")
        if malicious_count > 0:
            logger.warning(f"[!!!] VirusTotal check: [{domain}] flagged as MALICIOUS with score {malicious_count}")

        return malicious_count, suspicious_count

    except requests.exceptions.Timeout:
        logger.error(f"Error checking {domain} with VirusTotal: Request timed out.")
        return 0,0
    except requests.exceptions.RequestException as e:
        logger.error(f"Error checking {domain} with VirusTotal: {e} (Status: {response.status_code})")
        return 0,0
    except Exception as e:
        logger.error(f"Unexpected error checking {domain} with VirusTotal: {e}")
        return 0,0

if __name__ == "__main__":

    domain = "paypa1.com"

    malicious, suspicious = check_ip_virustotal(domain)
    print(f"Virustotal result for {domain}:")
    print(f"\t\t malicious: {malicious}")
    print(f"\t\t suspicious: {suspicious}")

    malicious, suspicious = check_ip_ismalicious(domain)
    print(f"IsMalicious result for {domain}:")
    print(f"\t\t malicious: {malicious}")
    print(f"\t\t suspicious: {suspicious}")

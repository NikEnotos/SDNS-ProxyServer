import base64
import requests
import logging
import os
import threading
from typing import Tuple, Optional
from dotenv import load_dotenv


# Load environment variables if using .env file
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
ISMALICIOUS_API_KEY = os.getenv('ISMALICIOUS_API_KEY')
ISMALICIOUS_API_SECRET = os.getenv('ISMALICIOUS_API_SECRET')

log_level = logging.WARNING
logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DomainChecker:
    """
    Checks a domain using VirusTotal and IsMalicious APIs concurrently.

    Attributes:
        domain (str): The domain name to check.
        vt_malicious (int): Malicious score from VirusTotal (0 if not checked/error).
        vt_suspicious (int): Suspicious score from VirusTotal (0 if not checked/error).
        im_malicious (int): Malicious score from IsMalicious (0 if not checked/error).
        im_suspicious (int): Suspicious score from IsMalicious (0 if not checked/error).
        _vt_thread (Optional[threading.Thread]): Thread for VirusTotal check.
        _im_thread (Optional[threading.Thread]): Thread for IsMalicious check.
        lock (threading.Lock): Lock to ensure thread-safe updates to scores.
    """

    def __init__(self, domain: str):
        """
        Initializes the DomainChecker for a specific domain.

        Args:
            domain: The domain name to check.
        """
        if not isinstance(domain, str) or not domain:
            raise ValueError("A valid domain string must be provided.")

        self.domain = domain
        self.vt_malicious = 0
        self.vt_suspicious = 0
        self.im_malicious = 0
        self.im_suspicious = 0
        self._vt_thread: Optional[threading.Thread] = None
        self._im_thread: Optional[threading.Thread] = None
        # Lock for thread-safe updates
        self.lock = threading.Lock()
        #self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")  # Instance-specific logger
        # Set up logging
        logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    def _check_domain_ismalicious_thread(self):
        """Internal method to run IsMalicious check in a thread."""

        if not ISMALICIOUS_API_KEY or not ISMALICIOUS_API_SECRET:
            logger.warning("IsMalicious API key or SECRET key not configured. Skipping check.")
            return
        if not self.domain:
            self.logger.warning("Empty domain passed to IsMalicious check.")
            return

        api_url = f"https://ismalicious.com/api/check/reputation?query={self.domain}"

        auth_string = f"{ISMALICIOUS_API_KEY}:{ISMALICIOUS_API_SECRET}"
        auth_bytes = auth_string.encode('utf-8')  # Encode the string to bytes
        base64_bytes = base64.b64encode(auth_bytes)  # Perform Base64 encoding
        base64_string = base64_bytes.decode('utf-8')  # Decode the bytes back to a string

        headers = {
            'Accept': 'application/json',
            "X-API-KEY": base64_string
        }

        malicious_count = 0
        suspicious_count = 0
        try:
            response = requests.get(api_url, headers=headers, timeout=3)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)  # TODO: implement in a better way

            data = response.json()

            reputation_data = data.get('reputation', {})

            malicious_count = reputation_data.get('malicious', 0)  # Get malicious count, default 0
            suspicious_count = reputation_data.get('suspicious', 0)  # Get suspicious count, default 0

            if suspicious_count > 0:
                logger.warning(f"[!] isMalicious check: [{self.domain}] flagged as SUSPICIOUS with score {suspicious_count}")
            if malicious_count > 0:
                logger.warning(f"[!!!] isMalicious check: [{self.domain}] flagged as MALICIOUS with score {malicious_count}")

        except requests.exceptions.Timeout:
            logger.error(f"Error checking {self.domain} with IsMalicious: Request timed out.")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.info(f"IsMalicious check: Domain {self.domain} not found (404).")
            elif e.response.status_code == 429:
                logger.warning(f"IsMalicious check: Rate limit exceeded (429).")
            else:
                logger.error(f"Error checking {self.domain} with IsMalicious: HTTP {e.response.status_code} - {e}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error checking {self.domain} with IsMalicious: {e}")
        except Exception as e:
            logger.error(f"Unexpected error checking {self.domain} with IsMalicious: {e}")
        finally:
            # Safely update the instance attributes
            with self.lock:
                self.im_malicious = malicious_count
                self.im_suspicious = suspicious_count

    def _check_domain_virustotal_thread(self):
        """Internal method to run VirusTotal check in a thread."""

        if not VIRUSTOTAL_API_KEY:
            logger.warning("VirusTotal API key not configured. Skipping check.")
            return
        if not self.domain:
            self.logger.warning("Empty domain passed to VirusTotal check.")
            return

        # General option for URL check
        #domain_id = base64.urlsafe_b64encode(domain.encode()).decode().strip("=")
        #api_url = f"https://www.virustotal.com/api/v3/urls/{domain_id}"

        api_url = f"https://www.virustotal.com/api/v3/domains/{self.domain}"
        headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_API_KEY
        }

        malicious_count = 0
        suspicious_count = 0
        try:
            response = requests.get(api_url, headers=headers, timeout=3)
            response.raise_for_status()

            data = response.json()

            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)

            if suspicious_count > 0:
                logger.warning(f"[!] VirusTotal check: [{self.domain}] flagged as SUSPICIOUS with score {suspicious_count}")
            if malicious_count > 0:
                logger.warning(f"[!!!] VirusTotal check: [{self.domain}] flagged as MALICIOUS with score {malicious_count}")

        except requests.exceptions.Timeout:
            logger.error(f"Error checking {self.domain} with VirusTotal: Request timed out.")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error checking {self.domain} with VirusTotal: {e}")
        except Exception as e:
            logger.error(f"Unexpected error checking {self.domain} with VirusTotal: {e}")
        finally:
            # Safely update the instance attributes
            with self.lock:
                self.vt_malicious = malicious_count
                self.vt_suspicious = suspicious_count

    def start_checks(self):
        """Starts the VirusTotal and IsMalicious checks in separate threads."""
        if not self._vt_thread:
            self._vt_thread = threading.Thread(target=self._check_domain_virustotal_thread, daemon=True)
            self._vt_thread.start()
            self.logger.debug(f"Started VirusTotal check thread for {self.domain}")

        if not self._im_thread:
            self._im_thread = threading.Thread(target=self._check_domain_ismalicious_thread, daemon=True)
            self._im_thread.start()
            self.logger.debug(f"Started IsMalicious check thread for {self.domain}")


    def wait_for_completion(self, timeout: Optional[float] = 5.0):
        """
        Waits for check threads to complete.

        Args:
            timeout: Maximum time in seconds to wait for each thread. Defaults to 5.0.
                     None means wait indefinitely.
        """
        if self._vt_thread and self._vt_thread.is_alive():
            self.logger.debug(f"Waiting for VirusTotal thread ({self.domain})...")
            self._vt_thread.join(timeout=timeout)
            if self._vt_thread.is_alive():
                self.logger.warning(f"VirusTotal check thread for {self.domain} timed out after {timeout}s.")

        if self._im_thread and self._im_thread.is_alive():
            self.logger.debug(f"Waiting for IsMalicious thread ({self.domain})...")
            self._im_thread.join(timeout=timeout)
            if self._im_thread.is_alive():
                self.logger.warning(f"IsMalicious check thread for {self.domain} timed out after {timeout}s.")
        self.logger.debug(f"All checks completed or timed out for {self.domain}")


    def get_scores(self) -> Tuple[int, int, int, int]:
        """
        Returns the collected scores after checks have run (or timed out).

        Returns:
            A tuple containing: (vt_malicious, vt_suspicious, im_malicious, im_suspicious)
        """
        with self.lock:  # Ensure reading consistent values
            return self.vt_malicious, self.vt_suspicious, self.im_malicious, self.im_suspicious


    def is_malicious(self, threshold: int = 1) -> bool:
        """Checks if the domain exceeds the malicious threshold from either source."""
        with self.lock:
            return self.vt_malicious >= threshold or self.im_malicious >= threshold


    def is_suspicious(self, threshold: int = 1) -> bool:
        """Checks if the domain exceeds the suspicious threshold from either source."""
        with self.lock:
            return self.vt_suspicious >= threshold or self.im_suspicious >= threshold



if __name__ == "__main__":
    test_domain = "google.com" # Replace with a domain to test
    checker = DomainChecker(test_domain)

    print(f"Starting checks for {test_domain}...")
    checker.start_checks()

    print("Waiting for checks to complete...")
    checker.wait_for_completion(timeout=6) # Wait up to 6 seconds

    vt_mal, vt_susp, im_mal, im_susp = checker.get_scores()
    print(f"\nResults for {test_domain}:")
    print(f"  VirusTotal -> Malicious: {vt_mal}, Suspicious: {vt_susp}")
    print(f"  IsMalicious -> Malicious: {im_mal}, Suspicious: {im_susp}")

    if checker.is_malicious():
        print(f"  Overall Status: MALICIOUS")
    elif checker.is_suspicious():
        print(f"  Overall Status: SUSPICIOUS")
    else:
        print(f"  Overall Status: Clean")


    # Test with potentially malicious domain
    test_domain_bad = "testphp.vulnweb.com" # Known vulnerable site, might be flagged
    checker_bad = DomainChecker(test_domain_bad)
    print(f"\nStarting checks for {test_domain_bad}...")
    checker_bad.start_checks()

    print("Waiting for checks to complete...")
    checker_bad.wait_for_completion(timeout=6)

    vt_mal, vt_susp, im_mal, im_susp = checker_bad.get_scores()
    print(f"\nResults for {test_domain_bad}:")
    print(f"  VirusTotal -> Malicious: {vt_mal}, Suspicious: {vt_susp}")
    print(f"  IsMalicious -> Malicious: {im_mal}, Suspicious: {im_susp}")

    if checker_bad.is_malicious():
        print(f"  Overall Status: MALICIOUS")
    elif checker_bad.is_suspicious():
        print(f"  Overall Status: SUSPICIOUS")
    else:
        print(f"  Overall Status: Clean")

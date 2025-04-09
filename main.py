import argparse
import sys
import re
import logging
import socket
from dns_proxy import DNSProxyServer

# Default DoH providers
DEFAULT_DOH_PROVIDERS = [
    'https://1.1.1.1/dns-query',
    'https://1.0.0.1/dns-query',
    'https://8.8.8.8/dns-query',
    'https://8.8.4.4/dns-query',
    'https://9.9.9.9:5053/dns-query',
    'https://149.112.112.112:5053/dns-query'
]

# Define regex allowing DoH URLs with IP addresses
# Regex breakdown:
    # ^https://       : Starts with https://
    # (               : Start group for host
    #  \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} : IPv4 address
    # )               : End group for host
    # (:[0-9]{1,5})?  : Optional port (1-5 digits)
    # (/[\w\-./?=&%]*)? : Optional path (alphanumeric, -, ., /, ?, =, &, %)
    # $               : End of string
DOH_URL_PATTERN = re.compile(
     r'^https://' # Must start with https://
     r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # IPv4 address
     r'(:[0-9]{1,5})?' # Optional port
     r'(/[\w\-.=&?%+~#]*)?' # Optional path (allowing more chars like ~+#)
     r'$' # End of string
)

# Simple IPv4/IPv6 regex for redirect IP validation
IP_ADDRESS_PATTERN = re.compile(
    r'^('
    # IPv4
    r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    r'|' # Or
    # IPv6 (simplified, accepts valid formats but not exhaustive validation)
    r'([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|'
    r'([0-9a-fA-F]{1,4}:){1,7}:|'
    r'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
    r'([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'
    r'([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'
    r'([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'
    r'([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|'
    r'[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'
    r':((:[0-9a-fA-F]{1,4}){1,7}|:)|'
    r'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'
    r'::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|'
    r'([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
    r')$'
)

def validate_doh_url(url_string):
    """
    Validates if a string is a plausible DoH URL using regex.
    Allows https://, IP addresses, optional ports, and optional paths.
    Raises ArgumentTypeError if the format is invalid.

    Args:
        url_string: string to check for URL format
    """
    if not DOH_URL_PATTERN.match(url_string):
        raise argparse.ArgumentTypeError(
            f"Invalid DoH URL format: '{url_string}'. "
            "Must start with https://, followed by a valid domain or IP, optional port, and optional path."
        )
    # Return the valid string if it matches
    return url_string

def validate_ip_address(ip_string):
    """
    Validates if a string is a valid IPv4 address.

    Args:
        ip_string: string of IPv4 address to validate
    """
    if not IP_ADDRESS_PATTERN.match(ip_string):
         raise argparse.ArgumentTypeError(
             f"Invalid IP address format: '{ip_string}'. Must be a valid IPv4 or IPv6 address."
         )
    return ip_string

def get_host_ip():
    """Attempts to get the primary non-loopback IP address."""
    s = None
    try:
        # Connect to an external address without sending any data
        # to find the socket's source IP address.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)) # Google's DNS server, port 80
        ip = s.getsockname()[0]
        return ip
    except Exception as e:
        print(f"\nWarning: Could not automatically determine host IP: {e}", file=sys.stderr)
        return None
    finally:
        if s:
            s.close()

def main():
    parser = argparse.ArgumentParser(
        description="Run a DNS proxy server that replaces DNS queries with more secure DNS over HTTPS (DoH).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter # Shows defaults in help
    )

    # Optional: Expose listen IP and port
    parser.add_argument(
        '--listen-ip',
        default='0.0.0.0',
        metavar='IP_ADDRESS',
        help="IP address for the proxy server to listen on."
    )
    parser.add_argument(
        '--listen-port',
        type=int,
        default=53,
        metavar='PORT',
        help="Port for the proxy server to listen on."
    )
    # Argument for specifying DoH providers (now defaults to None)
    parser.add_argument(
        '-d', '--doh-providers',
        nargs='+',  # Accepts one or more space-separated values
        default=None,  # Default is None, logic below will handle it
        metavar='URL',
        type=validate_doh_url,  # Add validation function here
        help="List of DNS-over-HTTPS provider URLs. By default, this list REPLACES the built-in defaults. "
             "Use -a or --add-to-defaults to append to the defaults instead."
    )
    # Argument to ADD providers to the default list instead of replacing
    parser.add_argument(
        '-a', '--add-to-defaults',
        action='store_true',  # Makes it a boolean flag
        help="If specified, URLs passed via -d or --doh-providers are ADDED to the default list, "
             "instead of replacing it. Duplicates are ignored."
    )
    # Argument to toggle randomization
    parser.add_argument(
        '-r', '--randomize',
        action='store_true', # Makes it a boolean flag, True if present
        help="Randomize the DoH provider selection for each request."
    )
    parser.add_argument(
        '-c', '--checker-service',
        choices=['virustotal', 'ismalicious', 'both'], # Valid explicit choices
        nargs='?', # Makes the argument optional
        const='both', # Value if flag is present but without a value (e.g., --checker-service)
        default=None, # Value if the flag is not present at all
        metavar='SERVICE',
        help="Enable domain checking and select service(s). If flag is present without a value, uses 'both'. "
             "Choices: 'virustotal', 'ismalicious', 'both'. If flag is omitted, checking is DISABLED."
    )
    parser.add_argument(
        '--redirect-ip',
        default=None,
        type=validate_ip_address,
        metavar='IP',
        help="IPv4 or IPv6 address to return for blocked domains (used only if -c/--checker-service is enabled)."
             "By default set to None and do not perform redirection."
    )
    parser.add_argument(
        '-v', '--verbose',
        action='count', # -v, -vv, -vvv increases verbosity
        default=0,
        help="Increase output verbosity (e.g., -v for WARNING, -vv for INFO, -vvv for DEBUG)."
    )

    args = parser.parse_args()

    # ----- Setup Logging based on Verbosity -----
    log_level = logging.ERROR       # Default
    if args.verbose == 1:
        log_level = logging.WARNING # -v option
    elif args.verbose == 2:
        log_level = logging.INFO    # -vv option
    elif args.verbose >=  3:
        log_level = logging.DEBUG   # -vvv option

    # Configure root logger
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s', stream=sys.stdout)
    # Get logger for this main module specifically
    logger = logging.getLogger(__name__)
    # Set level explicitly for this logger too, in case root logger level is different
    logger.setLevel(log_level)
    # ----- End Logging Setup -----


    # ----- Determine the final list of DoH providers -----
    final_doh_providers = []
    user_providers = args.doh_providers if args.doh_providers else []

    if args.add_to_defaults:
        # Combine defaults and user-provided list, removing duplicates
        combined_providers = DEFAULT_DOH_PROVIDERS + user_providers
        # Use a set for uniqueness
        final_doh_providers = list(set(combined_providers))
        logger.info("Adding user-provided DoH URLs to default list.")
    elif user_providers:
        # User provided list explicitly, and not adding to defaults, so use only user's list
        final_doh_providers = user_providers
        logger.info("Using only user-provided DoH URLs.")
    else:
        # No user list provided and not adding to defaults, so use the original defaults
        final_doh_providers = DEFAULT_DOH_PROVIDERS
        logger.info("Using the default list of DoH URLs.")

    # Ensure the final list is not empty
    if not final_doh_providers:
        logger.error(
            "Error: No DoH providers configured. Please provide some via -d or ensure defaults are available.")
        sys.exit("Configuration error: No DoH providers specified.")
    # ----- End of Provider List Logic -----

    host_ip_guess = get_host_ip()
    print("-" * 60)
    print("Starting DNS Proxy Server with the following settings:")
    print(f"  Accessible On:   {host_ip_guess if host_ip_guess else args.listen_ip}:{args.listen_port}")
    print(f"                   (Use host's IP to connect to the server!)\n")

    # Compare final_doh_providers to DEFAULT_DOH_PROVIDERS to decide whether to display [DEFAULT LIST] label
    is_default_list = sorted(final_doh_providers) == sorted(DEFAULT_DOH_PROVIDERS)
    print(f"  DoH Providers:   {'[DEFAULT LIST]' if is_default_list else '[CUSTOM LIST]'}")
    # List all the providers that will be used
    for provider in final_doh_providers:
        print(f"\t\t - {provider}")

    print(f"  Randomization:   {'ENABLED' if args.randomize else 'DISABLED'}")
    print("-" * 60)
    if args.checker_service:
        print(f"  Blocking Mode:   ENABLED")
        print(f"  Checker Service: {args.checker_service.upper()}")
        print(f"  Redirect IP:     {args.redirect_ip if args.redirect_ip else 'Redirection is DISABLED'}")
    else:
        print(f"  Blocking Mode:   DISABLED")
    print(f"  Log Level:       {logging.getLevelName(log_level)}")
    print("-" * 60)

    logger.info("Configuration parsed. Instantiating server.")


    # Instantiate and start the server, passing the arguments
    try:
        server = DNSProxyServer(
            listen_ip=args.listen_ip,
            listen_port=args.listen_port,
            doh_providers=final_doh_providers,
            randomize=args.randomize,
            checker_service=args.checker_service,
            redirect_ip=args.redirect_ip,
            log_level=log_level
        )
        logger.info("Server instantiated. Starting listeners...")
        server.start() # This will block until shutdown


    except PermissionError:
        logger.critical(
            f"Permission denied binding to {args.listen_ip}:{args.listen_port}. Try running as root/admin or using a port > 1024.")
        sys.exit(f"PermissionError: Could not bind to port {args.listen_port}.")
    except OSError as e:
        if "address already in use" in str(e).lower():
            logger.critical(
                f"Address {args.listen_ip}:{args.listen_port} is already in use. Is another DNS server running?")
            sys.exit(f"OSError: Address already in use ({args.listen_port}).")
        else:
            logger.critical(f"An OS error occurred during server startup: {e}", exc_info=True)
            sys.exit(f"OSError: {e}")
    except Exception as e:
        logger.critical(f"An unexpected error occurred: {e}", exc_info=True)
        sys.exit(f"Unexpected error: {e}")
    finally:
        logger.info("main.py finished.")


if __name__ == "__main__":
    main()








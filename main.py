import argparse
import sys
import re
import logging
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

def validate_doh_url(url_string):
    """
    Validates if a string is a plausible DoH URL using regex.
    Allows https://, IP addresses, optional ports, and optional paths.
    Raises ArgumentTypeError if the format is invalid.

    Args:
        url_string: string to check for URL format
    """
    # Regex breakdown:
    # ^https://       : Starts with https://
    # (               : Start group for host
    #  \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} : IPv4 address
    # )               : End group for host
    # (:[0-9]{1,5})?  : Optional port (1-5 digits)
    # (/[\w\-./?=&%]*)? : Optional path (alphanumeric, -, ., /, ?, =, &, %)
    # $               : End of string
    pattern = re.compile(r'^https://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:[0-9]{1,5})?(/[\w\-./?=&%]*)?$')
    if not pattern.match(url_string):
        raise argparse.ArgumentTypeError(
            f"Invalid DoH URL format: '{url_string}'. "
            "Must be https:// with IP, optional port, and optional path (e.g., /dns-query)."
        )
    # Return the valid string if it matches
    return url_string

def main():
    parser = argparse.ArgumentParser(
        description="Run a DNS proxy server that replaces DNS queries with more secure DNS over HTTPS (DoH).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter # Shows defaults in help
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
        help="If specified, URLs passed via --doh-providers are ADDED to the default list, "
             "instead of replacing it. Duplicates are ignored."
    )

    # Argument to toggle randomization
    parser.add_argument(
        '-r', '--randomize',
        action='store_true', # Makes it a boolean flag, True if present
        help="Randomize the DoH provider selection for each request."
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

    parser.add_argument(
        '-v', '--verbose',
        action='count', # -v, -vv, -vvv increases verbosity
        default=0,
        help="Increase output verbosity (e.g., -v for WARNING, -vv for INFO, -vvv for DEBUG)."
    )

    args = parser.parse_args()

    # --- Setup Logging based on Verbosity ---
    log_level = logging.ERROR       # Default
    if args.verbose == 1:
        log_level = logging.WARNING # -v option
    elif args.verbose == 2:
        log_level = logging.INFO    # -vv option
    elif args.verbose >=  3:
        log_level = logging.DEBUG   # -vvv option

    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s', stream=sys.stdout)
    # Get logger for this main module
    logger = logging.getLogger(__name__)
    # --- End Logging Setup ---


    # --- Determine the final list of DoH providers ---
    final_doh_providers = []
    user_providers = args.doh_providers if args.doh_providers else []

    if args.add_to_defaults:
        # Combine defaults and user-provided list, removing duplicates
        combined_providers = DEFAULT_DOH_PROVIDERS + user_providers
        # Use a set for uniqueness
        final_doh_providers = list(set(combined_providers))
        logger.info("Adding user providers to default list.")
    elif user_providers:
        # User provided list explicitly, and not adding to defaults, so use only user's list
        final_doh_providers = user_providers
        logger.info("Using user-provided list of providers exclusively.")
    else:
        # No user list provided and not adding to defaults, so use the original defaults
        final_doh_providers = DEFAULT_DOH_PROVIDERS
        logger.info("Using default list of providers.")

    # Ensure the final list is not empty
    if not final_doh_providers:
        logger.error(
            "Error: No DoH providers configured. Please provide some via -d or ensure defaults are available.")
        sys.exit("Configuration error: No DoH providers specified.")

    # --- End Provider List Logic ---

    print("-" * 60)
    print("Starting DNS Proxy Server with the following settings:")
    print(f"  Listen IP:    {args.listen_ip}")
    print(f"  Listen Port:  {args.listen_port}")
    print(f"  DoH Providers: ")
    for provider in final_doh_providers:
        print(f"\t\t{provider}")
    print(f"  Randomize:    {args.randomize}")
    print("-" * 60)


    # Instantiate and start the server, passing the arguments
    try:
        server = DNSProxyServer(
            listen_ip=args.listen_ip,
            listen_port=args.listen_port,
            log_level= log_level,
            doh_providers=final_doh_providers,
            randomize=args.randomize
        )
        server.start() # This will block until KeyboardInterrupt or shutdown
    except KeyboardInterrupt:
        print("\nCtrl+C detected. Shutting down server...")
        # The server's own shutdown logic should handle cleanup
    except Exception as e:
        # Use logger if implemented, otherwise print
        print(f"An error occurred: {e}", file=sys.stderr)
        # logger.exception("An unhandled error occurred during server startup or runtime.")
        sys.exit(1) # Exit with error code



if __name__ == "__main__":
    main()

# if __name__ == "__main__":
#     # Create and start the proxy server
#     # https://9.9.9.9:5053/dns-query        https://8.8.8.8/dns-query
#     server = DNSProxyServer(doh_url="https://9.9.9.9:5053/dns-query")
#     try:
#         server.start()
#     except KeyboardInterrupt:
#         print("Shutting down...")







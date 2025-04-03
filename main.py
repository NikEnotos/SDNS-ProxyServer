import argparse
import sys
from dns_proxy import DNSProxyServer

# Default DoH providers
DEFAULT_DOH_PROVIDERS = [
    'https://1.1.1.1/dns-query',
    'https://1.0.0.1/dns-query',
    'https://8.8.8.8/dns-query',
    'https://9.9.9.9:5053/dns-query' # Example with port
]

def main():
    parser = argparse.ArgumentParser(
        description="Run a DNS proxy server that replaces DNS queries with more secure DNS over HTTPS (DoH).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter # Shows defaults in help
    )

    # Argument for specifying DoH providers
    parser.add_argument(
        '-a', '--add-doh-providers',
        nargs='+', # Accepts one or more space-separated values
        default=DEFAULT_DOH_PROVIDERS,
        metavar='URL', # Placeholder name in help message
        help="List of DNS-over-HTTPS provider URLs to use."
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

    import logging
    log_level = logging.ERROR       # Default
    if args.verbose == 1:
        log_level = logging.WARNING # -v option
    elif args.verbose == 2:
        log_level = logging.INFO    # -vv option
    elif args.verbose >=  3:
        log_level = logging.DEBUG   # -vvv option

    print("-" * 60)
    print("Starting DNS Proxy Server with the following settings:")
    print(f"  Listen IP:    {args.listen_ip}")
    print(f"  Listen Port:  {args.listen_port}")
    print(f"  DoH Providers:{args.doh_providers}")
    print(f"  Randomize:    {args.randomize}")
    print("-" * 60)


    # Instantiate and start the server, passing the arguments
    try:
        server = DNSProxyServer(
            listen_ip=args.listen_ip,
            listen_port=args.listen_port,
            log_level= log_level,
            #doh_providers=args.doh_providers, # Pass the list
            #randomize=args.randomize       # Pass the flag
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







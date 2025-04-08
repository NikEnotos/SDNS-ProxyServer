import random
import socket
import struct
import requests
import base64
import threading
import time
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.name
import dns.query
import dns.rcode
import logging
from typing import Tuple, Dict, Any, Optional, List

from domain_checker import DomainChecker


class DNSProxyServer:
    def __init__(self, listen_ip: str = '0.0.0.0', listen_port: int = 53, doh_providers: list[str] = None,
                 randomize: bool = False, block_malicious: bool = False, block_threshold_malicious: int = 1,
                 block_threshold_suspicious: int = 1, redirect_ip: str = "0.0.0.0", log_level: logging = logging.ERROR):
        """
        Initialize the DNS proxy server with given or default parameters.
        
        Args:
            listen_ip: IP address to listen on (default: '0.0.0.0' - all interfaces)
            listen_port: Port to listen on (default: 53 - standard DNS port)
            doh_providers: A list of DNS over HTTPS URLs to use. (default: Cloudflare's 1.1.1.1)
            randomize: If True, pick a random DoH provider for each query.
            block_malicious: If True, check domains and block/redirect malicious/suspicious ones.
            block_threshold_malicious: The acceptable maliciousness score at which a domain is not yet blocked (default: 1)
            block_threshold_suspicious: The acceptable suspiciousness score at which a domain is not yet blocked (default: 1)
            redirect_ip: IP address to return for blocked domains.  # TODO IMPLEMENT
            log_level: Level of console logging verbosity
         """
        self.listen_ip = listen_ip
        self.listen_port = listen_port

        # Use provided list or a default if None is passed (though main.py handles default)
        self.doh_providers = doh_providers if doh_providers else ['https://1.1.1.1/dns-query']
        self.randomize = randomize

        self.block_malicious = block_malicious
        self.block_threshold_malicious = block_threshold_malicious
        self.block_threshold_suspicious = block_threshold_suspicious
        self.redirect_ip = redirect_ip

        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.shutdown_event = threading.Event()  # Flag to signal shutdown
        self._udp_thread = None  # To join later
        self._tcp_thread = None  # To join later

        # Set up logging
        logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    def start(self):
        """Start the DNS proxy server (both UDP and TCP)"""
        try:
            # Start UDP server
            self.udp_socket.bind((self.listen_ip, self.listen_port))
            self._udp_thread = threading.Thread(target=self._udp_listener)
            self._udp_thread.daemon = True
            self._udp_thread.start()
            self.logger.info(f"UDP DNS proxy listening on {self.listen_ip}:{self.listen_port}")

            # Start TCP server
            self.tcp_socket.bind((self.listen_ip, self.listen_port))
            self.tcp_socket.listen(10)  # Allow up to 10 queued connections
            self._tcp_thread = threading.Thread(target=self._tcp_listener)
            self._tcp_thread.daemon = True
            self._tcp_thread.start()
            self.logger.info(f"TCP DNS proxy listening on {self.listen_ip}:{self.listen_port}")

            self.logger.info(f"Malicious domain blocking is : { "enabled" if self.block_malicious else "NOT enabled" }")
            if self.block_malicious:
                self.logger.info(f"Redirecting blocked domains to: {self.redirect_ip}")  # TODO: Implement in a different way

            self.logger.info("-"*50)

            # Keep the main thread alive
            while not self.shutdown_event.is_set():
                # Sleep allows checking the event periodically and reduces CPU usage
                time.sleep(0.5)

            # Keep the main thread alive using the event's wait method
            #self.shutdown_event.wait()  # Wait until shutdown_event is set

        except KeyboardInterrupt:
            print("\nCtrl+C detected. Shutting down DNS proxy server...")
        except Exception as e:
            self.logger.error(f"Server startup error: {e}", exc_info=True)
        finally:
            # Signal threads to stop
            #self.shutdown_event.set()
            self.shutdown()

    def shutdown(self):
        """Initiates the shutdown sequence."""
        if not self.shutdown_event.is_set():
            self.logger.info("Starting shutdown sequence...")
            self.shutdown_event.set()  # Signal threads to stop

            # Closing sockets can help interrupt blocking calls like recvfrom/accept
            print("Closing sockets...")
            if hasattr(self, 'udp_socket') and self.udp_socket:
                try:
                    self.udp_socket.close()
                except Exception as e_udp_close:
                    self.logger.error(f"Error closing UDP socket: {e_udp_close}")

            if hasattr(self, 'tcp_socket') and self.tcp_socket:
                try:
                    # Closing the listening TCP socket should cause accept() to raise an error
                    self.tcp_socket.close()
                except Exception as e_tcp_close:
                    self.logger.error(f"Error closing TCP socket: {e_tcp_close}")

            # Wait for threads to potentially exit cleanly after socket closure
            # Giving a timeout avoids hanging indefinitely if a thread is stuck
            wait_timeout = 2.0
            if self._udp_thread and self._udp_thread.is_alive():
                self.logger.debug(f"Waiting for UDP listener thread to join (max {wait_timeout}s)...")
                self._udp_thread.join(timeout=wait_timeout)
                if self._udp_thread.is_alive():
                    self.logger.warning("UDP listener thread did not exit cleanly.")

            if self._tcp_thread and self._tcp_thread.is_alive():
                self.logger.debug(f"Waiting for TCP listener thread to join (max {wait_timeout}s)...")
                self._tcp_thread.join(timeout=wait_timeout)
                if self._tcp_thread.is_alive():
                    self.logger.warning("TCP listener thread did not exit cleanly.")

            print("Shutdown complete.")

    def _udp_listener(self):
        """Listen for and process UDP DNS requests"""

        while not self.shutdown_event.is_set():
            try:
                # Set a timeout so recvfrom doesn't block forever
                self.udp_socket.settimeout(1.0)  # Timeout after 1 second
                data, addr = self.udp_socket.recvfrom(4096)

                # Check shutdown
                if self.shutdown_event.is_set(): break

                if self._is_dns_request(data):
                    # Spawn a new thread to handle the request concurrently
                    threading.Thread(target=self._handle_dns_request, args=(data, addr)).start()
                else:
                    self.logger.info(f"Received non-DNS UDP packet from {addr}, ignoring")

            except socket.timeout:
                # Loop continues, checking the shutdown_event again
                continue
            except (socket.error, OSError) as e:
                # If the socket is closed while recvfrom is blocking, an error occurs.
                # Check if shutdown is in progress.
                if self.shutdown_event.is_set():
                    self.logger.debug("UDP listener shutting down due to socket closure.")
                    break  # Exit loop cleanly

                # Check if it's the specific error and log as warning/info if desired
                elif isinstance(e, OSError) and hasattr(e, 'winerror') and e.winerror == 10054:
                    self.logger.info(f"Non-critical error in UDP listener: {e}")

                else:
                    self.logger.error(f"Error in UDP listener: {e}", exc_info=True)
                    # Optional: Add a small delay before retrying to prevent fast error loops
                    time.sleep(0.1)

            except Exception as e:
                if self.shutdown_event.is_set():  # Check again in case exception happened during shutdown
                    break
                self.logger.error(f"Error in UDP listener: {e}", exc_info=True)
                time.sleep(0.1)
        self.logger.debug("UDP listener thread finished.")

    def _tcp_listener(self):
        """Listen for and process TCP DNS requests"""

        while not self.shutdown_event.is_set():  # Check event
            try:
                # Set a timeout so accept doesn't block forever
                self.tcp_socket.settimeout(1.0)  # Timeout after 1 second
                client_sock, addr = self.tcp_socket.accept()

                # Check shutdown again immediately after potential blocking call
                if self.shutdown_event.is_set():
                    try:
                        client_sock.close()  # Close accepted socket if shutting down
                    except:
                        pass
                    break

                threading.Thread(target=self._handle_tcp_client, args=(client_sock, addr)).start()

            except socket.timeout:
                # Loop continues, checking the shutdown_event again
                continue
            except (socket.error, OSError) as e:
                # If the socket is closed while accept is blocking, an error occurs.
                # Check if shutdown is in progress.
                if self.shutdown_event.is_set():
                    self.logger.debug("TCP listener shutting down due to socket closure.")
                    break
                else:
                    self.logger.error(f"Error in TCP listener accept(): {e}", exc_info=True)
                    time.sleep(0.1)  # Prevent potential fast loop on persistent errors
            except Exception as e:
                if self.shutdown_event.is_set():  # Check again
                    break
                self.logger.error(f"Error in TCP listener: {e}", exc_info=True)
                time.sleep(0.1)  # Prevent fast error loops
        self.logger.debug("TCP listener thread finished.")

    def _handle_tcp_client(self, client_sock: socket.socket, addr: Tuple[str, int]):
        """
        Handle a TCP client connection and performs domain check and DoH lookup concurrently.

        Args:
            client_sock: Socket object created specifically for communication with the connecting client
            addr: The client's address - Tuple[IP address, port]
        """
        try:
            # Set timeout for receiving data on the client socket
            client_sock.settimeout(10.0)

            # In TCP DNS, the first 2 bytes indicate the length of the DNS message
            length_bytes = client_sock.recv(2)
            if not length_bytes or len(length_bytes) < 2:
                self.logger.warning(f"Invalid TCP message from {addr}, closing connection")
                # Socket closere is handled in finally block
                return

            # '!H' is a format string defining how to interpret the bytes:
            # '!' specifies the byte order as network (big-endian)
            # 'H' specifies the data type as an unsigned short integer
            length = struct.unpack('!H', length_bytes)[0]
            if length == 0:
                self.logger.warning(f"Zero-length TCP message from {addr}, closing connection")
                return

            data = client_sock.recv(length)
            if len(data) != length:
                self.logger.warning(f"Incomplete TCP message from {addr}, closing connection")
                return

            if self._is_dns_request(data):
                # Parse the DNS request
                request = dns.message.from_wire(data)

                domain_to_check = None
                # Log the query details
                for question in request.question:
                    domain_to_check = question.name.to_text(omit_final_dot=True)
                    qtype = dns.rdatatype.to_text(question.rdtype)
                    self.logger.info(f"[>] Received (TCP) DNS request from \t{str(addr):<25} for [{domain_to_check}] (Type: {qtype})")



                # ----- Prepare for the concurrent operations -----
                # Initialize variables to use threads and store results of concurrent operations
                domain_checker: Optional[DomainChecker] = None
                checker_thread: Optional[threading.Thread] = None
                doh_thread: Optional[threading.Thread] = None

                # Use a list to hold the result from the DoH thread as it is mutable
                doh_result: List[Optional[bytes]] = [None]



                # ----- Start the concurrent checks -----
                if self.block_malicious and domain_to_check:
                    check_wait_start = time.monotonic()  # TODO remove
                    domain_checker = DomainChecker(domain_to_check)
                    domain_checker.start_checks()
                    self.logger.debug(f"Started domain checks for {domain_to_check} (TCP)")

                # Define the target function for the DoH thread
                def doh_worker():
                    try:
                        doh_result[0] = self._forward_to_doh(data)
                        #doh_result[0] = response_data  # Store result in mutable list
                    except Exception as e_doh:
                        self.logger.error(f"Exception in DoH worker thread for {domain_to_check} (TCP): {e_doh}",exc_info=True)
                        doh_result[0] = None

                # Start DoH request in its own thread
                self.logger.debug(f"Started DoH forwarding thread for {domain_to_check} (TCP)")
                doh_wait_start = time.monotonic()  # TODO remove
                doh_thread = (threading.Thread(target=doh_worker, daemon=True))
                doh_thread.start()



                # ----- Wait for results of the concurrent checks -----
                # Wait for DoH request thread
                if doh_thread:
                    doh_thread.join(timeout=6.0)
                    self.logger.debug(
                        f"DoH (TCP) thread for \t[{domain_to_check}] finished or timed out in {time.monotonic() - doh_wait_start:.2f}s")  # TODO remove time tracking
                    if doh_thread.is_alive():
                        self.logger.warning(f"DoH (TCP) thread for \t[{domain_to_check}]  timed out.")

                # Wait for domain checks (if started)
                if domain_checker:
                    domain_checker.wait_for_completion(timeout=3.0)
                    self.logger.debug(
                        f"Domain checks (TCP) for \t[{domain_to_check}] finished or timed out in {time.monotonic() - check_wait_start:.2f}s")  # TODO remove time tracking



                # ----- Process the results -----
                final_response: Optional[bytes] = None

                # Check domain status if blocking enabled and checks were run
                is_bad_domain = False
                if self.block_malicious and domain_checker:
                    if domain_checker.is_malicious(self.block_threshold_malicious):
                        self.logger.warning(
                            f"[!!!] MALICIOUS domain blocked (TCP): [{domain_to_check}]")  # TODO: Think about adding score display
                        is_bad_domain = True
                    elif domain_checker.is_suspicious(self.block_threshold_suspicious):
                        self.logger.warning(
                            f"[!] SUSPICIOUS domain blocked (TCP): [{domain_to_check}]")  # TODO: Think about adding score display
                        is_bad_domain = True

                # If domain is not bad, use DoH result
                if not is_bad_domain:
                    response_data = doh_result[0]  # Get result from the shared list
                    if response_data:
                        final_response = response_data
                        try:
                            # Log received response information
                            response_msg = dns.message.from_wire(response_data)
                            rcode_text = dns.rcode.to_text(response_msg.rcode())
                            answer_count = len(response_msg.answer)
                            self.logger.info(f"[+] DoH Response for \t\t[{domain_to_check}]: \t{rcode_text}, {answer_count} answers")

                            # Log every IPv4 and IPv6 addresses in the response
                            for answer in response_msg.answer:
                                # Loop through each resource record in the answer.
                                for record in answer:
                                    # Check if the record is an A record (IPv4 address).
                                    if record.rdtype == dns.rdatatype.A:
                                        self.logger.info(f"  ↳ IPv4: {record.address:<15}\t\t[{domain_to_check}]")

                                    elif record.rdtype == dns.rdatatype.AAAA:
                                        self.logger.info(f"  ↳ IPv6: {record.address:<39}\t\t[{domain_to_check}]")

                        except Exception:
                            self.logger.warning("Could not parse DoH response for logging (TCP).")
                    else:
                        # DoH failed or timed out, create SERVFAIL
                        self.logger.error(f"DoH lookup failed for {domain_to_check} (TCP). Sending SERVFAIL.")
                        final_response = self._create_error_response(data, dns.rcode.SERVFAIL)

                # If domain is not bad, use redirect
                else:
                    # TODO: redirection logic here, SERVFAIL for now
                    final_response = self._create_error_response(data, dns.rcode.SERVFAIL)



                # ----- Send parsed results as a response -----
                if final_response:
                    # Prepend 2-byte length for TCP response
                    response_length_bytes = struct.pack('!H', len(final_response))
                    try:
                        client_sock.sendall(response_length_bytes + final_response)
                        self.logger.debug(f"[<] Sent TCP response ({len(final_response)} bytes) to {addr}")
                    except socket.error as send_err:
                        self.logger.warning(
                            f"Failed to send TCP response to {addr}: {send_err}. Client might have closed connection.")
                else:
                    # This means even SERVFAIL failed to generate
                    self.logger.error(f"No final response generated for TCP request from {addr}. Closing connection.")

            else:
                self.logger.info(f"Received non-DNS TCP message from {addr}, ignoring and closing.")



        except socket.timeout:
            self.logger.warning(f"TCP connection from {addr} for [{domain_to_check}] timed out during communication.")
        except (socket.error, OSError) as e:
            self.logger.error(f"Socket error handling TCP client {addr}: {e}", exc_info=True)
        except dns.exception.DNSException as e:
            self.logger.error(f"DNS parsing/processing error for TCP client {addr}: {e}", exc_info=True)
        except Exception as e:
            self.logger.error(f"Unexpected error handling TCP client {addr}: {e}", exc_info=True)
        finally:
            # Ensure the client socket is always closed
            try:
                client_sock.close()
                self.logger.debug(f"[*] Closed TCP connection from {addr}")
            except Exception as close_err:
                self.logger.error(f"Error closing TCP client socket for {addr}: {close_err}")

    def _is_dns_request(self, data: bytes) -> bool:
        """
        Check if the given data appears to be a DNS request.
        
        Args:
            data: The packet data to check
            
        Returns:
            bool: True if the data appears to be a DNS request
        """
        # DNS messages must be at least 12 bytes (header size)
        if len(data) < 12:
            return False

        try:
            # Try to parse as a DNS message
            msg = dns.message.from_wire(data)
            # If it parsed,
            # has a QR(query/response) flag of 0 (query),
            # and if the parsed message contains at least one question,
            # it's likely a DNS request
            return (msg.flags & dns.flags.QR == 0) and len(msg.question) > 0
        except dns.exception.DNSException as e:
            self.logger.debug(f"Data failed DNS parsing check: {e}")
            return False
        except Exception as e:  # Catch other potential errors during parsing
            self.logger.debug(f"Unexpected error during DNS parsing check: {e}")
            return False

    def _handle_dns_request(self, data: bytes, addr: Tuple[str, int]):
        """
        Handles an incoming DNS request.
        Performs domain check and DoH lookup concurrently, then sends response.

        Args:
            data: The raw DNS request data
            addr: The client's address - Tuple[IP address, port]
        """
        try:
            request = dns.message.from_wire(data)
            domain_to_check = None
            if request.question:
                qname = request.question[0].name
                domain_to_check = qname.to_text(omit_final_dot=True)
                qtype = dns.rdatatype.to_text(request.question[0].rdtype)
                self.logger.info(
                    f"[>] Received (UDP) DNS request from \t{str(addr):<25} for [{domain_to_check}] (Type: {qtype})")
            else:
                # Should not happen if _is_dns_request passed, but handle defensively
                self.logger.warning(f"Received DNS request from {addr} with no questions.")
                # Send FORMERR response
                error_response = self._create_error_response(data,
                                                             dns.rcode.FORMERR)  # Format Error might be more appropriate
                if error_response:
                    try:
                        self.udp_socket.sendto(error_response, addr)
                    except socket.error as send_err:
                        self.logger.warning(f"Socket error sending FORMERR to {addr}: {send_err}")
                return



            # ----- Prepare for the concurrent operations -----
            # Initialize variables to use threads and store results of concurrent operations
            domain_checker: Optional[DomainChecker] = None
            checker_thread: Optional[threading.Thread] = None
            doh_thread: Optional[threading.Thread] = None

            # Use a list to hold the result from the DoH thread as it is mutable
            doh_result: List[Optional[bytes]] = [None]



            # ----- Start the concurrent checks -----
            if self.block_malicious and domain_to_check:
                check_wait_start = time.monotonic() # TODO remove
                domain_checker = DomainChecker(domain_to_check)
                domain_checker.start_checks()
                self.logger.debug(f"Started domain checks for {domain_to_check} (UDP)")

            # Define the target function for the DoH thread
            def doh_worker():
                try:
                    response_data = self._forward_to_doh(data)
                    doh_result[0] = response_data  # Store result in mutable list
                except Exception as e_doh:
                    self.logger.error(f"Exception in DoH worker thread for {domain_to_check} (UDP): {e_doh}", exc_info=True)
                    doh_result[0] = None

            # Start DoH request in its own thread
            self.logger.debug(f"Started DoH forwarding thread for {domain_to_check} (UDP)")
            doh_wait_start = time.monotonic() # TODO remove
            doh_thread = threading.Thread(target=doh_worker, daemon=True)
            doh_thread.start()



            # ----- Wait for results of the concurrent checks -----
            # Wait for DoH request thread
            if doh_thread:
                doh_thread.join(timeout=6.0)
                self.logger.debug(
                    f"DoH (UDP) thread for \t[{domain_to_check}] (UDP) finished or timed out in {time.monotonic() - doh_wait_start:.2f}s") # TODO remove time tracking
                if doh_thread.is_alive():
                    self.logger.warning(f"DoH (UDP) thread for \t[{domain_to_check}] timed out.")

            # Wait for domain checks (if started)
            if domain_checker:
                domain_checker.wait_for_completion(timeout=3.0)
                self.logger.debug(
                    f"Domain checks (UDP) for \t[{domain_to_check}] finished or timed out in {time.monotonic() - check_wait_start:.2f}s") # TODO remove time tracking



            # ----- Process the results -----
            final_response: Optional[bytes] = None

            # Check domain status if blocking enabled and checks were run
            is_bad_domain = False
            if self.block_malicious and domain_checker:
                if domain_checker.is_malicious(self.block_threshold_malicious):
                    self.logger.warning(f"[!!!] MALICIOUS domain blocked (UDP): [{domain_to_check}]")   # TODO: Think about adding score display
                    is_bad_domain = True
                elif domain_checker.is_suspicious(self.block_threshold_suspicious):
                    self.logger.warning(f"[!] SUSPICIOUS domain blocked (UDP): [{domain_to_check}]")    # TODO: Think about adding score display
                    is_bad_domain = True

            # If domain is not bad, use DoH result
            if not is_bad_domain:
                response_data = doh_result[0]  # Get result from the shared list
                if response_data:
                    final_response = response_data
                    try:
                        # Log received response information
                        response_msg = dns.message.from_wire(response_data)
                        rcode_text = dns.rcode.to_text(response_msg.rcode())
                        answer_count = len(response_msg.answer)
                        self.logger.info(f"[+] DoH Response for \t\t[{domain_to_check}]: \t{rcode_text}, {answer_count} answers")

                        # Log every IPv4 and IPv6 addresses in the response
                        for answer in response_msg.answer:
                            # Loop through each resource record in the answer.
                            for record in answer:
                                # Check if the record is an A record (IPv4 address).
                                if record.rdtype == dns.rdatatype.A:
                                    self.logger.info(f"  ↳ IPv4: {record.address:<15}\t\t[{domain_to_check}]")

                                elif record.rdtype == dns.rdatatype.AAAA:
                                    self.logger.info(f"  ↳ IPv6: {record.address:<39}\t\t[{domain_to_check}]")

                    except Exception:
                        self.logger.warning("Could not parse DoH response for logging (UDP).")
                else:
                    # DoH failed or timed out, create SERVFAIL
                    self.logger.error(f"DoH lookup failed for {domain_to_check} (UDP). Sending SERVFAIL.")
                    final_response = self._create_error_response(data, dns.rcode.SERVFAIL)

            # If domain is not bad, use redirect
            else:
                # TODO: redirection logic here, SERVFAIL for now
                final_response = self._create_error_response(data, dns.rcode.SERVFAIL)



            # ----- Send parsed results as a response -----
            if final_response:
                try:
                    self.udp_socket.sendto(final_response, addr)
                    self.logger.debug(f"[<] Sent UDP response ({len(final_response)} bytes) to {addr}")
                except (socket.error, OSError) as send_err:
                    # This can happen if the client closes the "connection" before response arrives
                    self.logger.warning(f"Failed to send UDP response to {addr}: {send_err}. Client might have timed out or disconnected.")
            else:
                # This means even SERVFAIL failed to generate
                self.logger.error(f"No final response generated for UDP request from {addr} for {domain_to_check}. No response sent.")


        except dns.exception.DNSException as e:
            self.logger.error(f"DNS (UDP) processing error for {addr}: {e}", exc_info=True)
            # Attempt to send a generic error response if possible
            error_response = self._create_error_response(data, dns.rcode.SERVFAIL)
            if error_response:
                try:
                    self.udp_socket.sendto(error_response, addr)
                except socket.error as send_err:
                    self.logger.warning(f"Socket error sending error response to {addr}: {send_err}")
        except Exception as e:
            self.logger.error(f"Unexpected error handling DNS (UDP) request from {addr}: {e}", exc_info=True)
            # Ssend SERVFAIL
            error_response = self._create_error_response(data, dns.rcode.SERVFAIL)
            if error_response:
                try:
                    self.udp_socket.sendto(error_response, addr)
                except socket.error as send_err:
                    self.logger.warning(f"Socket error sending fallback SERVFAIL to {addr}: {send_err}")

    # TODO DELETE OR USE FOR REFACTORING
    def _process_dns_request(self, dns_data: bytes) -> Optional[bytes]:
        """
        Process a DNS request by forwarding it to DoH and returning the response.
        
        Args:
            dns_data: The raw DNS request data
            
        Returns:
            bytes: The DNS response data, or None if an error occurred
        """
        try:
            # Forward to DoH
            response_data = self._forward_to_doh(dns_data)

            if response_data:
                # Parse the response to log it
                response = dns.message.from_wire(response_data)
                rcode_text = dns.rcode.to_text(response.rcode())
                answer_count = len(response.answer)
                self.logger.info(f"[+] DoH Response: {rcode_text}, {answer_count} answers")

                requested_domain = "No 'question' in response"
                if response.question:
                    requested_domain = response.question[0].name.to_text()

                for answer in response.answer:
                    # Loop through each resource record in the answer.
                    for record in answer:
                        # Check if the record is an A record (IPv4 address).
                        if record.rdtype == dns.rdatatype.A:
                            self.logger.info(f"  ↳ IPv4: {record.address:<15}\t\t[{requested_domain}]")


                        elif record.rdtype == dns.rdatatype.AAAA:
                            self.logger.info(f"  ↳ IPv6: {record.address:<39}\t\t[{requested_domain}]")

                # TODO: add IP addresses check hare
                return response_data
            else:
                # If DoH failed, create a SERVFAIL response
                self.logger.error(f"DoH getting failed. Creating a SERVFAIL response")
                return self._create_error_response(dns_data, dns.rcode.SERVFAIL)

        except Exception as e:
            self.logger.error(f"Error processing DNS request: {e}")
            return self._create_error_response(dns_data, dns.rcode.SERVFAIL)

    def _create_error_response(self, original_request_data: bytes, rcode: dns.rcode.Rcode) -> Optional[bytes]:
        """ Helper to create a DNS error response (e.g., SERVFAIL, REFUSED). """
        try:
            # Try to make a response
            request = dns.message.from_wire(original_request_data)
            response = dns.message.make_response(request)
            response.set_rcode(rcode)
            # Ensure QR bit is set to 1 (response)
            response.flags |= dns.flags.QR
            # Add RA flag (Recursion Available)
            response.flags |= dns.flags.RA
            # Clear answer, authority, additional sections
            response.answer = []
            response.authority = []
            response.additional = []
            return response.to_wire()
        except dns.exception.DNSException as e:
            # If original request is malformed, we might not be able to make a response based on it.
            # Creating a minimal error response might be possible but complex (need to guess ID).
            self.logger.error(f"Failed to parse original request to create error response (rcode {rcode}): {e}")
            return None
        except Exception as e:
            self.logger.error(f"Failed to create error response with rcode {rcode}: {e}", exc_info=True)
            return None  # Fallback


    def _create_redirection_response(self, original_request_data: bytes, redirect_ip: str = "127.0.0.1") -> Optional[bytes]:
        """
        Creates a DNS response with a safe IP address for redirection.
        Only creates A or AAAA records based on the redirect_ip format.

        Args:
            original_request_data: The raw DNS request data
            redirect_ip: safe IP address (v4 or v6) to redirect to (default is localhost)

        Returns:
            bytes: Forged DNS response data with provided IP for redirection, or None if an error occurred
        """
        try:
            request = dns.message.from_wire(original_request_data)
            if not request.question:
                self.logger.warning("Cannot create redirection response for request with no question.")
                return self._create_error_response(original_request_data, dns.rcode.FORMERR)

            # Return an A/AAAA record regardless of original qtype for simplicity of blocking,
            # OR return NOERROR with no answer section.
            qname = request.question[0].name

            # Determine if redirect_ip is v4 or v6 to create the correct record type
            target_rdtype = None
            try:
                socket.inet_pton(socket.AF_INET, redirect_ip)
                target_rdtype = dns.rdatatype.A
            except socket.error:
                try:
                    socket.inet_pton(socket.AF_INET6, redirect_ip)
                    target_rdtype = dns.rdatatype.AAAA
                except socket.error:
                    self.logger.error(f"Invalid redirect_ip '{redirect_ip}'. Must be IPv4 or IPv6.")
                    # Fallback to a standard error response if redirect IP is invalid
                    return self._create_error_response(original_request_data, dns.rcode.SERVFAIL)

            # Create the response based on the original request
            response = dns.message.make_response(request)
            response.set_rcode(dns.rcode.NOERROR)  # Successful response code
            response.flags |= dns.flags.AA  # Authoritative Answer flag
            response.flags |= dns.flags.RA  # Recursion Available

            # Clear any potential answer/authority/additional sections copied from request
            response.answer = []
            response.authority = []
            response.additional = []

            # Create the Rdata object for the A or AAAA record
            # Use a short TTL for blocked responses
            ttl = 60
            rdata = dns.rdata.from_text(dns.rdataclass.IN, target_rdtype, redirect_ip)

            # Create the RRset (Resource Record Set)
            rrset = dns.rrset.from_rdata(qname, ttl, rdata)

            # Add the RRset to the answer section
            response.answer.append(rrset)

            domain_text = qname.to_text(omit_final_dot=True)
            self.logger.info(f"  ↳ [REDIRECTION] {domain_text} -> {redirect_ip} (Type: {dns.rdatatype.to_text(target_rdtype)})")

            # Return the crafted response in wire format
            return response.to_wire()


        except dns.exception.DNSException as e:
            self.logger.error(f"DNS error creating redirection response for {qname}: {e}", exc_info=True)
            return self._create_error_response(original_request_data, dns.rcode.SERVFAIL)  # Fallback
        except Exception as e_redir:
            # Log the specific domain if available
            domain_str = "unknown domain"
            try:
                domain_str = dns.message.from_wire(original_request_data).question[0].name.to_text()
            except:
                pass
            self.logger.error(f"Unexpected error creating redirection response for {domain_str}: {e_redir}", exc_info=True)
            # Fallback to SERVFAIL if redirection crafting fails
            return self._create_error_response(original_request_data, dns.rcode.SERVFAIL)


    def _get_doh_url(self) -> str:
        """Selects a DoH URL based on the randomization setting."""
        if self.randomize and len(self.doh_providers) > 1:
            return random.choice(self.doh_providers)
        elif self.doh_providers:  # Make sure list is not empty
            # Default to the first provider if not randomizing or only one provider
            return self.doh_providers[0]    # TODO: implement logic of getting providers one by one if there are more than one
        else:
            # Fallback needed if the list could be empty (shouldn't happen with argparse default)
            self.logger.critical("CRITICAL: No DoH providers configured! Falling back to default.")
            return 'https://1.1.1.1/dns-query'

    def _forward_to_doh(self, dns_data: bytes) -> Optional[bytes]:
        """
        Forward a DNS request to a selected DoH server using POST, GET, or JSON methods.
        
        Args:
            dns_data: The raw DNS request data
            
        Returns:
            bytes: The DNS response data from the DoH server, or None if an error occurred
        """

        request = dns.message.from_wire(dns_data)
        domain_name = request.question[0].name.to_text()

        # Select the DoH URL for this specific request
        selected_doh_url = self._get_doh_url()
        self.logger.debug(f"\tForwarding query to DoH provider: {selected_doh_url}")  # Log which one is used

        # Define timeout for requests
        request_timeout = 2.0  # seconds

        try:
            # Base64 encode the DNS request for DoH
            # Used URL-safe variant which uses "-" and "_" instead of "+" and "/"
            dns_b64 = base64.urlsafe_b64encode(dns_data).decode('utf-8').rstrip('=')

            # Method 1: Using binary DNS wire format
            headers = {
                'Accept': 'application/dns-message',
                'Content-Type': 'application/dns-message'
            }
            response = requests.post(
                selected_doh_url,
                data=dns_data,
                headers=headers,
                timeout=request_timeout
            )

            # Check for successful response
            if response.status_code == 200 and response.headers.get('content-type') == 'application/dns-message':
                self.logger.debug(f"\t[⩗] DoH POST successful for \t[${domain_name}] \t({len(response.content)} bytes).")
                return response.content
            else:
                self.logger.error(
                    f"\t[-] POST DoH request to {selected_doh_url} for \t[${domain_name}] failed (Status: {response.status_code}), trying GET method as fallback.")

            # Method 2: Fall back to GET with dns parameter if POST fails
            response = requests.get(
                selected_doh_url,
                params={'dns': dns_b64},
                headers={'Accept': 'application/dns-message'},
                timeout=request_timeout
            )

            if response.status_code == 200 and response.headers.get('content-type') == 'application/dns-message':
                self.logger.debug(f"\t[⩗] DoH GET successful ({len(response.content)} bytes).")
                return response.content
            else:
                self.logger.error(
                    f"\t[-] GET DoH request to {selected_doh_url} failed (Status: {response.status_code}), trying JSON method as the last resort.")

            # Method 3: Try JSON format as a last resort
            # Parse the DNS request to get the query details
            request = dns.message.from_wire(dns_data)
            if request.question:
                qname = request.question[0].name.to_text()
                #qtype = dns.rdatatype.to_text(request.question[0].rdtype) # String type
                qtype_int = request.question[0].rdtype  # Integer type

                # Use JSON API
                json_url = 'https://1.1.1.1/dns-query'
                # json_url = 'https://8.8.8.8/resolve'   # TODO Implement list of URLs with adjustment based on the provider.
                response = requests.get(
                    json_url,
                    params={
                        'name': qname,
                        #'type': qtype
                        'type': str(qtype_int)
                    },
                    headers={'Accept': 'application/dns-json'},
                    timeout=request_timeout
                )

                if response.status_code == 200 and 'application/dns-json' in response.headers.get('content-type', ''):
                    # Convert JSON response back to DNS wire format
                    self.logger.warning(f"\t[⩗] DoH request to {selected_doh_url} succeeded using JSON fallback.")
                    json_response_data = response.json()
                    # Convert JSON back to wire format based on original request
                    wire_response = self._json_to_dns_response(json_response_data, request)
                    if wire_response:
                        self.logger.debug(
                            f"Successfully converted JSON response to wire format ({len(wire_response)} bytes).")
                        return wire_response
                    else:
                        self.logger.error("Failed to convert JSON response back to wire format.")
                        # Fall through to general failure case

                    # If all methods failed
                self.logger.error(f"\t[-] All DoH methods (POST, GET, JSON) failed for [{selected_doh_url}].")
                return None

        except requests.exceptions.Timeout:
            self.logger.error(f"DoH request to {selected_doh_url} timed out after {request_timeout}s.")
            return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error forwarding to DoH provider {selected_doh_url}: {e}", exc_info=True)
            return None
        except dns.exception.DNSException as e:
            self.logger.error(f"Error parsing original request for JSON DoH fallback: {e}", exc_info=True)
            return None
        # General exception handler
        except Exception as e:
            self.logger.error(f"Unexpected error forwarding to DoH {selected_doh_url}: {e}", exc_info=True)
            return None

    def _json_to_dns_response(self, json_data: Dict[str, Any], original_request: dns.message.Message) -> Optional[bytes]:
        """
        Converts a DNS JSON response (RFC 8427 format) to DNS wire format.

        Args:
            json_data: The JSON response from the DoH server
            original_request: The original dns.message.Message object used to make the query.

        Returns:
            bytes: The DNS response in wire format, or None on failure
        """
        try:
            # Create a response message based on the original request
            response = dns.message.make_response(original_request)


            # Clear sections that will be populated from JSON
            response.answer = []
            response.authority = []
            response.additional = []


            # Set response code
            status_code_int = json_data.get('Status', 0)  # Get integer status from JSON
            try:
                # Convert integer to dns.rcode.Rcode enum
                response_rcode = dns.rcode.Rcode(status_code_int)
                response.set_rcode(response_rcode)
            except ValueError:
                self.logger.error(f"Invalid RCODE value received in JSON: {status_code_int}. Using SERVFAIL.")
                response.set_rcode(dns.rcode.SERVFAIL)


            # Set Flags from JSON
            # Ensure the QR bit is set (it should be by make_response)
            response.flags |= dns.flags.QR
            if json_data.get('RA', False):  # Recursion Available
                response.flags |= dns.flags.RA
            if json_data.get('AD', False):  # Authenticated Data
                response.flags |= dns.flags.AD


            # Process Records(Answer, Authority)
            section_map = {
                'Answer': response.answer,
                'Authority': response.authority
            }

            for section_name, response_section_list in section_map.items():
                for record in json_data.get(section_name, []):
                    try:
                        name_str = record.get('name')
                        type_int = record.get('type')
                        ttl_int = record.get('TTL')
                        data_str = record.get('data')

                        if None in [name_str, type_int, ttl_int, data_str]:
                            self.logger.warning(f"Skipping incomplete record in JSON '{section_name}': {record}")
                            continue

                        # Convert name to dns.name object
                        name = dns.name.from_text(name_str)

                        # Convert type integer to RdataType enum
                        try:
                            rdtype = dns.rdatatype.RdataType(type_int)
                        except ValueError:
                            self.logger.warning(
                                f"Skipping record with unknown RR type integer {type_int} in JSON: {record}")
                            continue

                        # Create rdata object from the string representation in JSON data
                        rdata = dns.rdata.from_text(dns.rdataclass.IN, rdtype, data_str, origin=name)

                        # Create RRset and add the rdata
                        rrset = dns.rrset.from_rdata(name, ttl_int, rdata)

                        # Append the RRset to the appropriate section list
                        response_section_list.append(rrset)

                    except dns.exception.DNSException as e_rec:
                        self.logger.error(
                            f"Error processing record in JSON '{section_name}' section: {record} - {e_rec}")
                        continue  # Skip this record
                    except Exception as e_rec_other:
                        self.logger.error(
                            f"Unexpected error processing record in JSON '{section_name}': {record} - {e_rec_other}")
                        continue

                # Return the response in wire format
            return response.to_wire()


        except dns.exception.DNSException as e_conv:
            self.logger.error(f"DNS library error converting JSON to wire format: {e_conv}", exc_info=True)
            return None
        except Exception as e_conv_other:
            self.logger.error(f"Unexpected error converting JSON response to wire format: {e_conv_other}",
                              exc_info=True)
            return None



if __name__ == '__main__':
    print("Starting DNS Proxy Server directly (for testing)...")
    # Configure with some defaults for direct execution
    proxy = DNSProxyServer(
        log_level=logging.INFO,
        block_malicious=False,
        doh_providers=['https://1.1.1.1/dns-query']
    )
    try:
        proxy.start()
    except KeyboardInterrupt:
         print("\nStopping server...")
         proxy.shutdown()
    except Exception as e:
         logging.getLogger(__name__).error(f"Failed to run server directly: {e}", exc_info=True)

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
from typing import Tuple, Dict, Any, Optional



class DNSProxyServer:
    def __init__(self, listen_ip: str = '0.0.0.0', listen_port: int = 53, doh_providers: list[str] = None,
                 randomize: bool = False, log_level: logging = logging.ERROR):
        """
        Initialize the DNS proxy server with given or default parameters.
        
        Args:
            listen_ip: IP address to listen on (default: '0.0.0.0' - all interfaces)
            listen_port: Port to listen on (default: 53 - standard DNS port)
            doh_providers: A list of DNS over HTTPS URLs to use. (default: Cloudflare's 1.1.1.1)
            randomize: If True, pick a random DoH provider for each query.
            log_level: Level of console logging verbosity
         """
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        # self.doh_url = doh_url

        # Use provided list or a default if None is passed (though main.py handles default)
        self.doh_providers = doh_providers if doh_providers else ['https://1.1.1.1/dns-query']
        self.randomize = randomize

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

            # Keep the main thread alive
            while not self.shutdown_event.is_set():
                # Sleep allows checking the event periodically and reduces CPU usage
                time.sleep(0.5)

        except KeyboardInterrupt:
            print("Shutting down DNS proxy server...")
        except Exception as e:
            self.logger.error(f"Server startup error: {e}")
        finally:
            # Signal threads to stop
            self.shutdown_event.set()

            # Close sockets AFTER signaling (this might interrupt blocking calls in threads)
            print("Closing sockets...")
            # Check that DNSProxyServer object has created udp_socket, and it's not None before closing it
            if hasattr(self, 'udp_socket') and self.udp_socket:
                try:
                    self.udp_socket.close()
                except Exception as e_udp_close:
                    self.logger.error(f"Error closing UDP socket: {e_udp_close}")

            # Check that DNSProxyServer object has created tcp_socket, and it's not None before closing it
            if hasattr(self, 'tcp_socket') and self.tcp_socket:
                try:
                    self.tcp_socket.close()
                except Exception as e_tcp_close:
                    self.logger.error(f"Error closing TCP socket: {e_tcp_close}")

            # Optional: Wait for threads to finish
            if self._udp_thread:
                self._udp_thread.join(timeout=2)
            if self._tcp_thread:
                self._tcp_thread.join(timeout=2)
            print("Shutdown complete.")

    def _udp_listener(self):
        """Listen for and process UDP DNS requests"""

        while not self.shutdown_event.is_set():
            try:
                # Set a timeout so recvfrom doesn't block forever
                self.udp_socket.settimeout(1.0)  # Timeout after 1 second
                data, addr = self.udp_socket.recvfrom(4096)
                if self._is_dns_request(data):
                    # Parse the DNS request
                    request = dns.message.from_wire(data)

                    # Log the query details
                    for question in request.question:
                        qname = question.name.to_text()
                        qtype = dns.rdatatype.to_text(question.rdtype)
                        self.logger.info(
                            f"[+] Received UDP DNS request from \t{str(addr):<26} \t{qname} (Type: {qtype})")

                    threading.Thread(target=self._handle_dns_request, args=(data, addr, False)).start()
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
                    self.logger.warning(f"Non-critical error in UDP listener: {e}")
                else:
                    self.logger.error(f"Error in UDP listener: {e}")
                    # Optional: Add a small delay before retrying to prevent fast error loops
                    time.sleep(0.1)
            except Exception as e:
                self.logger.error(f"Error in UDP listener: {e}")
                time.sleep(0.1)
        self.logger.debug("UDP listener thread finished.")

    def _tcp_listener(self):
        """Listen for and process TCP DNS requests"""

        while not self.shutdown_event.is_set():  # Check event
            try:
                # Set a timeout so accept doesn't block forever
                self.tcp_socket.settimeout(1.0)  # Timeout after 1 second
                client_sock, addr = self.tcp_socket.accept()
                threading.Thread(target=self._handle_tcp_client, args=(client_sock, addr)).start()

            except socket.timeout:
                # Loop continues, checking the shutdown_event again
                continue
            except (socket.error, OSError) as e:
                # If the socket is closed while accept is blocking, an error occurs.
                # Check if shutdown is in progress.
                if self.shutdown_event.is_set():
                    self.logger.debug("TCP listener shutting down due to socket closure.")
                    break  # Exit loop cleanly
                else:
                    self.logger.error(f"Error in TCP listener: {e}")
                    # Optional: Add a small delay before retrying
                    time.sleep(0.1)
            except Exception as e:
                self.logger.error(f"Error in TCP listener: {e}")
                time.sleep(0.1)  # Prevent fast error loops
        self.logger.debug("TCP listener thread finished.")

    def _handle_tcp_client(self, client_sock: socket.socket, addr: Tuple[str, int]):
        """
        Handle a TCP client connection

        Args:
            client_sock: Socket object created specifically for communication with the connecting client
            addr: Tuple[IP address, port]
        """
        try:
            # In TCP DNS, the first 2 bytes indicate the length of the DNS message
            length_bytes = client_sock.recv(2)
            if len(length_bytes) != 2:
                self.logger.warning(f"Invalid TCP message from {addr}, closing connection")
                client_sock.close()
                return

            # '!H' is a format string defining how to interpret the bytes:
            # '!' specifies the byte order as network (big-endian)
            # 'H' specifies the data type as an unsigned short integer
            length = struct.unpack('!H', length_bytes)[0]
            if length == 0:
                self.logger.warning(f"Zero-length TCP message from {addr}, closing connection")
                client_sock.close()
                return

            data = client_sock.recv(length)
            if len(data) != length:
                self.logger.warning(f"Incomplete TCP message from {addr}, closing connection")
                client_sock.close()
                return

            if self._is_dns_request(data):
                # Parse the DNS request
                request = dns.message.from_wire(data)

                # Log the query details
                for question in request.question:
                    qname = question.name.to_text()
                    qtype = dns.rdatatype.to_text(question.rdtype)
                    self.logger.info(f"[+] Received TCP DNS request from \t{str(addr):<25} \t{qname} (Type: {qtype})")

                response = self._process_dns_request(data)
                if response:
                    # Prepend length for TCP
                    response_length = struct.pack('!H', len(response))
                    client_sock.sendall(response_length + response)
            else:
                self.logger.info(f"Received non-DNS TCP message from {addr}, ignoring")

            client_sock.close()
        except Exception as e:
            self.logger.error(f"Error handling TCP client {addr}: {e}")
            try:
                client_sock.close()
            except:
                pass

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
            return msg.flags & 0x8000 == 0 and len(msg.question) > 0
        except Exception:
            return False

    def _handle_dns_request(self, data: bytes, addr: Tuple[str, int], is_tcp: bool):  # TODO remove is_tcp
        """
        Handle a DNS request by forwarding it to DoH and sending the response back to host

        Args:
            data: The raw DNS request data
            addr: Tuple[IP address, port]
        """
        try:
            response = self._process_dns_request(data)

            try:
                self.udp_socket.sendto(response, addr)

            except (socket.error, OSError) as send_err:
                self.logger.warning(
                    f"Failed to send UDP response to {addr}: {send_err}. Client might have disconnected.")

        except Exception as e:
            self.logger.error(f"Error handling DNS request from {addr}: {e}")

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
                # Parse the DNS request
                request = dns.message.from_wire(dns_data)
                response = dns.message.make_response(request)
                response.set_rcode(dns.rcode.SERVFAIL)
                return response.to_wire()

        except Exception as e:
            self.logger.error(f"Error processing DNS request: {e}")
            return self._create_error_response(dns_data, dns.rcode.SERVFAIL)

    def _create_error_response(self, original_request: bytes, rcode: dns.rcode.Rcode) -> Optional[bytes]:
        """ Helper to create a DNS error response (e.g., SERVFAIL, REFUSED). """
        try:
            # Try to make a SERVFAIL response
            request = dns.message.from_wire(original_request)
            response = dns.message.make_response(request)
            response.set_rcode(rcode)
            return response.to_wire()
        except Exception as e:
            self.logger.error(f"Failed to create error response with rcode {rcode}: {e}")
            return None


    def _create_redirection_response(self, dns_data: bytes, redirect_ip: str = "127.0.0.1") -> Optional[bytes]:
        """
        Creates a DNS response with a safe IP address for redirection.

        Args:
            dns_data: The raw DNS request data
            redirect_ip: safe IP address to redirect to (default is localhost)

        Returns:
            bytes: Forged DNS response data with provided IP for redirection, or None if an error occurred
        """
        request = dns.message.from_wire(dns_data)

        qname = request.question[0].name
        qtype = request.question[0].rdtype
        domain_to_check = qname.to_text(omit_final_dot=True)
        self.logger.debug(
            f"Extracted domain for checking: {domain_to_check} (Type: {dns.rdatatype.to_text(qtype)})")

        # Creating response based on the request
        response = dns.message.make_response(request)
        response.set_rcode(dns.rcode.NOERROR)
        response.flags |= dns.flags.AA  # Authoritative Answer flag, common for sinks/blocks

        # Clear any potential answers copied from request template
        response.answer.clear()

        # Create the A record pointing to the redirect_ip (local server is default)
        try:
            # Create the Rdata object for the A record
            rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, redirect_ip)
            # Create the RRset (Resource Record Set) using short TTL (60 sec)
            rrset = dns.rrset.from_rdata(qname, 60, rdata)
            # Add the RRset to the answer section
            response.answer.append(rrset)


            self.logger.warning(f"  ↳ [REDIRECTION]: to {redirect_ip:<15}\t\tfor [{domain_to_check}]")

            # Return the crafted response in wire format
            return response.to_wire()

        except Exception as e_redir:
            self.logger.error(f"Failed to create redirection response for {domain_to_check}: {e_redir}")
            # Fallback to SERVFAIL if redirection crafting fails
            return self._create_error_response(dns_data, dns.rcode.SERVFAIL)


    def _get_doh_url(self) -> str:
        """Selects a DoH URL based on the randomization setting."""
        if self.randomize and len(self.doh_providers) > 1:
            return random.choice(self.doh_providers)
        elif self.doh_providers:  # Make sure list is not empty
            # Default to the first provider if not randomizing or only one provider
            return self.doh_providers[0]
        else:
            # Fallback needed if the list could be empty (shouldn't happen with argparse default)
            self.logger.error("No DoH providers configured!")
            # Returning a default or raising an error might be appropriate
            return 'https://1.1.1.1/dns-query'  # Or raise ConfigurationError

    def _forward_to_doh(self, dns_data: bytes) -> Optional[bytes]:
        """
        Forward a DNS request to a selected DoH server.
        
        Args:
            dns_data: The raw DNS request data
            
        Returns:
            bytes: The DNS response data from the DoH server, or None if an error occurred
        """

        # Select the DoH URL for this specific request
        selected_doh_url = self._get_doh_url()
        self.logger.debug(f"Forwarding query to DoH provider: {selected_doh_url}")  # Log which one is used

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
                timeout=5
            )

            # Check for successful response
            if response.status_code == 200 and response.headers.get('content-type') == 'application/dns-message':
                return response.content
            else:
                self.logger.error(
                    f"POST DoH request to {selected_doh_url} failed, trying to use GET method as fallback.")

            # Method 2: Fall back to GET with dns parameter if POST fails
            response = requests.get(
                selected_doh_url,
                params={'dns': dns_b64},
                headers={'Accept': 'application/dns-message'},
                timeout=5
            )

            if response.status_code == 200 and response.headers.get('content-type') == 'application/dns-message':
                return response.content
            else:
                self.logger.error(
                    f"GET DoH request to {selected_doh_url} failed, trying to use JSON method as the last resort.")

            # Method 3: Try JSON format as a last resort
            # Parse the DNS request to get the query details
            request = dns.message.from_wire(dns_data)
            if len(request.question) > 0:
                qname = request.question[0].name.to_text()
                qtype = dns.rdatatype.to_text(request.question[0].rdtype)

                # Use JSON API
                json_url = 'https://1.1.1.1/dns-query'
                # json_url = 'https://8.8.8.8/resolve'   # TODO
                response = requests.get(
                    json_url,
                    params={
                        'name': qname,
                        'type': qtype
                    },
                    headers={'Accept': 'application/dns-json'},
                    timeout=5
                )

                if response.status_code == 200 and 'application/dns-json' in response.headers.get('content-type', ''):
                    # Convert JSON response back to DNS wire format
                    self.logger.warning(
                        f"DoH request to {selected_doh_url} was successful using JSON as a last resort.")
                    return self._json_to_dns_response(response.json(), request)

            self.logger.error(f"DoH request failed using {selected_doh_url}. Status: {response.status_code}")
            return None

        except requests.exceptions.Timeout:
            self.logger.error(f"DoH request to {selected_doh_url} timed out.")
            return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error forwarding to DoH provider {selected_doh_url}: {e}")
            return None
        # General exception handler
        except Exception as e:
            self.logger.error(f"Unexpected error forwarding to DoH {selected_doh_url}: {e}")
            return None

    def _json_to_dns_response(self, json_data: Dict[str, Any], original_request: dns.message.Message) -> Optional[
        bytes]:
        """
        Convert a DNS-over-HTTPS JSON response to DNS wire format. Correctly handles integer types and rcodes.

        Args:
            json_data: The JSON response from the DoH server
            original_request: The original DNS request message

        Returns:
            bytes: The DNS response in wire format, or None on failure
        """
        try:
            response = dns.message.make_response(original_request)

            # Set response code
            status_code_int = json_data.get('Status', 0)  # Get integer status from JSON
            try:
                # Convert integer to dns.rcode.Rcode enum
                response_rcode = dns.rcode.Rcode(status_code_int)
                response.set_rcode(response_rcode)
            except ValueError:
                self.logger.error(f"Invalid RCODE value received in JSON: {status_code_int}. Defaulting to SERVFAIL.")
                response.set_rcode(dns.rcode.SERVFAIL)

            # Process Answer section
            for answer in json_data.get('Answer', []):
                try:
                    name = dns.name.from_text(answer.get('name', '.'))
                    ttl = int(answer.get('TTL', 300))
                    data = answer.get('data', '')

                    # Determine rdtype
                    type_val = answer.get('type')
                    rdtype = None
                    if isinstance(type_val, int):
                        try:
                            # Convert integer type to dns.rdatatype.RdataType enum
                            rdtype = dns.rdatatype.RdataType(type_val)
                        except ValueError:
                            self.logger.warning(
                                f"Invalid integer RR TYPE received in JSON: {type_val} for name {name}. Skipping record.")
                            continue  # Skip this answer record
                    elif isinstance(type_val, str):
                        # Fallback if type is unexpectedly a string
                        try:
                            rdtype = dns.rdatatype.from_text(type_val)
                        except dns.rdatatype.UnknownRdatatype:
                            self.logger.warning(
                                f"Unknown string RR TYPE received in JSON: '{type_val}' for name {name}. Skipping record.")
                            continue  # Skip this answer record
                    else:
                        self.logger.warning(f"Missing or invalid RR TYPE in JSON for name {name}. Skipping record.")
                        continue  # Skip this answer record

                    # Create appropriate rdata based on type
                    rdata = None
                    if rdtype == dns.rdatatype.A:
                        # Use the library's recommended way to create from text for specific types
                        rdata = dns.rdata.from_text(dns.rdataclass.IN, rdtype, data)
                    elif rdtype == dns.rdatatype.AAAA:
                        rdata = dns.rdata.from_text(dns.rdataclass.IN, rdtype, data)
                    elif rdtype == dns.rdatatype.CNAME:
                        # CNAME data needs to be a dns.name object
                        rdata = dns.rdata.from_text(dns.rdataclass.IN, rdtype, data)
                    elif rdtype == dns.rdatatype.MX:
                        # MX data needs preference (int) and name (str)
                        rdata = dns.rdata.from_text(dns.rdataclass.IN, rdtype, data)
                    elif rdtype == dns.rdatatype.TXT:
                        # TXT data needs to be bytes or list of bytes
                        # The from_text handles quoting etc.
                        rdata = dns.rdata.from_text(dns.rdataclass.IN, rdtype, data)
                    elif rdtype == dns.rdatatype.HTTPS:
                        # HTTPS data is defined in RFC 9115 and is a string of parameters
                        rdata = dns.rdata.from_text(dns.rdataclass.IN, rdtype, data)
                    else:
                        self.logger.warning(
                            f"Unsupported RR TYPE {dns.rdatatype.to_text(rdtype)} ({rdtype}) for name {name}. Skipping record.")
                        continue  # Skip unsupported types

                    # Create RRset and add rdata
                    rrset = dns.rrset.from_rdata(name, ttl, rdata)
                    response.answer.append(rrset)

                except Exception as e_ans:
                    self.logger.error(f"Error processing JSON answer record {answer}: {e_ans}")
                    continue  # Skip problematic answer records

            return response.to_wire()

        except Exception as convert_e:
            self.logger.error(f"Failed to convert JSON to DNS response: {convert_e}")
            # Fallback: return a SERVFAIL based on original request if conversion fails badly
            try:
                fail_response = dns.message.make_response(original_request)
                fail_response.set_rcode(dns.rcode.SERVFAIL)
                return fail_response.to_wire()
            except Exception as e:
                self.logger.error(f"Failed to return a SERVFAIL response: {convert_e}")
                return None  # Absolute last resort

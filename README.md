# Secure DNS Proxy Server (SDNS-ProxyServer)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## 📋 Overview

This script runs a local DNS server that forwards queries securely using **DNS-over-HTTPS** (DoH) instead of standard DNS. It sends encrypted queries to configurable DoH providers, significantly enhancing online privacy and security by preventing DNS eavesdropping and manipulation.

Additionally, it can optionally check requested domains against VirusTotal and/or IsMalicious APIs to block access to known malicious or suspicious sites *before* resolving them.


   `Don't forget to star ⭐ this repository `

## ✨ Key Features

* **🔒 DNS-over-HTTPS (DoH) Forwarding:** Converts standard DNS requests (UDP/TCP) into secure DoH requests.
* **🌐 Configurable DoH Providers:** Use a default list of well-known DoH providers or specify your own custom list via command-line arguments.
* **🔄 Provider Randomization:** Optionally choose a DoH provider randomly from the configured list for each query to distribute load and potentially reduce fingerprinting.
* **🛡️ Malicious Domain Blocking (Optional):**
    * Integrates with [VirusTotal](https://www.virustotal.com/) and/or [IsMalicious](https://ismalicious.com/) APIs.
    * Checks domain reputation *before* forwarding the query.
    * Blocks domains flagged as malicious or suspicious based on API results.
    * Requires API keys for the respective services (see Configuration).
* **📡 TCP & UDP Support:** Listens for and handles DNS requests over both standard UDP and TCP protocols.
* **🐳 Docker Ready:** Includes a `Dockerfile` for easy containerized deployment.

## ⚙️ Setup & Installation

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/NikEnotos/SDNS-ProxyServer.git
    cd SDNS-ProxyServer
    ```
2.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **Configure API Keys (Optional but Recommended for Blocking):**
    * If you want to use the domain blocking feature, create a file named `.env` in the project's root directory (`SDNS-ProxyServer/`).
    * Add your API keys to this file:
        ```dotenv
        # .env file contents
        VIRUSTOTAL_API_KEY=YOUR_VIRUSTOTAL_API_KEY_HERE
        ISMALICIOUS_API_KEY=YOUR_ISMALICIOUS_API_KEY_HERE
        ISMALICIOUS_API_SECRET=YOUR_ISMALICIOUS_API_SECRET_HERE
        ```
    * Obtain a VirusTotal API key from [virustotal.com](https://www.virustotal.com/).
    * Obtain IsMalicious API credentials from [ismalicious.com](https://ismalicious.com/).
    * *The script will still run without these, but the checking feature (`-c/--checker-service`) will warn and skip checks if key(s) are missing.*

## 🚀 Usage

Run the server from the command line within the project directory.

**Basic Syntax:**

```bash
python main.py [OPTIONS]
```
**Important**: Running a server on port 53 typically requires root/administrator privileges.
```bash
sudo python main.py [OPTIONS]
```
Command-Line Options:
```bash
usage: main.py [-h] [--listen-ip IP_ADDRESS] [--listen-port PORT] [-d URL [URL ...]] [-a] [-r] [-c [SERVICE]] [--redirect-ip IP] [-v]

Run a DNS proxy server that replaces DNS queries with more secure DNS over HTTPS (DoH).

options:
  -h, --help            show this help message and exit
  --listen-ip IP_ADDRESS
                        IP address for the proxy server to listen on. (default: 0.0.0.0)
  --listen-port PORT    Port for the proxy server to listen on. (default: 53)
  -d URL [URL ...], --doh-providers URL [URL ...]
                        List of DNS-over-HTTPS provider URLs. By default, this list REPLACES the built-in defaults. Use -a or --add-to-defaults to append to the defaults instead. (default: None)       
  -a, --add-to-defaults
                        If specified, URLs passed via -d or --doh-providers are ADDED to the default list, instead of replacing it. Duplicates are ignored. (default: False)
  -r, --randomize       Randomize the DoH provider selection for each request. (default: False)
  -c [SERVICE], --checker-service [SERVICE]
                        Enable domain checking and select service(s). If flag is present without a value, uses 'both'. Choices: 'virustotal', 'ismalicious', 'both'. If flag is omitted, checking is     
                        DISABLED. (default: None)
  --redirect-ip IP      IPv4 or IPv6 address to return for blocked domains (used only if -c/--checker-service is enabled).By default set to None and do not perform redirection. (default: None)
  -v, --verbose         Increase output verbosity (e.g., -v for WARNING, -vv for INFO, -vvv for DEBUG). (default: 0)
```
### **Examples**:
* Run with default settings (listens on 0.0.0.0:53, uses default DoH providers, no blocking, ERROR log level):
  ```bash
  sudo python main.py
  ```
* Run with INFO level logging, add a custom DoH provider to the defaults, randomize providers, and enable domain checking using both VirusTotal and IsMalicious:
  ```bash
  # Assumes .env file is configured with API keys
  sudo python main.py -vv -c -a -d https://my-doh-server.example/dns-query -r
  ```
* Run with DEBUG logging and use only Google's DoH servers:
  ```bash
  sudo python main.py -vvv -d https://8.8.8.8/dns-query https://8.8.4.4/dns-query
  ```
**Client Configuration**: After starting the server, configure your operating system or specific devices to use the IP address of the machine running `SDNS-ProxyServer` as their primary DNS server.

## 🐳 Docker Usage
A `Dockerfile` is provided for easy containerized deployment.
1. **Build the Docker Image**:
    ```bash
    docker build -t sdns-proxy .
    ```
2. **Run the Container**:
  * Using `--network host` is often the easiest way to allow the container to bind directly to the host machine's port 53.
    This requires running the docker run command with sudo. Alternatively, you can map the ports manually using `-p 53:53/udp -p 53:53/tcp`
  * If using domain checking (`-c`), mount your .env file into the container or use `-e` to add key(s).
  * Use `-i` (interactive) and `--rm` (remove container on exit) for convenience during testing.

**Example Command (Host Network, with .env)**:
  ```bash
  # Run with host networking, mount .env, enable 'both' checkers, INFO logging
  sudo docker run -i --rm --network host \
  -v "$(pwd)/.env:/app/.env" \
  sdns-proxy [OPTIONS]
  ```
**Example Command (Port Mapping, with manual keys adding)**:
   ```bash
  # Map host port 5353 to container port 53 (UDP and TCP)
  docker run -i --rm \
  -p 5353:53/udp \
  -p 5353:53/tcp \
  -e VIRUSTOTAL_API_KEY="YOUR_KEY" \
  -e ISMALICIOUS_API_KEY="YOUR_KEY" \
  -e ISMALICIOUS_API_SECRET="YOUR_KEY" \
  sdns-proxy [OPTIONS]
  ```
***(Remember to point your clients to port 5353 on the Docker host in this case)***

## 📄 License 
This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

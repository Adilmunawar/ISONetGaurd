```markdown
🚀 ISONetGaurd

 🔐 Overview

ISONetGaurd is a powerful, feature-rich firewall designed for isolating and protecting a local network from potentially harmful devices while providing limited access to the Internet. This firewall offers advanced packet filtering, traffic shaping, logging, and supports both IPv4 and IPv6 protocols. The firewall is ideal for securing devices, studying viruses, and configuring isolated environments for testing.

Key Features:
- 🔥 Advanced Packet Filtering: Filters packets based on IP, MAC, port, and protocol.
- ⚡ Traffic Shaping: Manages network bandwidth and applies traffic control via `tc` (Traffic Control).
- 🧩 Dynamic IP and MAC Detection: Automatically discovers IP and MAC addresses of devices on the network.
- 🌐 IPv6 Support: Full support for both IPv4 and IPv6 addresses.
- 💻 Web Interface (Placeholder): Placeholder for future integration with a web interface for easier configuration and management.
- 📝 Logging: Detailed logs of actions taken by the firewall, stored for auditing and troubleshooting.
- ⚙️ Easy Configuration: Configurable through both a file-based system and command-line arguments.

 📖 Table of Contents

1. [Features](#features)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Configuration](#configuration)
5. [Logging](#logging)
6. [Traffic Shaping](#traffic-shaping)
7. [Web Interface](#web-interface)
8. [License](#license)
9. [Contributing](#contributing)

 💡 Features

🔒 Packet Filtering
- IP Filtering: Block or allow specific IP addresses or ranges (both IPv4 and IPv6 supported).
- MAC Address Filtering: Block or allow devices based on their MAC addresses.
- Port Filtering: Filter specific ports or port ranges for additional security.
- Protocol Filtering: Allows you to filter by protocols such as TCP, UDP, ICMP, etc.

 ⚙️ Traffic Shaping
- Bandwidth Limiting: Controls the rate of data transfer using `tc` (Traffic Control) to ensure fair distribution of bandwidth.
- Priority Traffic: Allows prioritization of critical traffic while throttling less important traffic.

 📜 Logging
- Logs all allowed and dropped packets along with detailed timestamps.
- Saves logs to `/var/log/isowall.log` for easy access and auditing.
  
 🌍 Web Interface (Placeholder)
- A simple interface for managing firewall rules and settings is planned for future versions. The web interface will enable easy management and configuration via a browser.

 🌐 IPv6 Support
- Full support for both IPv4 and IPv6 addresses, making the firewall compatible with modern networks.

 🛠️ Installation

 💾 Prerequisites
- Linux-based OS (Ubuntu, Debian, CentOS, etc.)
- `libpcap-dev` (For packet capture functionality)
- `tc` (Traffic Control utility for traffic shaping)
- C Compiler (gcc)

 🔧 Steps:

1. Clone the repository:
    ```bash
    git clone https://github.com/AdilMunawar/ISONetGaurd.git
    cd ISONetGaurd
    ```

2. Install required dependencies:
    ```bash
    sudo apt-get install libpcap-dev tc
    ```

3. Compile the code:
    ```bash
    gcc -o isowall isowall.c -lpcap
    ```

4. Ensure that your user has permission to capture packets (you may need to run the program as root or use `sudo`).

 📜 Usage

Run Isowall with the following command:

```bash
./isowall --conf /path/to/config
```

 ⚙️ Command-Line Options:
- `-c <file>`: Specify the path to a custom configuration file. By default, it will look for `/etc/isowall.conf`.
- `--allow <ip/range>`: Allow a specific IP or range of IPs.
- `--block <ip/range>`: Block a specific IP or range of IPs.
- `--blockfile <filename>`: Load block ranges from a file.
- `--echo`: Output the current configuration to a file.
- `--packet-trace`: Enable packet tracing for debugging.
- `--reuse-external`: Reuse an existing external network adapter.

 🔧 Example Usage:

```bash
./isowall --conf /etc/isowall.conf
```

This will load the configuration from `/etc/isowall.conf` and apply the firewall settings.
```

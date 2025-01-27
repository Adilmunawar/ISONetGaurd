#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <pcap.h>
#include <ifaddrs.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define CONFIG_FILE "/etc/isowall.conf"
#define LOG_FILE "/var/log/isowall.log"
#define MAX_BLOCKED_IPS 100
#define MAX_ALLOWED_IPS 100
#define MAX_BLOCKED_MACS 100
#define MAX_PACKET_LOGS 1000

// Function Prototypes
void log_message(const char *message);
int load_config(const char *file);
void detect_interfaces();
void get_ip_mac_address(const char *interface, char *ip, char *mac);
void start_packet_filtering();
int should_allow_packet(const u_char *packet);
int is_ip_blocked(const struct in_addr *ip);
int is_mac_blocked(const u_char *mac);
void handle_web_interface();
void apply_traffic_shaping();
void log_packet(const u_char *packet, const struct pcap_pkthdr *header);
void dynamic_ip_block(const struct in_addr *ip);
void alert_admin(const char *message);

// Configuration and rule handling
typedef struct {
    char *interface;
    char *target_ip;
    char *target_mac;
    char *router_ip;
    char *external_interface;
    char *block_list[MAX_BLOCKED_IPS];
    char *allow_list[MAX_ALLOWED_IPS];
    char *blocked_mac_list[MAX_BLOCKED_MACS];
} firewall_config;

firewall_config config;

// Main function with command-line parsing and logic
int main(int argc, char *argv[]) {
    char *config_file = CONFIG_FILE;
    int option;
    
    // Parse command-line options
    while ((option = getopt(argc, argv, "c:")) != -1) {
        switch (option) {
            case 'c':
                config_file = optarg;
                break;
            default:
                printf("Usage: isowall [--conf <file.conf>] [options]\n");
                return EXIT_FAILURE;
        }
    }
    
    // Load configuration
    if (load_config(config_file) != 0) {
        fprintf(stderr, "Error loading configuration\n");
        return EXIT_FAILURE;
    }

    // Detect network interfaces
    detect_interfaces();

    // Apply traffic shaping rules
    apply_traffic_shaping();

    // Start packet filtering (i.e., run firewall)
    start_packet_filtering();

    // Handle web interface (if applicable)
    handle_web_interface();
    
    return EXIT_SUCCESS;
}

// Print usage of the command
void print_usage() {
    printf("Usage: isowall [--conf <file.conf>] [options]\n");
    printf("Options:\n");
    printf("  -c <file>  Specify configuration file (default: /etc/isowall.conf)\n");
}

// Logging function
void log_message(const char *message) {
    FILE *logfile = fopen(LOG_FILE, "a");
    if (!logfile) {
        perror("Error opening log file");
        return;
    }

    time_t now;
    time(&now);
    fprintf(logfile, "[%s] %s\n", ctime(&now), message);
    fclose(logfile);
}

// Load configuration file and parse it
int load_config(const char *file) {
    FILE *config_file = fopen(file, "r");
    if (!config_file) {
        perror("Error opening config file");
        return -1;
    }
    // Here you'd parse the configuration file
    // For this example, we mock it with a basic hardcoded configuration

    config.interface = "eth1";
    config.target_ip = "192.168.1.10";
    config.target_mac = "00:1A:2B:3C:4D:5E";
    config.router_ip = "192.168.1.1";
    config.external_interface = "eth0";

    // Block/Allow lists (hardcoded for demo)
    config.block_list[0] = "10.0.0.0/8";
    config.allow_list[0] = "0.0.0.0/0";
    config.blocked_mac_list[0] = "00:1A:2B:3C:4D:5E";

    fclose(config_file);
    return 0;
}

// Detect network interfaces and their IP/MAC addresses
void detect_interfaces() {
    struct ifaddrs *ifaddr, *ifa;
    getifaddrs(&ifaddr);

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family == AF_INET || ifa->ifa_addr->sa_family == AF_INET6) {
            printf("Detected Interface: %s\n", ifa->ifa_name);
            // Further logic for handling the interface can be added here
        }
    }
    freeifaddrs(ifaddr);
}

// Example of dynamically getting IP/MAC address of a given interface
void get_ip_mac_address(const char *interface, char *ip, char *mac) {
    // Dummy implementation: System calls or library functions would go here
    // Example: system("ifconfig eth0 | grep inet");
}

// Packet filtering function (simplified)
void start_packet_filtering() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;

    // Open network device for packet capture
    handle = pcap_open_live(config.interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return;
    }

    // Process packets
    while ((packet = pcap_next(handle, &header)) != NULL) {
        // Log the packet for monitoring
        log_packet(packet, &header);
        
        // Filter packets based on configuration
        if (should_allow_packet(packet)) {
            printf("Allowed packet: %u bytes\n", header.len);
        } else {
            printf("Dropped packet\n");
        }
    }

    pcap_close(handle);
}

// Simplified packet filtering logic
int should_allow_packet(const u_char *packet) {
    // Example packet check: If it's an IP packet, filter based on IP/MAC
    struct ip *ip_header = (struct ip *)(packet + 14);  // 14 bytes Ethernet header
    if (ip_header->ip_p == IPPROTO_TCP) {
        if (is_ip_blocked(&ip_header->ip_src)) {
            return 0;  // Block IP
        }
    }

    return 1;  // Allow packet
}

// Check if an IP address is blocked
int is_ip_blocked(const struct in_addr *ip) {
    // Check against block list (mock implementation)
    if (strcmp(inet_ntoa(*ip), "10.0.0.1") == 0) {
        return 1;  // Blocked
    }
    return 0;
}

// Check if a MAC address is blocked (simplified)
int is_mac_blocked(const u_char *mac) {
    // Compare MAC address (this is just a simplified check)
    if (memcmp(mac, "\x00\x1A\x2B\x3C\x4D\x5E", 6) == 0) {
        return 1;  // Blocked
    }
    return 0;
}

// Traffic shaping with tc (Traffic Control)
void apply_traffic_shaping() {
    // Example: Using tc to limit bandwidth on the external interface (eth0)
    char command[256];
    snprintf(command, sizeof(command), "tc qdisc add dev %s root handle 1: htb default 12", config.external_interface);
    system(command);
    snprintf(command, sizeof(command), "tc class add dev %s parent 1: classid 1:12 htb rate 512kbps", config.external_interface);
    system(command);
}

// Log packet information
void log_packet(const u_char *packet, const struct pcap_pkthdr *header) {
    // Log the source and destination IPs and the packet size
    struct ip *ip_header = (struct ip *)(packet + 14);  // 14 bytes Ethernet header
    char log_message_str[512];
    snprintf(log_message_str, sizeof(log_message_str), 
             "Packet logged: Src IP: %s, Dst IP: %s, Size: %u bytes",
             inet_ntoa(ip_header->ip_src),
             inet_ntoa(ip_header->ip_dst),
             header->len);
    log_message(log_message_str);
}

// Dynamically block an IP (simplified)
void dynamic_ip_block(const struct in_addr *ip) {
    printf("Blocking IP: %s\n", inet_ntoa(*ip));
    // Here you could add it to the block list dynamically
}

// Alert the admin (e.g., via email or other means)
void alert_admin(const char *message) {
    // Placeholder for sending alerts via email/SMS
    printf("ALERT: %s\n", message);
}

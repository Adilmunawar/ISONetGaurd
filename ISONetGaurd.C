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
#include <pthread.h>
#include "mongoose.h"

#define CONFIG_FILE "/etc/isowall.conf"
#define LOG_FILE "/var/log/isowall.log"
#define MAX_BLOCKED_IPS 100
#define MAX_ALLOWED_IPS 100
#define MAX_BLOCKED_MACS 100
#define MAX_PACKET_LOGS 1000
#define BLOCK_DURATION 60 // Time in seconds for temporary IP block
#define MAX_TRACKED_IPS 1000
#define DDOS_THRESHOLD 1000 // Max packets from an IP in 1 second
#define MAX_PACKETS_PER_IP 1000

static const char *s_http_port = "8000";
static struct mg_serve_http_opts s_http_server_opts;
static struct mg_mgr mgr;

typedef struct {
    char *interface;
    char *target_ip;
    char *target_mac;
    char *router_ip;
    char *external_interface;
    char *block_list[MAX_BLOCKED_IPS];
    char *allow_list[MAX_ALLOWED_IPS];
    char *blocked_mac_list[MAX_BLOCKED_MACS];
    pthread_mutex_t block_list_mutex;
} firewall_config;

firewall_config config;

typedef struct {
    char ip[INET_ADDRSTRLEN];
    int packet_count;
    time_t last_seen;
} ip_tracker;

ip_tracker tracked_ips[MAX_TRACKED_IPS];

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

    struct mg_connection *c;
    for (c = mg_next(&mgr, NULL); c != NULL; c = mg_next(&mgr, c)) {
        if (c->user_data != NULL) {
            mg_send_websocket_frame(c, WEBSOCKET_OP_TEXT, message, strlen(message));
        }
    }
}

int load_config(const char *file) {
    FILE *config_file = fopen(file, "r");
    if (!config_file) {
        perror("Error opening config file");
        return -1;
    }

    config.interface = "eth1";
    config.target_ip = "192.168.1.10";
    config.target_mac = "00:1A:2B:3C:4D:5E";
    config.router_ip = "192.168.1.1";
    config.external_interface = "eth0";
    pthread_mutex_init(&config.block_list_mutex, NULL);

    config.block_list[0] = "10.0.0.0/8";
    config.allow_list[0] = "0.0.0.0/0";
    config.blocked_mac_list[0] = "00:1A:2B:3C:4D:5E";

    fclose(config_file);
    return 0;
}

void detect_interfaces() {
    struct ifaddrs *ifaddr, *ifa;
    getifaddrs(&ifaddr);

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family == AF_INET || ifa->ifa_addr->sa_family == AF_INET6) {
            printf("Detected Interface: %s\n", ifa->ifa_name);
        }
    }
    freeifaddrs(ifaddr);
}

void start_packet_filtering() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;

    handle = pcap_open_live(config.interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return;
    }

    while ((packet = pcap_next(handle, &header)) != NULL) {
        log_packet(packet, &header);

        struct ip *ip_header = (struct ip *)(packet + 14);
        track_ip(&ip_header->ip_src);

        if (should_allow_packet(packet)) {
            printf("Allowed packet: %u bytes\n", header.len);
        } else {
            printf("Dropped packet\n");
        }
    }

    pcap_close(handle);
}

int should_allow_packet(const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14);

    if (ip_header->ip_p == IPPROTO_TCP || ip_header->ip_p == IPPROTO_UDP || ip_header->ip_p == IPPROTO_ICMP) {
        if (is_ip_blocked(&ip_header->ip_src)) {
            return 0;  // Block IP
        }
    }

    return 1;  // Allow packet
}

void track_ip(const struct in_addr *ip) {
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ip, ip_str, INET_ADDRSTRLEN);

    for (int i = 0; i < MAX_TRACKED_IPS; i++) {
        if (tracked_ips[i].packet_count > 0 && strcmp(tracked_ips[i].ip, ip_str) == 0) {
            tracked_ips[i].packet_count++;
            tracked_ips[i].last_seen = time(NULL);
            if (tracked_ips[i].packet_count > DDOS_THRESHOLD) {
                printf("Anomalous traffic detected from IP: %s\n", ip_str);
                dynamic_ip_block(ip);
            }
            return;
        }
    }

    for (int i = 0; i < MAX_TRACKED_IPS; i++) {
        if (tracked_ips[i].packet_count == 0) {
            strcpy(tracked_ips[i].ip, ip_str);
            tracked_ips[i].packet_count = 1;
            tracked_ips[i].last_seen = time(NULL);
            return;
        }
    }
}

int is_ip_blocked(const struct in_addr *ip) {
    pthread_mutex_lock(&config.block_list_mutex);
    for (int i = 0; i < MAX_BLOCKED_IPS; i++) {
        if (config.block_list[i] && strcmp(inet_ntoa(*ip), config.block_list[i]) == 0) {
            pthread_mutex_unlock(&config.block_list_mutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&config.block_list_mutex);
    return 0;
}

void log_packet(const u_char *packet, const struct pcap_pkthdr *header) {
    struct ip *ip_header = (struct ip *)(packet + 14);
    char log_message_str[512];
    snprintf(log_message_str, sizeof(log_message_str), 
             "Packet logged: Src IP: %s, Dst IP: %s, Size: %u bytes",
             inet_ntoa(ip_header->ip_src),
             inet_ntoa(ip_header->ip_dst),
             header->len);
    log_message(log_message_str);
}

void dynamic_ip_block(const struct in_addr *ip) {
    printf("Blocking IP: %s\n", inet_ntoa(*ip));
    pthread_mutex_lock(&config.block_list_mutex);
    for (int i = 0; i < MAX_BLOCKED_IPS; i++) {
        if (!config.block_list[i]) {
            config.block_list[i] = strdup(inet_ntoa(*ip));
            break;
        }
    }
    pthread_mutex_unlock(&config.block_list_mutex);
    
    pthread_t cleanup_thread;
    pthread_create(&cleanup_thread, NULL, dynamic_block_cleanup, (void *)ip);
}

void *dynamic_block_cleanup(void *arg) {
    struct in_addr *ip = (struct in_addr *)arg;
    sleep(BLOCK_DURATION);

    pthread_mutex_lock(&config.block_list_mutex);
    for (int i = 0; i < MAX_BLOCKED_IPS; i++) {
        if (config.block_list[i] && strcmp(inet_ntoa(*ip), config.block_list[i]) == 0) {
            free(config.block_list[i]);
            config.block_list[i] = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&config.block_list_mutex);
    return NULL;
}

void alert_admin(const char *message) {
    printf("ALERT: %s\n", message);
}

void apply_traffic_shaping() {
    if (is_http_traffic()) {
        limit_http_requests();
    }
}

int is_http_traffic() {
    return 1;
}

void limit_http_requests() {
    printf("Limiting excessive HTTP requests.\n");
}

static void ev_handler(struct mg_connection *nc, int ev, void *ev_data) {
    switch (ev) {
        case MG_EV_HTTP_REQUEST:
            mg_serve_http(nc, ev_data, s_http_server_opts);
            break;
        case MG_EV_WEBSOCKET_HANDSHAKE_DONE:
            nc->user_data = (void *)1;
            break;
        case MG_EV_WEBSOCKET_FRAME: {
            struct websocket_message *wm = (struct websocket_message *)ev_data;
            break;
        }
        case MG_EV_CLOSE:
            if (nc->user_data != NULL) {
            }
            break;
        default:
            break;
    }
}

void start_web_server() {
    struct mg_connection *nc;

    mg_mgr_init(&mgr, NULL);
    nc = mg_bind(&mgr, s_http_port, ev_handler);
    if (nc == NULL) {
        fprintf(stderr, "Failed to create listener\n");
        return;
    }

    mg_set_protocol_http_websocket(nc);
    s_http_server_opts.document_root = "web_root";

    printf("Starting web server on port %s\n", s_http_port);
    for (;;) {
        mg_mgr_poll(&mgr, 1000);
    }
    mg_mgr_free(&mgr);
}

int main(int argc, char *argv[]) {
    char *config_file = CONFIG_FILE;
    int option;
    
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
    
    if (load_config(config_file) != 0) {
        fprintf(stderr, "Error loading configuration\n");
        return EXIT_FAILURE;
    }

    detect_interfaces();
    apply_traffic_shaping();
    start_packet_filtering();
    start_web_server();
    
    return EXIT_SUCCESS;
}

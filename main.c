#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <net/if.h>     
#include <sys/socket.h>
#include <netinet/in.h>


int is_private_ip(struct in_addr ip) {
    unsigned char *bytes = (unsigned char *)&ip.s_addr;

    uint32_t ip_host = ntohl(ip.s_addr);
    
    if ((ip_host & 0xFF000000) == 0x0A000000) {
        return 1;
    }
    
    if ((ip_host & 0xFFF00000) == 0xAC100000) {
        return 1;
    }
    
    if ((ip_host & 0xFFFF0000) == 0xC0A80000) {
        return 1;
    }

    return 0;
}

int find_private_ipv4_interface(char *interface_name, size_t name_len) {
    pcap_if_t *alldevs, *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Erro ao buscar dispositivos: %s\n", errbuf);
        return -1;
    }

    for (dev = alldevs; dev != NULL; dev = dev->next) {
        pcap_addr_t *address;
        for (address = dev->addresses; address != NULL; address = address->next) {
            if (address->addr && address->addr->sa_family == AF_INET) {
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)address->addr;
                if (is_private_ip(ipv4->sin_addr)) {
                    strncpy(interface_name, dev->name, name_len-1);
                    interface_name[name_len-1] = '\0';
                    pcap_freealldevs(alldevs);
                    return 0; 
                }
            }
        }
    }

    pcap_freealldevs(alldevs);
    return -1; 
}


#define MAX_CONNECTIONS 100
#define SCAN_THRESHOLD 10
#define SCAN_TIMEFRAME 5

typedef struct {
    char ip[INET_ADDRSTRLEN];
    int port;
    time_t last_seen;
} connection_t;

connection_t connections[MAX_CONNECTIONS];
int connection_count = 0;

void add_connection(const char *ip, int port) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].ip, ip) == 0 && connections[i].port == port) {
            connections[i].last_seen = time(NULL);
            return;
        }
    }
    if (connection_count < MAX_CONNECTIONS) {
        strcpy(connections[connection_count].ip, ip);
        connections[connection_count].port = port;
        connections[connection_count].last_seen = time(NULL);
        connection_count++;
    }
}

void check_for_scanning() {
    time_t now = time(NULL);
    for (int i = 0; i < connection_count; i++) {
        if (difftime(now, connections[i].last_seen) > SCAN_TIMEFRAME) {
            memmove(&connections[i], &connections[i + 1], (connection_count - i - 1) * sizeof(connection_t));
            connection_count--;
            i--;
        }
    }

    for (int i = 0; i < connection_count; i++) {
        int count = 0;
        for (int j = 0; j < connection_count; j++) {
            if (strcmp(connections[i].ip, connections[j].ip) == 0) {
                count++;
            }
        }
        if (count > SCAN_THRESHOLD) {
            printf("Possível ataque de port scanning detectado de %s\n", connections[i].ip);
        }
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header = (struct ip*)(packet + 14); 

    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr*)(packet + 14 + ip_header->ip_hl * 4);
        printf("TCP: %s:%d -> %s:%d\n",
               inet_ntoa(ip_header->ip_src), ntohs(tcp_header->th_sport),
               inet_ntoa(ip_header->ip_dst), ntohs(tcp_header->th_dport));

        add_connection(inet_ntoa(ip_header->ip_src), ntohs(tcp_header->th_sport));
        check_for_scanning();
    }
}

int main() {
	
    char interface_name[256];
    if (find_private_ipv4_interface(interface_name, sizeof(interface_name)) == -1) {
        fprintf(stderr, "Nenhuma interface com IP privado encontrada\n");
        return 1;
    }

    printf("Interface escolhida para captura: %s\n", interface_name);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface_name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Erro ao abrir o dispositivo %s: %s\n", interface_name, errbuf);
        return 1;
    }

    struct bpf_program fp;
    char filter_exp[] = "tcp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Erro ao compilar filtro\n");
        pcap_close(handle);
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Erro ao aplicar filtro\n");
        pcap_freecode(&fp);
        pcap_close(handle);
        return 2;
    }

    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}


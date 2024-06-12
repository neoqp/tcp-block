#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <stdbool.h>

typedef struct _pesudoHeader {
    uint32_t srcAddr;
    uint32_t dstAddr;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcpLen;
} pesudoHeader;

typedef struct {
    u_int8_t ether_dmac[6];
    u_int8_t ether_smac[6];
    u_int16_t ether_type;
} EthHdr;

typedef struct {
    u_int16_t th_sport;
    u_int16_t th_dport;
    u_int32_t th_seq;
    u_int32_t th_ack;
    u_int8_t th_offx2;
    u_int8_t th_flags;
    u_int16_t th_win;
    u_int16_t th_sum;
    u_int16_t th_urp;
} TcpHdr;

typedef struct {
    u_int8_t ip_vhl;
    u_int8_t ip_tos;
    u_int16_t ip_len;
    u_int16_t ip_id;
    u_int16_t ip_off;
    u_int8_t ip_ttl;
    u_int8_t ip_p;
    u_int16_t ip_sum;
    struct in_addr ip_src, ip_dst;
} IpHdr;

typedef struct {
    uint8_t dmac_[6];
    uint8_t smac_[6];
    uint16_t type_;
} Mac;

Mac my_mac;

void usage() {
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

void get_my_mac(const char* dev, Mac* mac) {
    FILE* mac_file = fopen("/sys/class/net/", "r");
    if (!mac_file) {
        perror("Failed to open MAC address file\n");
        exit(EXIT_FAILURE);
    }
    char mac_address[18];
    fscanf(mac_file, "%s", mac_address);
    fclose(mac_file);

    sscanf(mac_address, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac->dmac_[0], &mac->dmac_[1], &mac->dmac_[2],
           &mac->dmac_[3], &mac->dmac_[4], &mac->dmac_[5]);
}

uint16_t Checksum(uint16_t* ptr, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(uint8_t*)ptr;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

void send_packet(pcap_t* handle, const char* packet, int len) {
    if (pcap_sendpacket(handle, (const u_char*)packet, len)) {
        fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return EXIT_FAILURE;
    }

    char* dev = argv[1];
    char* pattern = argv[2];

    get_my_mac(dev, &my_mac);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (!handle) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;

    while (true) {
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d: %s\n", res, pcap_geterr(handle));
            break;
        }

        EthHdr* ethernet_hdr = (EthHdr*)packet;
        if (ntohs(ethernet_hdr->ether_type) != ETHERTYPE_IP) continue;

        IpHdr* ip_hdr = (IpHdr*)(packet + sizeof(EthHdr));
        uint32_t iphdr_len = ip_hdr->ip_vhl & 0x0f;
        uint32_t ippkt_len = ntohs(ip_hdr->ip_len);
        if (ip_hdr->ip_p != IPPROTO_TCP) continue;

        TcpHdr* tcp_hdr = (TcpHdr*)((uint8_t*)ip_hdr + iphdr_len * 4);
        uint32_t tcphdr_len = (tcp_hdr->th_offx2 >> 4) * 4;
        uint32_t tcpdata_len = ippkt_len - iphdr_len * 4 - tcphdr_len;
        if (tcpdata_len == 0) continue;

        char* tcp_data = (char*)((uint8_t*)tcp_hdr + tcphdr_len);
        if (strstr(tcp_data, pattern) && memcmp(tcp_data, "GET", 3) == 0) {
			// Send redirect packet to client
            int http_pkt_len = sizeof(EthHdr) + iphdr_len * 4 + tcphdr_len + strlen("HTTP/1.1 302 Found\r\nLocation: http://warning.or.kr\r\n\r\n");
            char* http_pkt = (char*)malloc(http_pkt_len);
            memset(http_pkt, 0, http_pkt_len);
            memcpy(http_pkt, packet, sizeof(EthHdr) + iphdr_len * 4 + tcphdr_len);

            EthHdr* http_eth_hdr = (EthHdr*)http_pkt;
            IpHdr* http_ip_hdr = (IpHdr*)(http_pkt + sizeof(EthHdr));
            TcpHdr* http_tcp_hdr = (TcpHdr*)((uint8_t*)http_ip_hdr + iphdr_len * 4);
            char* http_data = (char*)((uint8_t*)http_tcp_hdr + tcphdr_len);

            memcpy(http_eth_hdr->ether_dmac, ethernet_hdr->ether_smac, 6);
            memcpy(http_eth_hdr->ether_smac, my_mac.dmac_, 6);
            http_ip_hdr->ip_ttl = 128;
            http_ip_hdr->ip_src = ip_hdr->ip_dst;
            http_ip_hdr->ip_dst = ip_hdr->ip_src;
            http_tcp_hdr->th_seq = tcp_hdr->th_ack;
            http_tcp_hdr->th_ack = htonl(ntohl(tcp_hdr->th_seq) + tcpdata_len);
            http_tcp_hdr->th_flags = TH_ACK;
            http_tcp_hdr->th_sum = 0;
            http_ip_hdr->ip_sum = 0;

            memcpy(http_data, "HTTP/1.1 302 Found\r\nLocation: http://warning.or.kr\r\n\r\n", strlen("HTTP/1.1 302 Found\r\nLocation: http://warning.or.kr\r\n\r\n"));
            http_tcp_hdr->th_sum = Checksum((uint16_t*)http_tcp_hdr, http_pkt_len - sizeof(EthHdr) - sizeof(IpHdr));
            http_ip_hdr->ip_sum = Checksum((uint16_t*)http_ip_hdr, sizeof(IpHdr));

            send_packet(handle, http_pkt, http_pkt_len);
            free(http_pkt);


			// Send FIN packet to client
			int fin_pkt_len = sizeof(EthHdr) + iphdr_len * 4 + tcphdr_len;

			char* fin_pkt = (char*)malloc(fin_pkt_len);
			memset(fin_pkt, 0, fin_pkt_len);
			memcpy(fin_pkt, packet, fin_pkt_len);

			EthHdr* fin_eth_hdr = (EthHdr*)fin_pkt;
			IpHdr* fin_ip_hdr = (IpHdr*)(fin_pkt + sizeof(EthHdr));
			TcpHdr* fin_tcp_hdr = (TcpHdr*)((uint8_t*)fin_ip_hdr + iphdr_len * 4);

			memcpy(fin_eth_hdr->ether_dmac, ethernet_hdr->ether_smac, 6);
			memcpy(fin_eth_hdr->ether_smac, my_mac.dmac_, 6);
			fin_ip_hdr->ip_ttl = 128;
			fin_ip_hdr->ip_len = htons(fin_pkt_len - sizeof(EthHdr));
			fin_ip_hdr->ip_src = ip_hdr->ip_dst;
			fin_ip_hdr->ip_dst = ip_hdr->ip_src;
			fin_tcp_hdr->th_seq = tcp_hdr->th_ack;
			fin_tcp_hdr->th_ack = htonl(ntohl(tcp_hdr->th_seq) + tcpdata_len);
			fin_tcp_hdr->th_flags = TH_FIN;
			fin_tcp_hdr->th_sum = 0;

			fin_tcp_hdr->th_sum = Checksum((uint16_t*)fin_tcp_hdr, fin_pkt_len - sizeof(EthHdr) - sizeof(IpHdr));

			send_packet(handle, fin_pkt, fin_pkt_len);
			free(fin_pkt);

            // Send RST packet to server
            int rst_pkt_len = sizeof(EthHdr) + iphdr_len * 4 + tcphdr_len;
			char* rst_pkt = (char*)malloc(rst_pkt_len);
			memset(rst_pkt, 0, rst_pkt_len);
			memcpy(rst_pkt, packet, rst_pkt_len);

			EthHdr* rst_eth_hdr = (EthHdr*)rst_pkt;
			IpHdr* rst_ip_hdr = (IpHdr*)(rst_pkt + sizeof(EthHdr));
			TcpHdr* rst_tcp_hdr = (TcpHdr*)((uint8_t*)rst_ip_hdr + iphdr_len * 4);

			memcpy(rst_eth_hdr->ether_dmac, ethernet_hdr->ether_dmac, 6);
			memcpy(rst_eth_hdr->ether_smac, my_mac.dmac_, 6);
			rst_ip_hdr->ip_ttl = 128;
			rst_ip_hdr->ip_len = htons(rst_pkt_len - sizeof(EthHdr));
			rst_tcp_hdr->th_seq = tcp_hdr->th_ack;
			rst_tcp_hdr->th_ack = 0;
			rst_tcp_hdr->th_flags = TH_RST;
			rst_tcp_hdr->th_sum = 0;

			rst_tcp_hdr->th_sum = Checksum((uint16_t*)rst_tcp_hdr, rst_pkt_len - sizeof(EthHdr) - sizeof(IpHdr));

			send_packet(handle, rst_pkt, rst_pkt_len);
			free(rst_pkt);
        }
    }

    pcap_close(handle);
    return EXIT_SUCCESS;
}


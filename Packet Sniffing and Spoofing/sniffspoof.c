// Kevin Huang
// CSS 537
// sniffspoof.c
// 01/24/2022

#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                  /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4, //IP header length
                       iph_ver:4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag:3, //Fragmentation flags
                       iph_offset:13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address 
    struct  in_addr    iph_destip;   //Destination IP address 
};

/* ICMP Header  */
struct icmpheader {
    unsigned char icmp_type; // ICMP message type
    unsigned char icmp_code; // Error code
    unsigned short int icmp_chksum; //Checksum for ICMP Header and data
    unsigned short int icmp_id;     //Used for identifying request
    unsigned short int icmp_seq;    //Sequence number
};

/* Internet Checksum */
unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

    /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all 
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16 
    sum += (sum >> 16);                  // add carry 
    return (unsigned short)(~sum);
}

/* Send IP packet using raw socket */
void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, 
                        &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0, 
            (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

// Process captured packet
void got_packet(u_char *args, const struct pcap_pkthdr *header, 
                                const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader * ip = (struct ipheader *)
                            (packet + sizeof(struct ethheader)); 

    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));  
    printf("         To: %s\n", inet_ntoa(ip->iph_destip));   

    /* determine protocol */
    switch(ip->iph_protocol) {                               
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");

            struct icmpheader *previmcp = (struct icmpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));
            if (previmcp->icmp_type == 8) {
                printf("   This is an ICMP request\n");

                // Copy packet to edit
                int size = ntohs(ip->iph_len) + sizeof(struct ethheader);
                char buffer[size];
                memcpy(buffer, packet, size);
                
                // Fill in the ICMP header.
                struct icmpheader *icmp = (struct icmpheader *) 
                                (buffer + sizeof(struct ipheader) + sizeof(struct ethheader));
                icmp->icmp_type = 0; //ICMP Type: 0 is reply.

                // Calculate the checksum for integrity
                icmp->icmp_chksum = 0;
                icmp->icmp_chksum = in_cksum((unsigned short *)icmp, 
                                        sizeof(struct icmpheader));

                // Fill in the IP header.
                struct ipheader *newip = (struct ipheader *)(buffer + sizeof(struct ethheader));
                memcpy(&(newip->iph_sourceip.s_addr), &(ip->iph_sourceip), 4);
                memcpy(&(newip->iph_destip.s_addr), &(ip->iph_destip), 4);

                // Send the spoofed packet
                printf("   Sending spoofed ICMP reply\n");
                send_raw_ip_packet(ip);                
            }
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }
  }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net;

    // Open live pcap session on NIC
    handle = pcap_open_live("br-8349f2980054", BUFSIZ, 1, 1000, errbuf); 

    // Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);              
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }                                

    // Capture packets
    pcap_loop(handle, -1, got_packet, NULL);                    

    // Close the handle
    pcap_close(handle);   
    return 0;
}

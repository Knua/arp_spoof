# target dependency
# 	command

# 최상단의 all target 은 암묵적 약속
all: arp_spoof

# target 이 빌드되기 위해 command 명령어가 실행되는 조건 -> dependency 의 날짜가 target 보다 최신인 경우
arp_spoof: arp_spoof.o arp_packet.o
	g++ -g -o arp_spoof arp_spoof.o arp_packet.o -lpcap

arp_spoof.o: arp_spoof.cpp arp_packet.h
	g++ -std=c++14 -g -c -o arp_spoof.o arp_spoof.cpp

arp_packet.o: arp_packet.cpp arp_packet.h
	g++ -std=c++14 -g -c -o arp_packet.o arp_packet.cpp

# 최하단의 clean target 또한 암묵적 약속
clean:
	rm -f arp_spoof *.o

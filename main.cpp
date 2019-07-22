#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

struct Ethernet{
    uint8_t DestMac[6];
    uint8_t SourceMac[6];
    uint16_t type;
};

struct IP_H{
    uint8_t version;
    uint8_t TOS;
    uint16_t TL;
    uint16_t Identification;
    uint16_t flags;
    uint8_t TTL;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t SourceAddress[4];
    uint8_t DestinationAddress[4];
};

struct TCP_H{
    uint8_t SourcePort[2];
    uint8_t DestinationPort[2];
    uint32_t SequenceNumber;
    uint32_t AcknowledgementNumber;
    uint8_t Headerlength;
    uint8_t flags;
    uint16_t WindowSize;
    uint16_t checksum;
    uint16_t UrgentPointer;
};

struct Data{
    uint8_t data[10];
};

uint16_t my_ntohs(uint16_t n) {
    uint8_t r = n;
    uint8_t r2 = n >> 8;
    n = (r << 8) | r2;
    return n;
}

uint8_t my_ntohs2(uint8_t n) {
    return n << 4 | n;
}

void printMac(uint8_t *value){
    for(int i=0; i < 6; i++)
    {
        printf("%02X", value[i]);
        if(i!=5) {printf(":");}
    }
    putchar('\n');
}

void printIp(uint8_t *value){
    printf("%d.%d.%d.%d", value[0], value[1], value[2], value[3]);
    putchar('\n');
}

void printPort(uint8_t *value){
    int portnum = (value[0] << 8 | value[1]);
    printf("%d\n", portnum);
}

void printData(uint8_t* value){
     for(int i=0; i<10; i++)
     {
         printf("%02X ", value[i]);
     }
     putchar('\n');

}


int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    struct Ethernet* ether = (Ethernet *)packet;
    struct IP_H* IH = (IP_H *)(packet + sizeof(struct Ethernet));
    struct TCP_H* TH = (TCP_H *)(packet + sizeof(struct Ethernet) + sizeof(struct IP_H) + my_ntohs2((IH->version & 0x0000FFFF)*4 - 20));
    struct Data* DA = (Data *)(packet + (sizeof(struct Ethernet) + sizeof(struct IP_H) + sizeof(struct TCP_H)));

    if(ether->type == my_ntohs(0x0800))
    {
        if(IH->protocol == 0x06)
        {
            printf("========================= Packet Capture ==========================\n");
            printf("DestMac : ");
            printMac(ether->DestMac);
            printf("SourMac : ");
            printMac(ether->SourceMac);
            printf("SourceAddress : ");
            printIp(IH->SourceAddress);
            printf("DestinationAddress : ");
            printIp(IH->DestinationAddress);
            printf("Source Port : ");
            printPort(TH->SourcePort);
            printf("Destination Port : ");
            printPort(TH->DestinationPort);
            printf("Data : ");
            if( ((IH->TL) - my_ntohs(0x0028)) == 0 )
                printf("\n");
            else
                printData(DA->data);
            printf("===================================================================\n");
        }
    }
  }

  pcap_close(handle);
  return 0;
}

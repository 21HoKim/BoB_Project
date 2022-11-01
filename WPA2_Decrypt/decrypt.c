#include <stdio.h>
#include <pcap.h>


#include <stdbool.h>
#include <stdlib.h>
#include "decrypt.h"
#include "eapol.h"

void usage()
{
    printf("syntax: decrypt <interface>\n");
    printf("sample: decrypt wlan0\n");
}

typedef struct
{
    char *dev_;
} Param;

Param param = {
    .dev_ = NULL};

bool parse(Param *param, int argc, char *argv[])
{
    if (argc != 2)
    {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void PtData(const u_char *packet, u_char caplen)
{
    for (int i = 0; i < caplen; i++)
    {
        if (i % 8 == 0 && i != 0 && i % 16 != 0)
        {
            printf("| ");
        }
        if (i % 16 == 0 && i != 0)
        {
            printf("\n");
        }
        *(packet + i) < 16 ? printf("0%x ", *(packet + i)) : printf("%x ", *(packet + i));
    }
    printf("\n");
}



bool IsEAPOL(const u_char *packet)
{
    packet=JumpRadio(packet);
    QoS *qos = (QoS *)packet;
    //printf("Type : %x Subtype : %x Version : %x\n", qos->Type, qos->Subtype,qos->Version);
    if (qos->Type == 2 && qos->Subtype == 8)
    {
        if (qos->Protected_flag == 0)
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    return false;
}

const u_char* JumpRadio(const u_char *packet)
{
    //u_char *packet_2=packet;
    if (packet == NULL)
    {
        printf("packet is NULL!!!\n");
        exit(1);
    }
    Radio *rad = (Radio *)packet;

    return packet+(rad->hdr_len);
}

void CapturePacket(const unsigned char *Interface)
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        exit(1);
    }

    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        Radio *rad;
        rad = (Radio *)packet;
        //PtData(packet,header->caplen);
        if (IsEAPOL(packet))
        {
            printf("EAPOL Capture!!!\n");
        }
    }
    pcap_close(pcap);
}

int main(int argc, char *argv[])
{

    unsigned char *Interface;

    if (!parse(&param, argc, argv))
        return -1;
    Interface=argv[1];
    CapturePacket(Interface);

    return 0;
}

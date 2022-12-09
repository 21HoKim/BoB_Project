#pragma once

#ifndef PCAP_H
#define PCAP_H
#include <pcap.h>
#endif

#include "crypto.h"
typedef struct WPA2noPMF_Information
{
    unsigned char AP_mac[6];
    unsigned char STA_mac[6];
    unsigned char Anonce[32];
    unsigned char Snonce[32];
    unsigned char PSK[32];
    unsigned char KCK[16];
    unsigned char KEK[16];
    unsigned char TK[16];
    unsigned char MIC_Tx[8];
    unsigned char MIC_Rx[8];
} WPA2noPMF_info;

void GetPTK_noPMF(struct WPA_ST_info **st_cur, WPA2noPMF_info *wpa2_noPMF_info);
void GetPSK_noPMF(const unsigned char *passwd, const unsigned char *ssid, WPA2noPMF_info *wpa2_noPMF_info);
void GetPMK(WPA2noPMF_info *wpa2_noPMF_info, unsigned char *PMK);
void HMAC_sha1(const unsigned char *key, size_t key_len, const unsigned char *message, unsigned char *out);
void Pad(const unsigned char *key,size_t key_len, unsigned char *out);
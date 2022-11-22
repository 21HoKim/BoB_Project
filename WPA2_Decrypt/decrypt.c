#ifndef PCAP_H
#define PCAP_H
#include <pcap.h>
#endif

#ifndef STR_H
#define STR_H
#include <string.h>
#endif

#ifndef STLIB_H
#define STLIB_H
#include <stdlib.h>
#endif

#ifndef EVP_H
#define EVP_H
#include <openssl/evp.h>
#endif

#ifndef SHA_H
#define SHA_H
#include <openssl/sha.h>
#endif

#include <openssl/hmac.h>

#include "decrypt.h"


unsigned char opad[64] = {
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c};

unsigned char ipad[64] = {
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36};

void GetPTK_noPMF(struct WPA_ST_info **st_cur)
{

    // unsigned char PTK[64];

    // unsigned char *input = malloc(sizeof(unsigned char) * (32 + 32 + 32 + 6 + 6));
    // memcpy(input, wpa2_noPMF_info->PSK, 32);
    // memcpy(input + 32, wpa2_noPMF_info->Anonce, 32);
    // memcpy(input + 32 + 32, wpa2_noPMF_info->Snonce, 32);
    // memcpy(input + 32 + 32 + 32, wpa2_noPMF_info->AP_mac, 6);
    // memcpy(input + 32 + 32 + 32 + 6, wpa2_noPMF_info->STA_mac, 6);

    // printf(" PTK : ");
    // for(int i=0;i<32+32+6+6+256;i++){
    //     printf("%x",*(input+i));
    //     if(i==255 || i==255+32 || i==255+64 || i==255+64+6 || i==255+64+12){
    //         puts("");
    //     }
    // }
    


    // memcpy(wpa2_noPMF_info->KEK, PTK, 16);
    // memcpy(wpa2_noPMF_infGetPTK_noPMFfo->MIC_Rx, PTK + 56, 8);
    // free(input);
    


    printf("bssid : ");for(int i=0;i<6;i++){printf("%02x",(*st_cur)->bssid[i]);}puts("");


    if(!calc_ptk((*st_cur),(*st_cur)->ptk)){
        fprintf(stderr,"MIC check failde\n");
        exit(-1);
    }
    printf("PTK : ");
    for(int i=0;i<80;i++){
        printf("%x",(*st_cur)->ptk[i]);
    }
    puts("");


}
void GetPSK_noPMF(const unsigned char *passwd, const unsigned char *ssid, WPA2noPMF_info *wpa2_noPMF_info)
{
    PKCS5_PBKDF2_HMAC_SHA1(passwd, -1, ssid, strlen(ssid), 4096, 32, wpa2_noPMF_info->PSK);
    printf("PSK : ");for(int i=0;i<32;i++){printf("%x",wpa2_noPMF_info->PSK[i]);}puts("");
    // for(int i=0;i<256;i++){printf("%x",wpa2_noPMF_info->PSK[i]);}
}

void GetPMK(WPA2noPMF_info *wpa2_noPMF_info, unsigned char *PMK){
}


void Pad(const unsigned char *key, size_t key_len, unsigned char *out)
{
    memcpy(out,key,key_len);
    memcpy(out+key_len,0,64-key_len);
}

void HMAC_sha1(const unsigned char *key, size_t key_len, const unsigned char *message, unsigned char *out)
{
    unsigned char key_[64];
    if (key_len > 64)
    {
        SHA1(key, 64, key_);
    }
    if (key_len < 64)
    {
        Pad(key, key_len ,key_);
    }
    unsigned char o_key_pad[64]; for(int i=0;i<64;i++){o_key_pad[i]^=opad[i];}
    unsigned char i_key_pad[64]; for(int i=0;i<64;i++){i_key_pad[i]^=ipad[i];}

    unsigned char out1[128];
    unsigned char out2[64];
    memcpy(out1,i_key_pad,64);
    memcpy(out1+64,message,64);
    SHA1(out1,64,out2);
    memcpy(out1,o_key_pad,64);
    memcpy(out1+64,out2,64);
    SHA1(out1,64,out2);
    memcpy(out,out1,64);
}
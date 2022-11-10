#pragma once

#ifndef PCAP_H
#include <pcap.h>
#define PCAP_H
#endif

#ifndef EAPOL
#define EAPOL

#ifndef MAC_LEN
#define MAC_LEN 6
#endif

bool PMF = false;

typedef struct Radiotap_hdr
{
    u_char hdr_rev;          // Header revision
    u_char hdr_pad;          // Header Header pad
    u_short hdr_len;         // Header length
    u_char present_flag[12]; //이 길이 가변이라 보내는 놈의 안테나길이에 따라 가변임
    u_char flags;
} __attribute__((packed)) Radio;

typedef struct QoS_Data
{
    u_char Version : 2;
    u_char Type : 2;
    u_char Subtype : 4;

    // Flags
    u_char Ds_status : 2;
    u_char More_fragments : 1;
    u_char Retry : 1;
    u_char PWR_mgt : 1;
    u_char More_data : 1;
    u_char Protected_flag : 1;
    u_char HTC_Order_flag : 1;

    u_short Duration;

    unsigned char Src_mac[MAC_LEN];
    unsigned char Des_mac[MAC_LEN];
    unsigned char Bssid[MAC_LEN];

    u_char Fragment_number : 4;
    u_short Sequence_number : 12;

    // Qos Control
    u_char TID : 4;
    u_char EOSP : 1;
    u_char Ack_policy : 2;
    u_char Payload_type : 1;
    u_char QAP_ps_buffer_state;

} __attribute__((packed)) QoS;

typedef struct Logical_Link_Control
{
    // DSAP
    u_char IG_bit : 1;
    u_char DSAP_SAP : 7;

    // SSAP
    u_char CR_bit : 1;
    u_char SSAP_SAP : 7;

    // Control field
    u_char Frame_type : 2;
    u_char Command : 6;

    u_char Organization_code[3];
    u_short Type;
} __attribute__((packed)) LLC;

typedef struct Dot1Xi_authentication
{
    u_char Version;
    u_char Type;
    u_short Length;
    u_char Key_desc_type;

    // Key Information (2byte)
    //u_short Key_info;
    u_char Key_mic : 1;
    u_char Secure : 1;
    u_char Error : 1;
    u_char Request : 1;
    u_char Encrypted_keydata : 1;
    u_char SMK_Message : 1;
    u_char NULLpadding : 2;

    u_char Key_desc_version : 3;
    u_char Key_type : 1;
    u_char Key_index : 2;
    u_char Install : 1;
    u_char Key_ack : 1;

    u_short Key_length;
    u_int64_t Replay_counter;
    u_char WPA_key_nonce[32];
    u_char Key_iv[16];
    u_char WPA_key_rsc[8];
    u_char WPA_key_id[8];
    u_char WPA_key_mic[16];
    u_short WPA_key_data;
    
} __attribute__((packed)) Doti_Auth;

typedef struct EAPOLpacket
{
    QoS qos;
    LLC llc;
    Doti_Auth auth;
} __attribute__((packed)) Eapol;

bool IsEAPOL(const u_char *packet);
const u_char *JumpRadio(const u_char *packet);
void PtData(const u_char *packet, u_char caplen);
void CapturePacket(const unsigned char *Interface,const unsigned char *ssid,const unsigned char *passwd);
int NumEAPOL(const u_char *packet);
void GetAnonce(const u_char *packet, struct WPA_ST_info *st_cur);
void GetSnonce(const u_char *packet, struct WPA_ST_info *st_cur);
#endif
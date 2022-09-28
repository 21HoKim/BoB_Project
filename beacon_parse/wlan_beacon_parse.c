#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#define MAC_ADDR_LEN 6

/*
4byte : u_int, u_int32_t, int, int32_t
2byte : u_short, u_int16_t, short, int16_t
1byte : u_char, u_int8, char int8_t
*/
/*
    Radiotap Header
*/
struct radiotap_hdr
{
    u_char hdr_rev;        // Header revision
    u_char hdr_pad;        // Header Header pad
    u_short hdr_len;       // Header length
    u_int present_flag;    // Present Flag
    uint64_t MAC_time;     // MAC timestamp
    u_char flags;          // Flags
    u_char data_rate;      // Data Rate
    u_short channel_freq;  // Channel Frequency
    u_short channel_flgas; // Channel Flags
    u_char ant_signal;     // Antenna signal
    u_char ant_noise;      // Antenna noise
    u_char ant;            // Antenna
};

/*
    802.11 Beacon frame header
*/
struct wlan_Beacon_hdr
{
    u_char type;                    //Type/Subtype
    u_short cnt_field;              //Frame Control Field
    u_char mac_dhost[MAC_ADDR_LEN]; //Destination address
    u_char mac_shost[MAC_ADDR_LEN]; //Source address
    uint8_t mac_bssid[MAC_ADDR_LEN];//BSS Id
    u_char Frag_num : 4;            //Fragment number
    u_int Seq_num : 12;             //Sequence number
};

/*
    802.11 Beacon frame Body
*/
struct wlan_Beacon_body
{
    /*Fixed parameters*/
    uint64_t time;           //Timestamp
    u_short Be_interval;     //Beacon Interval
    u_short Cap_inf;         //Capabilities Information

    /*Tagged parameters*/
    //Tag : SSID parameter set
    u_char tag_num;          //Tag Number
    u_char tag_len;          //Tag length
    u_char ssid[10];         //SSID
    //Tag : Supported Rates
    u_char sup_rat[10];
    //Tag : DS Parameter set
    u_char DS_parset[3];
    //Tag : Traffic Indication Map
    u_char TIM[6];
    //Tag : Channel Switch Announcement Mode
    u_char tag_num_ch;       //Tag Number : Channel Switch Announcdment
    u_char tag_len_ch;       //Tag length
    u_char ch_switch_mode;   //Channel Switch Mode
    u_char New_ch_num;       //New Channel Number
    u_char ch_switch_cnt;    //Channel Switch Count
    //Tag : Country Information
    u_char country_ifm[8];
    //Tag : Extended Supported Rates
    u_char tag_num_esr;      //Tag Number : Extended Supported Rates
    u_char tag_len_esr;      //Tag length
    u_char esr[4];           //Extended Supported Rates
    //Tag : Vendor Specific : Espressif Inc.
    u_char vse[11];
    //Tag : RSN Information
    u_char RSN[26];
    //Tag : Vendor Specific : Microsoft Corp
    u_char vsm[28];
};


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

        printf("Parsing....");

        const struct radiotap_hdr *frame;
        const struct wlan_Beacon_hdr *beacon_hdr;
        const struct wlan_Beacon_body * beacon_body;
        
        frame = (struct radiotap_hdr*)(packet);
        printf("Radiotap Header Length : 0x%x\n", frame->hdr_len);

        // printf("Destination Mac : %s",beacon_hdr->mac_dhost);
        // printf("Source Mac : %s",beacon_hdr->mac_shost);

        // wlan_frame = (struct wlan_auth_frame*)(packet+frame->hdr_len);
        // printf("Frame Control : 0x%x\n", wlan_frame->auth_hdr.frame_control);
        // printf("Duration ID : 0x%x\n", wlan_frame->auth_hdr.duration_ID);
        // printf("Sequence Control : 0x%x\n", wlan_frame->auth_hdr.sequence_control);

        // printf("Auth Algorithm : 0x%x\n", wlan_frame->auth_body.auth_algorithm_num);
        // printf("Auth SEQ : 0x%x\n", wlan_frame->auth_body.auth_seq);
        // printf("Status Code : 0x%x\n", wlan_frame->auth_body.status_code);
	}

	pcap_close(pcap);
}

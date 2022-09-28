#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#define MAC_ADDR_LEN 6

/*
    Radiotap Header
*/
struct radiotap_hdr
{
    u_char hdr_rev;         // Header revision
    u_char hdr_pad;         // Header Header pad
    u_short hdr_len;        // Header length
    u_int present_flag1;    // Present Flag 1
    u_int present_flag2;    // Present Flag 2
    u_int present_flag3;    // Present Flag 3
    u_char flags;           // Flags
    u_char data_rate;       // Data Rate
    u_short channel_freq;    // Channel Frequency
    u_short channel_flgas;   // Channel Flags
    u_short ant_signal;      // Antenna signal
    u_short signal_qual;     // Signal Quality
    u_short rx_flags;        // RX flags
    u_char ant_signal2;      // Antenna Signal 2
    u_char ant1;             // Antenna 1
    u_char ant_signal3;      // Antenna Signal 3
    u_char ant2;             // Antenna 2
};

/*
    802.11 Authentication Header
*/
struct wlan_auth_hdr
{
    u_short frame_control;              // Frame Control
    u_short duration_ID;                // Duration ID
    uint8_t mac_dhost[MAC_ADDR_LEN];    // Destination MAC Addr
    uint8_t mac_shost[MAC_ADDR_LEN];    // Source MAC Addr
    uint8_t bss_id[MAC_ADDR_LEN];       // BSS ID MAC Addr
    u_short sequence_control;           // Sequence Control 
};

/*
    802.11 Authentication Body
*/
struct wlan_auth_body
{
    u_short auth_algorithm_num;         // Authentication Algorithm Number
    u_short auth_seq;                   // Authentication Transaction Sequence
    u_short status_code;                // Status Code
    // Variable Challenge Text
};

/*
    802.11 Authentication Frame
*/
struct wlan_auth_frame
{
    struct wlan_auth_hdr auth_hdr;
    struct wlan_auth_body auth_body;
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
        const struct wlan_auth_frame *wlan_frame;
        
        frame = (struct radiotap_hdr*)(packet);
        printf("Radiotap Header Length : 0x%x\n", frame->hdr_len);

        wlan_frame = (struct wlan_auth_frame*)(packet+frame->hdr_len);
        printf("Frame Control : 0x%x\n", wlan_frame->auth_hdr.frame_control);
        printf("Duration ID : 0x%x\n", wlan_frame->auth_hdr.duration_ID);
        printf("Sequence Control : 0x%x\n", wlan_frame->auth_hdr.sequence_control);

        printf("Auth Algorithm : 0x%x\n", wlan_frame->auth_body.auth_algorithm_num);
        printf("Auth SEQ : 0x%x\n", wlan_frame->auth_body.auth_seq);
        printf("Status Code : 0x%x\n", wlan_frame->auth_body.status_code);
	}

	pcap_close(pcap);
}

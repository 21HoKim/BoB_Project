all: beacon_parse

beacon_parse: wlan_beacon_parse.c
	gcc -o beacon_parse wlan_beacon_parse.c -lpcap

clean:
	rm -f beacon_parse *.o

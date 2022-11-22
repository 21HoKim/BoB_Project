all: decrypt

decrypt: main.c
	gcc -o decrypt decrypt.c main.c crypto.c arcfour-generic.c \
	sha1.c sha1-generic.c mac-hmac-sha1-generic.c mac-hmac-md5-generic.c \
	aes-128-cbc-openssl.c md5-generic.c \
	md5.c channel_hopper.c iwlib.c -lpcap -lcrypto -lssl -lm

decrypt-g: main.c
	gcc -g decrypt.c main.c crypto.c arcfour-generic.c \
	sha1.c sha1-generic.c mac-hmac-sha1-generic.c mac-hmac-md5-generic.c \
	aes-128-cbc-openssl.c md5-generic.c \
	md5.c channel_hopper.c iwlib.c -lpcap -lcrypto -lssl -lm -fPIC

clean:
	rm -f decrypt

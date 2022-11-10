all: decrypt

decrypt: main.c
	gcc -o decrypt decrypt.c main.c mac-hmac-sha1-generic.c -lpcap -lcrypto

clean:
	rm -f decrypt

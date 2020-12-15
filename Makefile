#
CC=	gcc
#
CFLAGS =	-g 
# platform specific cruft
CFLAGS	+= -I../openssl-1.1.1g/include
#LDFLAGS=	-L../openssl-1.1.1g -lcrypto -ldl -lpthread
LDFLAGS=	-L../openssl-1.1.1g -lcrypto 

all: hpke_test hpke_wrap hpke_unwrap hpke_genkey parse_tv

hpke_test:	hpke_test.o hpke.o hkdf.o aes_siv.o
	$(CC) -o hpke_test hpke_test.o hpke.o hkdf.o aes_siv.o $(LDFLAGS)

hpke_wrap:	hpke_wrap.o hpke.o hkdf.o aes_siv.o
	$(CC) -o hpke_wrap hpke_wrap.o hpke.o hkdf.o aes_siv.o $(LDFLAGS)

hpke_unwrap:	hpke_unwrap.o hpke.o hkdf.o aes_siv.o
	$(CC) -o hpke_unwrap hpke_unwrap.o hpke.o hkdf.o aes_siv.o $(LDFLAGS)

hpke_genkey:	hpke_genkey.o hpke.o hkdf.o aes_siv.o
	$(CC) -o hpke_genkey hpke_genkey.o hpke.o hkdf.o aes_siv.o $(LDFLAGS)

parse_tv:	parse_tv.o hpke.o hkdf.o aes_siv.o jsmn.o
	$(CC) -o parse_tv parse_tv.o hpke.o hkdf.o aes_siv.o jsmn.o $(LDFLAGS)

clean:
	rm -f hpke_test hpke_wrap hpke_unwrap hpke_genkey parse_tv *.o




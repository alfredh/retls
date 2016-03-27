# retls
Simple TLS client using libre's TLS api


# Building

Install libre and build it with ``make``


# Usage

```
$ ./retls 
retls -u TLS-server:port
	-h            Show summary of options
	-u            Use DTLS over UDP

```

Example doing a TLS-connection to twitter.com port 443:

```
$ ./retls twitter.com:443
connecting to twitter.com:443 ...
created context with TLSv1.2 ()
resolving host twitter.com ...
resolved host: 104.244.42.1
TLS connection established with cipher TLS_RSA_WITH_AES_128_CBC_SHA in 111 milliseconds
Common name:    twitter.com

```

# lws api test lwsac

Demonstrates how to generate and format new random JWK keys

## build

```
 $ cmake . && make
```

## usage

Commandline option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
-b <bits>|For RSA and OCT, key size in bits
-t <type>|RSA, OCT or EC
-v <curve>|For EC keys, the curve, eg, "P-384"
-c|Format the jwk as a linebroken C string

```
 $ ./lws-crypto-jwk -c -t EC -v P-256
[2018/12/18 20:19:29:6972] USER: LWS JWK example
[2018/12/18 20:19:29:7200] NOTICE: Creating Vhost 'default' (serving disabled), 1 protocols, IPv6 off
[2018/12/18 20:19:29:7251] NOTICE: lws_jwk_generate: generating ECDSA key on curve P-256
"{"
	"\"crv\":\"P-256\","
	"\"kty\":\"EC\","
	"\"x\":\"J8RmI5bf_HMBt8RZd7blsn6zWk28Bl2w_2V6V3-sCBg\","
	"\"d\":\"UqWp4P-GgnR5p18jOCR9HNIVkQt06EjRWqyhV8-MWjs\","
	"\"y\":\"bRuVWouT3VvrzgG3MyDI1TTw3suq7TgIUGklHi626RQ\""
"}"
```


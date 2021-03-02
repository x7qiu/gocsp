#Complie and Run
```
go build
```
```
./gocsp client --host google.com:443
2021/03/02 07:16:17 Starting OCSP certificate check.
2021/03/02 07:16:17 Cert #1: Checking OCSP status.
2021/03/02 07:16:17 Cert #1 Subject: CN=*.google.com,O=Google LLC,L=Mountain View,ST=California,C=US
2021/03/02 07:16:17 Cert #1 Issuer: CN=GTS CA 1O1,O=Google Trust Services,C=US
2021/03/02 07:16:17 Cert #1: OK.
2021/03/02 07:16:17 Cert #2: Checking OCSP status.
2021/03/02 07:16:17 Cert #2 Subject: CN=GTS CA 1O1,O=Google Trust Services,C=US
2021/03/02 07:16:17 Cert #2 Issuer: CN=GlobalSign,OU=GlobalSign Root CA - R2,O=GlobalSign
2021/03/02 07:16:18 Cert #2: OK.
2021/03/02 07:16:18 Cert #3: Checking OCSP status.
2021/03/02 07:16:18 Cert #3 Subject: CN=GlobalSign,OU=GlobalSign Root CA - R2,O=GlobalSign
2021/03/02 07:16:18 Cert #3 Issuer: CN=GlobalSign,OU=GlobalSign Root CA - R2,O=GlobalSign
2021/03/02 07:16:18 Reached a trusted CA. Certificate chain is verified.
```

```
./gocsp client --host google.com:443 -x http://foo:bar@localhost:3130
2021/03/02 07:16:32 Succesfully established connection to proxy
2021/03/02 07:16:32 Starting OCSP certificate check.
2021/03/02 07:16:32 Cert #1: Checking OCSP status.
2021/03/02 07:16:32 Cert #1 Subject: CN=*.google.com,O=Google LLC,L=Mountain View,ST=California,C=US
2021/03/02 07:16:32 Cert #1 Issuer: CN=GTS CA 1O1,O=Google Trust Services,C=US
2021/03/02 07:16:32 Cert #1: OK.
2021/03/02 07:16:32 Cert #2: Checking OCSP status.
2021/03/02 07:16:32 Cert #2 Subject: CN=GTS CA 1O1,O=Google Trust Services,C=US
2021/03/02 07:16:32 Cert #2 Issuer: CN=GlobalSign,OU=GlobalSign Root CA - R2,O=GlobalSign
2021/03/02 07:16:33 Cert #2: OK.
2021/03/02 07:16:33 Cert #3: Checking OCSP status.
2021/03/02 07:16:33 Cert #3 Subject: CN=GlobalSign,OU=GlobalSign Root CA - R2,O=GlobalSign
2021/03/02 07:16:33 Cert #3 Issuer: CN=GlobalSign,OU=GlobalSign Root CA - R2,O=GlobalSign
2021/03/02 07:16:33 Reached a trusted CA. Certificate chain is verified.
```

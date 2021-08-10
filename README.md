#Complie and Run
```
go build
```
```
./gocsp client --server google.com:443
2021/08/09 17:41:38 Starting certificate validation.
2021/08/09 17:41:38 Cert #1: Checking revocation status.
2021/08/09 17:41:38 Cert #1 Subject: CN=*.google.com
2021/08/09 17:41:38 Cert #1 Issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
2021/08/09 17:41:38 Cert #1: OK.
2021/08/09 17:41:38 Cert #2: Checking revocation status.
2021/08/09 17:41:38 Cert #2 Subject: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
2021/08/09 17:41:38 Cert #2 Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
2021/08/09 17:41:38 Cert #2: OK.
2021/08/09 17:41:38 Cert #3: Checking revocation status.
2021/08/09 17:41:38 Cert #3 Subject: CN=GTS Root R1,O=Google Trust Services LLC,C=US
2021/08/09 17:41:38 Cert #3 Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
2021/08/09 17:41:38 Reached a trusted CA. Certificate chain is validated.
```

```
./gocsp client --server google.com:443 --proxy http://foo:bar@localhost:3130
2021/08/09 17:42:08 Succesfully established connection to proxy
2021/08/09 17:42:08 Starting certificate validation.
2021/08/09 17:42:08 Cert #1: Checking revocation status.
2021/08/09 17:42:08 Cert #1 Subject: CN=*.google.com
2021/08/09 17:42:08 Cert #1 Issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
2021/08/09 17:42:08 Cert #1: OK.
2021/08/09 17:42:08 Cert #2: Checking revocation status.
2021/08/09 17:42:08 Cert #2 Subject: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
2021/08/09 17:42:08 Cert #2 Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
2021/08/09 17:42:08 Cert #2: OK.
2021/08/09 17:42:08 Cert #3: Checking revocation status.
2021/08/09 17:42:08 Cert #3 Subject: CN=GTS Root R1,O=Google Trust Services LLC,C=US
2021/08/09 17:42:08 Cert #3 Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
2021/08/09 17:42:08 Reached a trusted CA. Certificate chain is validated.
```

```
./gocsp client --server revoked.badssl.com:443
2021/08/09 17:42:32 Starting certificate validation.
2021/08/09 17:42:32 Cert #1: Checking revocation status.
2021/08/09 17:42:32 Cert #1 Subject: CN=revoked.badssl.com,O=Lucas Garron Torres,L=Walnut Creek,ST=California,C=US
2021/08/09 17:42:32 Cert #1 Issuer: CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US
2021/08/09 17:42:33 Found a match on CRL. This certificate has been revoked.
2021/08/09 17:42:33 Warning: Cert #1 failed to verify revocation status: revoked. Trying the next chain if there is one.
2021/08/09 17:42:33 Certificate Validation Failed.
```
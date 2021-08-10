#Complie and Run
```
go build
```
```
./gocsp client --server google.com:443 
2021/08/09 17:33:22 Starting certificate validation.
2021/08/09 17:33:22 Cert #1: Checking revocation status.
2021/08/09 17:33:22 Cert #1 Subject: CN=*.google.com
2021/08/09 17:33:22 Cert #1 Issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
2021/08/09 17:33:22 Cert #1: OK.
2021/08/09 17:33:22 Cert #2: Checking revocation status.
2021/08/09 17:33:22 Cert #2 Subject: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
2021/08/09 17:33:22 Cert #2 Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
2021/08/09 17:33:22 Cert #2: OK.
2021/08/09 17:33:22 Cert #3: Checking revocation status.
2021/08/09 17:33:22 Cert #3 Subject: CN=GTS Root R1,O=Google Trust Services LLC,C=US
2021/08/09 17:33:22 Cert #3 Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
2021/08/09 17:33:22 Reached a trusted CA. Certificate chain is verified.
```

```
./gocsp client --server google.com:443 --proxy http://foo:bar@localhost:3130
2021/08/09 17:33:30 Succesfully established connection to proxy
2021/08/09 17:33:30 Starting certificate validation.
2021/08/09 17:33:30 Cert #1: Checking revocation status.
2021/08/09 17:33:30 Cert #1 Subject: CN=*.google.com
2021/08/09 17:33:30 Cert #1 Issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
2021/08/09 17:33:30 Cert #1: OK.
2021/08/09 17:33:30 Cert #2: Checking revocation status.
2021/08/09 17:33:30 Cert #2 Subject: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
2021/08/09 17:33:30 Cert #2 Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
2021/08/09 17:33:30 Cert #2: OK.
2021/08/09 17:33:30 Cert #3: Checking revocation status.
2021/08/09 17:33:30 Cert #3 Subject: CN=GTS Root R1,O=Google Trust Services LLC,C=US
2021/08/09 17:33:30 Cert #3 Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
2021/08/09 17:33:30 Reached a trusted CA. Certificate chain is verified.
```

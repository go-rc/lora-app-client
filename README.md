# Lora App Client

Simple client to access through gRPC the [@brocaar's](https://github.com/brocaar) [lora-app-server](https://github.com/brocaar/lora-app-server).


```$ lorainfo -h
Usage of ./lorainfo:
  -b string
        address of the lora-app-server backend (default "your-lora-app-server:443")
  -c string
        TLS certificate file (default "cert.crt")
  -k string
        TLS certificate key (default "cert.key")
  -p string
        login password
  -u string
        login username (default "admin")

Your certificates could be generated with the following commands:

        openssl genrsa -out cert.key 2048
        openssl ecparam -genkey -name secp384r1 -out cert.key
        openssl req -new -x509 -sha256 -key cert.key -out cert.crt -days 3650
```

Example:

```
$ lorainfo -p password -b your.lora-app-server.com:443
User ID:        1
User Name:      admin

Application "Your App"
Nodes: (1)

        DevEUI: 00c20faf465d2752
        Description:    sensor node
        Frame Count:    23631
        === Last Message ===
        Type:           UnconfirmedDataUp
        Content:        2 []uint8 [1001000 1001001] 0x4849 "HI"
```

# PKI
## Config
 - ca-csr.json
```
{
"CN": "ENTERPRISE ENTITE",
"key": {
"algo": "rsa",
"size": 4096
},
"names": [{
"C": "FR",
"L": "PARIS",
"O": "ENTERPRISE"
}],
"ca": {
"expiry": "43830h"
}
}
```

 - profiles.json
```
{
  "signing": {
    "default": {
      "expiry": "26280h"
    },
    "profiles": {
      "server": {
        "usages": [
            "signing",
            "digital signing",
            "key encipherment",
            "server auth"
        ],
        "expiry": "26280h"
      },
      "client": {
          "usages": [
            "signing",
            "digital signature",
            "key encipherment",
            "client auth"
          ],
          "expiry": "26280h"
        }
    }
  }
}

```

 - clt-user.json
```
{
  "CN": "lionel",
  "key": {
    "algo": "rsa",
    "size": 4096
  },
  "names": [
    {
      "C": "FR",
      "L": "Paris",
      "O": "ENTERPRISE",
      "OU": "ENTERPRISE ENTITE"
    }
  ]
}
```

 - srv-service.json
```
{
    "CN": "host.domaine",
    "key": {
      "algo": "rsa",
      "size": 4096
    },
    "names": [
    {
      "C": "FR",
      "L": "Paris",
      "O": "ENTERPRISE",
      "OU": "ENTERPRISE ENTITE"
    }
    ],
    "hosts": [
      "X.X.X.X",
      "host.domaine"
    ]
  }
```

 - serials-revoked.txt
```
#openssl x509 -noout -serial -in /data/CLIENTS/user.pem
# Convert hex to dec => https://www.mathsisfun.com/binary-decimal-hexadecimal-converter.html
```
## Create
```
Copy json file (config)
docker run --rm --entrypoint /bin/bash -v /data/docker-data/cfssl:/data -ti cfssl/cfssl
cfssl gencert -initca /data/config/ca-csr.json | cfssljson -bare ca "/data/CA/"
cfssl gencert -ca "/data/CA/ca.pem" -ca-key "/data/CA/ca-key.pem" -config /data/config/profiles.json -profile=server /data/config/srv-service.json 2>/dev/null | cfssljson --bare "/data/SERVERS/service"
#Generate a client certificate for the bouncer
cfssl gencert -ca "/data/CA/ca.pem" -ca-key "/data/CA/ca-key.pem" -config /data/config/profiles.json -profile=client /data/config/clt-user.json 2>/dev/null | cfssljson --bare "/data/CLIENTS/user"
#generate pkcs12
openssl pkcs12 -export -out change_name.full.pfx -inkey change_name-key.pem -in change_name.pem -certfile /data/CA/ca.pem
# CRL
## GET SERIAL
openssl x509 -noout -serial -in /data/CLIENTS/user.pem
## Convert hex to dec => https://www.mathsisfun.com/binary-decimal-hexadecimal-converter.html
## create serial.txt with dec (one by line) - valable 600 jours
cfssl gencrl /data/config/serials-revoked.txt /data/CA/ca.pem /data/CA/ca-key.pem 51840000 | base64 -d | openssl crl -inform DER -out crl.pem
```

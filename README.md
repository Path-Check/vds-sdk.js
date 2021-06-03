# Verifiable QR SDK for ICAO Visible Digital Seals

JavaScript Implementation of [ICAO Visible Digital Seals](https://www.icao.int/Security/FAL/TRIP/Documents/TR%20-%20Visible%20Digital%20Seals%20for%20Non-Electronic%20Documents%20V1.31.pdf), a JSON-based Verifiable QR Credentials. 

# Install

```sh
npm install @pathcheck/vds-sdk --save
```

# Setting up CSCA, DCS and Key IDs

```sh
./gen-csca-dsc.sh
```

It will generate a dsc-worker.p8 file like this: 

```
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZgp3uylFeCIIXozb
ZkCkSNr4DcLDxplZ1ax/u7ndXqahRANCAARkJeqyO85dyR+UrQ5Ey8EdgLyf9Nts
CrwORAj6T68/elL19aoISQDbzaNYJjdD77XdHtd+nFGTQVpB88wPTwgb
-----END PRIVATE KEY-----
```

and a dsc-worker.pem certificate as: 

```
-----BEGIN CERTIFICATE-----
MIIBYDCCAQYCEQCAG8uscdLb0ppaneNN5sB7MAoGCCqGSM49BAMCMDIxIzAhBgNV
BAMMGk5hdGlvbmFsIENTQ0Egb2YgRnJpZXNsYW5kMQswCQYDVQQGEwJGUjAeFw0y
MTA0MjcyMDQ3MDVaFw0yNjAzMTIyMDQ3MDVaMDYxJzAlBgNVBAMMHkRTQyBudW1i
ZXIgd29ya2VyIG9mIEZyaWVzbGFuZDELMAkGA1UEBhMCRlIwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAARkJeqyO85dyR+UrQ5Ey8EdgLyf9NtsCrwORAj6T68/elL1
9aoISQDbzaNYJjdD77XdHtd+nFGTQVpB88wPTwgbMAoGCCqGSM49BAMCA0gAMEUC
IQDvDacGFQO3tuATpoqf40CBv09nfglL3wh5wBwA1uA7lAIgZ4sOK2iaaTsFNqEN
AF7zi+d862ePRQ9Lwymr7XfwVm0=
-----END CERTIFICATE-----
```


# Usage

With the keys: 

```js
const PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZgp3uylFeCIIXozb
ZkCkSNr4DcLDxplZ1ax/u7ndXqahRANCAARkJeqyO85dyR+UrQ5Ey8EdgLyf9Nts
CrwORAj6T68/elL19aoISQDbzaNYJjdD77XdHtd+nFGTQVpB88wPTwgb
-----END PRIVATE KEY-----`;

const PUB_KEY_ID = `-----BEGIN CERTIFICATE-----
MIIBYDCCAQYCEQCAG8uscdLb0ppaneNN5sB7MAoGCCqGSM49BAMCMDIxIzAhBgNV
BAMMGk5hdGlvbmFsIENTQ0Egb2YgRnJpZXNsYW5kMQswCQYDVQQGEwJGUjAeFw0y
MTA0MjcyMDQ3MDVaFw0yNjAzMTIyMDQ3MDVaMDYxJzAlBgNVBAMMHkRTQyBudW1i
ZXIgd29ya2VyIG9mIEZyaWVzbGFuZDELMAkGA1UEBhMCRlIwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAARkJeqyO85dyR+UrQ5Ey8EdgLyf9NtsCrwORAj6T68/elL1
9aoISQDbzaNYJjdD77XdHtd+nFGTQVpB88wPTwgbMAoGCCqGSM49BAMCA0gAMEUC
IQDvDacGFQO3tuATpoqf40CBv09nfglL3wh5wBwA1uA7lAIgZ4sOK2iaaTsFNqEN
AF7zi+d862ePRQ9Lwymr7XfwVm0=
-----END CERTIFICATE-----`
```

And a Payload 

```js
const TEST_PAYLOAD = {
    "data": {
        "hdr": {
            "t": "icao.vacc",
            "v": 1,
            "is": "UTO"
        },
        "msg": {
            "uvci": "U32870",
            "pid": {
                "n": "Smith Bill",
                "dob": "1990-01-02",
                "sex": "M",
                "i": "A1234567Z",
                "ai": "L4567890Z"
            },
            "ve": [{
                "des": "XM68M6",
                "nam": "Comirnaty",
                "dis": "RA01.0",
                "vd": [{
                    "dvc": "2021-03-03",
                    "seq": 1,
                    "ctr": "UTO",
                    "adm": "RIVM",
                    "lot": "VC35679",
                    "dvn": "2021-03-24"
                }, {
                    "dvc": "2021-03-24",
                    "seq": 2,
                    "ctr": "UTO",
                    "adm": "RIVM",
                    "lot": "VC87540"
                }]
            }]
        }
    }
};
```

Call the signAndPack to create the URI for the QR Code: 

```js
const qrUri = await signAndPack(TEST_PAYLOAD, PUBLIC_KEY_PEM, PRIVATE_KEY_P8);
```

And call the unpack and verify to convert the URI into the payload: 

```js
const payload = await unpackAndVerify(qrUri);
```

# Development

```sh
npm install
``` 

# Test

```sh
npm test
```

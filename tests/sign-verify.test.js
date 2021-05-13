const {sign, verify, pack, unpack, signAndPack, unpackAndVerify} = require('../lib/index');

const PUBLIC_KEY_PEM = '-----BEGIN CERTIFICATE-----\nMIIBYDCCAQYCEQCAG8uscdLb0ppaneNN5sB7MAoGCCqGSM49BAMCMDIxIzAhBgNV\nBAMMGk5hdGlvbmFsIENTQ0Egb2YgRnJpZXNsYW5kMQswCQYDVQQGEwJGUjAeFw0y\nMTA0MjcyMDQ3MDVaFw0yNjAzMTIyMDQ3MDVaMDYxJzAlBgNVBAMMHkRTQyBudW1i\nZXIgd29ya2VyIG9mIEZyaWVzbGFuZDELMAkGA1UEBhMCRlIwWTATBgcqhkjOPQIB\nBggqhkjOPQMBBwNCAARkJeqyO85dyR+UrQ5Ey8EdgLyf9NtsCrwORAj6T68/elL1\n9aoISQDbzaNYJjdD77XdHtd+nFGTQVpB88wPTwgbMAoGCCqGSM49BAMCA0gAMEUC\nIQDvDacGFQO3tuATpoqf40CBv09nfglL3wh5wBwA1uA7lAIgZ4sOK2iaaTsFNqEN\nAF7zi+d862ePRQ9Lwymr7XfwVm0=\n-----END CERTIFICATE-----';
const PRIVATE_KEY_P8 = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZgp3uylFeCIIXozb\nZkCkSNr4DcLDxplZ1ax/u7ndXqahRANCAARkJeqyO85dyR+UrQ5Ey8EdgLyf9Nts\nCrwORAj6T68/elL19aoISQDbzaNYJjdD77XdHtd+nFGTQVpB88wPTwgb\n-----END PRIVATE KEY-----';

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

test('Sign the json', async () => {
  const signed = await sign(TEST_PAYLOAD, PUBLIC_KEY_PEM, PRIVATE_KEY_P8);
  expect(signed).not.toBe(null);
});

test('Verify the json', async () => {
  // Signed by the original EU source.  They encoded the JSON as a String
  const signed = '{"data":{"hdr":{"t":"icao.vacc","v":1,"is":"UTO"},"msg":{"uvci":"U32870","pid":{"n":"Smith Bill","dob":"1990-01-02","sex":"M","i":"A1234567Z","ai":"L4567890Z"},"ve":[{"des":"XM68M6","nam":"Comirnaty","dis":"RA01.0","vd":[{"dvc":"2021-03-03","seq":1,"ctr":"UTO","adm":"RIVM","lot":"VC35679","dvn":"2021-03-24"},{"dvc":"2021-03-24","seq":2,"ctr":"UTO","adm":"RIVM","lot":"VC87540"}]}]}},"sig":{"alg":"ES256","sigvl":"MEUCIQDbdJe3bFL2gK47u4FexuFTtXvXHsuvH1Ngpf-QdmK3YQIgF1chQ52nH7MJDFrmVxMxVB8l5KEkQqfQl8cexONvSDg","cer":"MIIBYDCCAQYCEQCAG8uscdLb0ppaneNN5sB7MAoGCCqGSM49BAMCMDIxIzAhBgNVBAMMGk5hdGlvbmFsIENTQ0Egb2YgRnJpZXNsYW5kMQswCQYDVQQGEwJGUjAeFw0yMTA0MjcyMDQ3MDVaFw0yNjAzMTIyMDQ3MDVaMDYxJzAlBgNVBAMMHkRTQyBudW1iZXIgd29ya2VyIG9mIEZyaWVzbGFuZDELMAkGA1UEBhMCRlIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARkJeqyO85dyR+UrQ5Ey8EdgLyf9NtsCrwORAj6T68/elL19aoISQDbzaNYJjdD77XdHtd+nFGTQVpB88wPTwgbMAoGCCqGSM49BAMCA0gAMEUCIQDvDacGFQO3tuATpoqf40CBv09nfglL3wh5wBwA1uA7lAIgZ4sOK2iaaTsFNqENAF7zi+d862ePRQ9Lwymr7XfwVm0="}}';
  const result = await verify(JSON.parse(signed));
  expect(result).toStrictEqual(TEST_PAYLOAD);
});

test('Pack And Unpack', async () => {
  const binaryData = {arg1: "test"};
  const packed = await pack(binaryData);
  const unpacked = await unpack(packed);
  expect(unpacked.toString()).toStrictEqual(binaryData.toString());
});

test('Sign Pack And Unpack Verify JSON', async () => {
  const signed = await signAndPack(TEST_PAYLOAD, PUBLIC_KEY_PEM, PRIVATE_KEY_P8);
  const resultJSON = await unpackAndVerify(signed);
  expect(resultJSON).toStrictEqual(TEST_PAYLOAD);
});

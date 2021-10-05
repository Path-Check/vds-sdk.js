const { sign, verify, pack, unpack, signAndPack, unpackAndVerify } = require("../lib/index");
const expect = require("chai").expect;

const PUBLIC_KEY_PEM = "-----BEGIN CERTIFICATE-----\nMIIBYDCCAQYCEQCAG8uscdLb0ppaneNN5sB7MAoGCCqGSM49BAMCMDIxIzAhBgNV\nBAMMGk5hdGlvbmFsIENTQ0Egb2YgRnJpZXNsYW5kMQswCQYDVQQGEwJGUjAeFw0y\nMTA0MjcyMDQ3MDVaFw0yNjAzMTIyMDQ3MDVaMDYxJzAlBgNVBAMMHkRTQyBudW1i\nZXIgd29ya2VyIG9mIEZyaWVzbGFuZDELMAkGA1UEBhMCRlIwWTATBgcqhkjOPQIB\nBggqhkjOPQMBBwNCAARkJeqyO85dyR+UrQ5Ey8EdgLyf9NtsCrwORAj6T68/elL1\n9aoISQDbzaNYJjdD77XdHtd+nFGTQVpB88wPTwgbMAoGCCqGSM49BAMCA0gAMEUC\nIQDvDacGFQO3tuATpoqf40CBv09nfglL3wh5wBwA1uA7lAIgZ4sOK2iaaTsFNqEN\nAF7zi+d862ePRQ9Lwymr7XfwVm0=\n-----END CERTIFICATE-----";
const PRIVATE_KEY_P8 = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZgp3uylFeCIIXozb\nZkCkSNr4DcLDxplZ1ax/u7ndXqahRANCAARkJeqyO85dyR+UrQ5Ey8EdgLyf9Nts\nCrwORAj6T68/elL19aoISQDbzaNYJjdD77XdHtd+nFGTQVpB88wPTwgb\n-----END PRIVATE KEY-----";

const TEST_PAYLOAD = {
  data: {
    hdr: {
      t: "icao.vacc",
      v: 1,
      is: "UTO",
    },
    msg: {
      uvci: "U32870",
      pid: {
        n: "Smith Bill",
        dob: "1990-01-02",
        sex: "M",
        i: "A1234567Z",
        ai: "L4567890Z",
      },
      ve: [
        {
          des: "XM68M6",
          nam: "Comirnaty",
          dis: "RA01.0",
          vd: [
            {
              dvc: "2021-03-03",
              seq: 1,
              ctr: "UTO",
              adm: "RIVM",
              lot: "VC35679",
              dvn: "2021-03-24",
            },
            {
              dvc: "2021-03-24",
              seq: 2,
              ctr: "UTO",
              adm: "RIVM",
              lot: "VC87540",
            },
          ],
        },
      ],
    },
  },
};

describe("ICAOs VDS", function () {
  it("should Sign the json", async () => {
    const signed = await sign(TEST_PAYLOAD, PUBLIC_KEY_PEM, PRIVATE_KEY_P8);
    expect(signed).to.not.be.null;
  });

  it("should Verify the json", async () => {
    // Signed by the original EU source.  They encoded the JSON as a String
    const signed = {
      data: {
        hdr: { t: "icao.vacc", v: 1, is: "UTO" },
        msg: {
          uvci: "U32870",
          pid: {
            n: "Smith Bill",
            dob: "1990-01-02",
            sex: "M",
            i: "A1234567Z",
            ai: "L4567890Z",
          },
          ve: [
            {
              des: "XM68M6",
              nam: "Comirnaty",
              dis: "RA01.0",
              vd: [
                {
                  dvc: "2021-03-03",
                  seq: 1,
                  ctr: "UTO",
                  adm: "RIVM",
                  lot: "VC35679",
                  dvn: "2021-03-24",
                },
                {
                  dvc: "2021-03-24",
                  seq: 2,
                  ctr: "UTO",
                  adm: "RIVM",
                  lot: "VC87540",
                },
              ],
            },
          ],
        },
      },
      sig: {
        alg: "ES256",
        cer: "MIIBYDCCAQYCEQCAG8uscdLb0ppaneNN5sB7MAoGCCqGSM49BAMCMDIxIzAhBgNVBAMMGk5hdGlvbmFsIENTQ0Egb2YgRnJpZXNsYW5kMQswCQYDVQQGEwJGUjAeFw0yMTA0MjcyMDQ3MDVaFw0yNjAzMTIyMDQ3MDVaMDYxJzAlBgNVBAMMHkRTQyBudW1iZXIgd29ya2VyIG9mIEZyaWVzbGFuZDELMAkGA1UEBhMCRlIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARkJeqyO85dyR-UrQ5Ey8EdgLyf9NtsCrwORAj6T68_elL19aoISQDbzaNYJjdD77XdHtd-nFGTQVpB88wPTwgbMAoGCCqGSM49BAMCA0gAMEUCIQDvDacGFQO3tuATpoqf40CBv09nfglL3wh5wBwA1uA7lAIgZ4sOK2iaaTsFNqENAF7zi-d862ePRQ9Lwymr7XfwVm0=",
        sigvl: "ECDS51RInKaFMxE2dQKmE93SinhNBkCNLQeZ9qa5dBgq0ktpPIAXKt4HCY8LxcpRrbJzhBUyuiHwnaHCCiV6ew==",
      },
    };
    const result = await verify(signed);
    delete result['sig'];
    expect(result).to.eql(TEST_PAYLOAD);
  });

  it("should Pack And Unpack", async () => {
    const binaryData = { arg1: "test" };
    const packed = await pack(binaryData);
    const unpacked = await unpack(packed);
    expect(unpacked.toString()).to.eql(binaryData.toString());
  });

  it("should Sign Pack And Unpack Verify JSON", async () => {
    const signed = await signAndPack(
      TEST_PAYLOAD,
      PUBLIC_KEY_PEM,
      PRIVATE_KEY_P8
    );
    const resultJSON = await unpackAndVerify(signed);
    delete resultJSON["sig"];
    expect(resultJSON).to.eql(TEST_PAYLOAD);
  });
});

describe("Prod ICAOs VDS", function () {
  it("should Verify the json from AUS", async () => {
    // Signed by the original AUS source.  They encoded the JSON as a String
    const EXPECTED = {
      data: {
        hdr: { is: "AUS", t: "icao.vacc", v: 1 },
        msg: {
          pid: {
            dob: "1961-05-15",
            i: "PA0941262",
            n: "CITIZEN  JANE SUE",
            sex: "F",
          },
          uvci: "VB0009990012",
          ve: [
            {
              des: "XM68M6",
              dis: "RA01.0",
              nam: "AstraZeneca Vaxzevria",
              vd: [
                {
                  adm: "General Practitioner",
                  ctr: "AUS",
                  dvc: "2021-09-15",
                  lot: "300157P",
                  seq: 1,
                },
              ],
            },
          ],
        },
      },
      sig: {
        alg: "ES256",
        cer: "MIIDhDCCAWygAwIBAgICGK0wDQYJKoZIhvcNAQELBQAwZTELMAkGA1UEBhMCQVUxDDAKBgNVBAoMA0dPVjENMAsGA1UECwwEREZBVDEMMAoGA1UECwwDQVBPMSswKQYDVQQDDCJQYXNzcG9ydCBDb3VudHJ5IFNpZ25pbmcgQXV0aG9yaXR5MB4XDTIxMDgzMTE0MDAwMFoXDTMxMDkzMDEzNTk1OVowHDELMAkGA1UEBhMCQVUxDTALBgNVBAMTBERGQVQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARSVpOyHuLjm01TB1iLBr3SrUp2GkQlM-mPqubbW3mjs0DTeRKrfVTSkkZNgOGj_DB_fo3p8qGy8UVgT4DQRVhIo1IwUDAWBgdngQgBAQYCBAswCQIBADEEEwJOVjAVBgNVHSUBAf8ECzAJBgdngQgBAQ4CMB8GA1UdIwQYMBaAFDYXwef1Z5VxLjd1cI5VgzGG6TgOMA0GCSqGSIb3DQEBCwUAA4ICAQCh_Qc5i6-vewGqinR9EdUpsl0P4jqg0pdx7hyOtPgYOwbTOegJyZOjyWZyuLlxGYuvCHqbrnATMedoIoUJzt8GxHA-4v5TUN2yEbRFXev8ur_0Y3uF4WXFr93Zl0LV78PBNZwXKfZEC6oTN_eVgtR37GdnYsWno0SuhR4fJo8JC_blivas8BJt78Hg8VhvWSK3uT0T58eYQjQhbsXV-BxJ2kSspdvkUF6-arLHh6DVS3ATPAGIm6fEvF4AxnLq5OSHOC3zZR0SR9XntYxEwjo_bW8O0Se8qa5mIBpXmvlwh0Ij6sqVwEskvkM30GmQGfZh5VjFujN2AZnwpjOjK0R-JvR3u6jsBJqVMgm75HgezOzayNiaqzhitrgg5KpO3gK_j3C-Doj5iPAm7I_63GyjUi8ZnqVUZ37UxM19uX2SvhTTQ70nL-zHNfHOyBXJgzMi4Zkor2uagHPz-W1XvNVwGEfFAu-nEyIOKBndHwnvSomL54yBv83X2yAQsoYggU18LNXMHUonTJ_ug7FU0LEX3qA1TeARJ4WBFNjysrBXQepVLowcbtvrhLFjocHjmCp3z17xUoKGI6daajCbvedXgeeSWSD5CuMAXpdN3Yml7VdW7PCK4DD0E_raw6d_wKNGSYAh0TBpNLxnunquai-gFIjgf4iRoys5F35KwmvpZw==",
        sigvl:
          "G4-yhmStxY1MML0fLf7LG6OmJXtP6uo5v_fonZ-wiP1N0oSTp9BD8ZqqwHB6uEFukSrsgqBThmOr7aD0_jHY3g==",
      },
    };

    const signed =
      '{"data":{"hdr":{"is":"AUS","t":"icao.vacc","v":1},"msg":{"pid":{"dob":"1961-05-15","i":"PA0941262","n":"CITIZEN  JANE SUE","sex":"F"},"uvci":"VB0009990012","ve":[{"des":"XM68M6","dis":"RA01.0","nam":"AstraZeneca Vaxzevria","vd":[{"adm":"General Practitioner","ctr":"AUS","dvc":"2021-09-15","lot":"300157P","seq":1}]}]}},"sig":{"alg":"ES256","cer":"MIIDhDCCAWygAwIBAgICGK0wDQYJKoZIhvcNAQELBQAwZTELMAkGA1UEBhMCQVUxDDAKBgNVBAoMA0dPVjENMAsGA1UECwwEREZBVDEMMAoGA1UECwwDQVBPMSswKQYDVQQDDCJQYXNzcG9ydCBDb3VudHJ5IFNpZ25pbmcgQXV0aG9yaXR5MB4XDTIxMDgzMTE0MDAwMFoXDTMxMDkzMDEzNTk1OVowHDELMAkGA1UEBhMCQVUxDTALBgNVBAMTBERGQVQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARSVpOyHuLjm01TB1iLBr3SrUp2GkQlM-mPqubbW3mjs0DTeRKrfVTSkkZNgOGj_DB_fo3p8qGy8UVgT4DQRVhIo1IwUDAWBgdngQgBAQYCBAswCQIBADEEEwJOVjAVBgNVHSUBAf8ECzAJBgdngQgBAQ4CMB8GA1UdIwQYMBaAFDYXwef1Z5VxLjd1cI5VgzGG6TgOMA0GCSqGSIb3DQEBCwUAA4ICAQCh_Qc5i6-vewGqinR9EdUpsl0P4jqg0pdx7hyOtPgYOwbTOegJyZOjyWZyuLlxGYuvCHqbrnATMedoIoUJzt8GxHA-4v5TUN2yEbRFXev8ur_0Y3uF4WXFr93Zl0LV78PBNZwXKfZEC6oTN_eVgtR37GdnYsWno0SuhR4fJo8JC_blivas8BJt78Hg8VhvWSK3uT0T58eYQjQhbsXV-BxJ2kSspdvkUF6-arLHh6DVS3ATPAGIm6fEvF4AxnLq5OSHOC3zZR0SR9XntYxEwjo_bW8O0Se8qa5mIBpXmvlwh0Ij6sqVwEskvkM30GmQGfZh5VjFujN2AZnwpjOjK0R-JvR3u6jsBJqVMgm75HgezOzayNiaqzhitrgg5KpO3gK_j3C-Doj5iPAm7I_63GyjUi8ZnqVUZ37UxM19uX2SvhTTQ70nL-zHNfHOyBXJgzMi4Zkor2uagHPz-W1XvNVwGEfFAu-nEyIOKBndHwnvSomL54yBv83X2yAQsoYggU18LNXMHUonTJ_ug7FU0LEX3qA1TeARJ4WBFNjysrBXQepVLowcbtvrhLFjocHjmCp3z17xUoKGI6daajCbvedXgeeSWSD5CuMAXpdN3Yml7VdW7PCK4DD0E_raw6d_wKNGSYAh0TBpNLxnunquai-gFIjgf4iRoys5F35KwmvpZw==","sigvl":"G4-yhmStxY1MML0fLf7LG6OmJXtP6uo5v_fonZ-wiP1N0oSTp9BD8ZqqwHB6uEFukSrsgqBThmOr7aD0_jHY3g=="}}';

    const result = await verify(JSON.parse(signed));
    expect(result).to.eql(EXPECTED);
  });

  it("should Verify the json from Spec Examples", async () => {
    // Signed by the original AUS source.  They encoded the JSON as a String
    const signed =
      '{"data":{"hdr":{"t":"icao.vacc","v":1,"is":"UTO"},"msg":{"uvci":"U32870","pid":{"n":"Smith Bill","dob":"1990-01-02","sex":"M","i":"A1234567Z","ai":"L4567890Z"},"ve":[{"des":"XM68M6","nam":"Comirnaty","dis":"RA01.0","vd":[{"dvc":"2021-03-03","seq":1,"ctr":"UTO","adm":"RIVM","lot":"VC35679","dvn":"2021-03-24"},{"dvc":"2021-03-24","seq":2,"ctr":"UTO","adm":"RIVM","lot":"VC87540"}]}]}},"sig":{"alg":"ES 256","cer":"MIIBeTCCAR2gAwIBAgIBaDAMBggqhkjOPQQDAgUAMB0xCzAJBgNVBAYTAlVUMQ4wDAYDVQQDDAVVVCBDQTAeFw0yMTA0MDcwNDMwMjZaFw0yNjEwMDcwNDMwMjZaMBoxCzAJBgNVBAYTAlVUMQswCQYDVQQDEwIwNjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI5bRQ3-vabXhHAs2IPi-k9rP_TS2J8aq5fTtUG1iOwXdBxx2n6c38TJ2MzBWT5PHCKVlq5JOCyJ1nDlCPd1S2yjTzBNMBIGA1UdJQQLMAkGB2eBCAEBDgIwHwYDVR0jBBgwFoAUymyksnX8rywn0RH7nDq-Bs2QOqowFgYHZ4EIAQEGAgQLMAkCAQAxBBMCTlYwDAYIKoZIzj0EAwIFAANIADBFAiBVaaJVHvWLX756yAGt04C89ZEWGr-BsHDgaRb0EH3d9gIhAO2UNvLNhEoUWT1I_zj_cG5mh2U-lWCMBUQ3zSQqWUcs","sigvl":"cxfyi2vq2XJfZF7ksEkIZJtKbGrRE570UZc_rNAlpfRHD_Xjq57r2h-QLvd_tCQGitsZevFmB0iXzEFdeeZ4zA=="}}';

    const result = await verify(JSON.parse(signed));
    delete result['sig'];
    expect(result).to.eql(TEST_PAYLOAD);
  });
});

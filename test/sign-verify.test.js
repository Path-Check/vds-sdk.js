const { sign, verify, pack, unpack, signAndPack, unpackAndVerify, getKID, addCachedCerts } = require("../lib/index");
const expect = require("chai").expect;

const PUBLIC_KEY_PEM = "-----BEGIN CERTIFICATE-----\nMIIBYDCCAQYCEQCAG8uscdLb0ppaneNN5sB7MAoGCCqGSM49BAMCMDIxIzAhBgNVBAMMGk5hdGlvbmFsIENTQ0Egb2YgRnJpZXNsYW5kMQswCQYDVQQGEwJGUjAeFw0yMTA0MjcyMDQ3MDVaFw0yNjAzMTIyMDQ3MDVaMDYxJzAlBgNVBAMMHkRTQyBudW1iZXIgd29ya2VyIG9mIEZyaWVzbGFuZDELMAkGA1UEBhMCRlIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARkJeqyO85dyR+UrQ5Ey8EdgLyf9NtsCrwORAj6T68/elL19aoISQDbzaNYJjdD77XdHtd+nFGTQVpB88wPTwgbMAoGCCqGSM49BAMCA0gAMEUCIQDvDacGFQO3tuATpoqf40CBv09nfglL3wh5wBwA1uA7lAIgZ4sOK2iaaTsFNqENAF7zi+d862ePRQ9Lwymr7XfwVm0=\n-----END CERTIFICATE-----";
const PRIVATE_KEY_P8 = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZgp3uylFeCIIXozbZkCkSNr4DcLDxplZ1ax/u7ndXqahRANCAARkJeqyO85dyR+UrQ5Ey8EdgLyf9NtsCrwORAj6T68/elL19aoISQDbzaNYJjdD77XdHtd+nFGTQVpB88wPTwgb\n-----END PRIVATE KEY-----";

const UTO_PEM = "-----BEGIN CERTIFICATE-----\nMIIBeTCCAR2gAwIBAgIBaDAMBggqhkjOPQQDAgUAMB0xCzAJBgNVBAYTAlVUMQ4wDAYDVQQDDAVVVCBDQTAeFw0yMTA0MDcwNDMwMjZaFw0yNjEwMDcwNDMwMjZaMBoxCzAJBgNVBAYTAlVUMQswCQYDVQQDEwIwNjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI5bRQ3+vabXhHAs2IPi+k9rP/TS2J8aq5fTtUG1iOwXdBxx2n6c38TJ2MzBWT5PHCKVlq5JOCyJ1nDlCPd1S2yjTzBNMBIGA1UdJQQLMAkGB2eBCAEBDgIwHwYDVR0jBBgwFoAUymyksnX8rywn0RH7nDq+Bs2QOqowFgYHZ4EIAQEGAgQLMAkCAQAxBBMCTlYwDAYIKoZIzj0EAwIFAANIADBFAiBVaaJVHvWLX756yAGt04C89ZEWGr+BsHDgaRb0EH3d9gIhAO2UNvLNhEoUWT1I/zj/cG5mh2U+lWCMBUQ3zSQqWUcs\n-----END CERTIFICATE-----"

addCachedCerts({
  "Rjene8QvRwBx9bytJQq5VY8+Qai4X4x0OpENSrX1sqk=": PUBLIC_KEY_PEM,
  "UT#ymyksnX8rywn0RH7nDq+Bs2QOqo=": UTO_PEM
})

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
    delete result['contents']['sig'];
    expect(result.status).to.be.eq("verified");
    expect(result.contents).to.eql(TEST_PAYLOAD);
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
    const result = await unpackAndVerify(signed);
    expect(result.status).to.be.eq("verified");

    delete result["contents"]["sig"];
    expect(result.contents).to.eql(TEST_PAYLOAD);
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

    const AUS_ISSUER = {
      displayName: { en: 'Gov of Australia' },
      entityType: 'issuer',
      status: 'current',
      validFromDT: '2020-05-04T21:04:32.000Z',
      validUntilDT: '2036-05-04T20:47:02.000Z',
      didDocument: '-----BEGIN CERTIFICATE-----\n' +
        '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\n' +
        '-----END CERTIFICATE-----',
      credentialType: [ 'icao.vacc', 'icao.test' ]
    };

    const signed =
      '{"data":{"hdr":{"is":"AUS","t":"icao.vacc","v":1},"msg":{"pid":{"dob":"1961-05-15","i":"PA0941262","n":"CITIZEN  JANE SUE","sex":"F"},"uvci":"VB0009990012","ve":[{"des":"XM68M6","dis":"RA01.0","nam":"AstraZeneca Vaxzevria","vd":[{"adm":"General Practitioner","ctr":"AUS","dvc":"2021-09-15","lot":"300157P","seq":1}]}]}},"sig":{"alg":"ES256","cer":"MIIDhDCCAWygAwIBAgICGK0wDQYJKoZIhvcNAQELBQAwZTELMAkGA1UEBhMCQVUxDDAKBgNVBAoMA0dPVjENMAsGA1UECwwEREZBVDEMMAoGA1UECwwDQVBPMSswKQYDVQQDDCJQYXNzcG9ydCBDb3VudHJ5IFNpZ25pbmcgQXV0aG9yaXR5MB4XDTIxMDgzMTE0MDAwMFoXDTMxMDkzMDEzNTk1OVowHDELMAkGA1UEBhMCQVUxDTALBgNVBAMTBERGQVQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARSVpOyHuLjm01TB1iLBr3SrUp2GkQlM-mPqubbW3mjs0DTeRKrfVTSkkZNgOGj_DB_fo3p8qGy8UVgT4DQRVhIo1IwUDAWBgdngQgBAQYCBAswCQIBADEEEwJOVjAVBgNVHSUBAf8ECzAJBgdngQgBAQ4CMB8GA1UdIwQYMBaAFDYXwef1Z5VxLjd1cI5VgzGG6TgOMA0GCSqGSIb3DQEBCwUAA4ICAQCh_Qc5i6-vewGqinR9EdUpsl0P4jqg0pdx7hyOtPgYOwbTOegJyZOjyWZyuLlxGYuvCHqbrnATMedoIoUJzt8GxHA-4v5TUN2yEbRFXev8ur_0Y3uF4WXFr93Zl0LV78PBNZwXKfZEC6oTN_eVgtR37GdnYsWno0SuhR4fJo8JC_blivas8BJt78Hg8VhvWSK3uT0T58eYQjQhbsXV-BxJ2kSspdvkUF6-arLHh6DVS3ATPAGIm6fEvF4AxnLq5OSHOC3zZR0SR9XntYxEwjo_bW8O0Se8qa5mIBpXmvlwh0Ij6sqVwEskvkM30GmQGfZh5VjFujN2AZnwpjOjK0R-JvR3u6jsBJqVMgm75HgezOzayNiaqzhitrgg5KpO3gK_j3C-Doj5iPAm7I_63GyjUi8ZnqVUZ37UxM19uX2SvhTTQ70nL-zHNfHOyBXJgzMi4Zkor2uagHPz-W1XvNVwGEfFAu-nEyIOKBndHwnvSomL54yBv83X2yAQsoYggU18LNXMHUonTJ_ug7FU0LEX3qA1TeARJ4WBFNjysrBXQepVLowcbtvrhLFjocHjmCp3z17xUoKGI6daajCbvedXgeeSWSD5CuMAXpdN3Yml7VdW7PCK4DD0E_raw6d_wKNGSYAh0TBpNLxnunquai-gFIjgf4iRoys5F35KwmvpZw==","sigvl":"G4-yhmStxY1MML0fLf7LG6OmJXtP6uo5v_fonZ-wiP1N0oSTp9BD8ZqqwHB6uEFukSrsgqBThmOr7aD0_jHY3g=="}}';

    const result = await verify(JSON.parse(signed));
    expect(result.status).to.be.eq("verified");
    expect(result.contents).to.eql(EXPECTED);
    expect(result.issuer).to.eql(AUS_ISSUER);
  });

  it("should Verify the json from Spec Examples", async () => {
    // Signed by the original AUS source.  They encoded the JSON as a String
    const signed =
      '{"data":{"hdr":{"t":"icao.vacc","v":1,"is":"UTO"},"msg":{"uvci":"U32870","pid":{"n":"Smith Bill","dob":"1990-01-02","sex":"M","i":"A1234567Z","ai":"L4567890Z"},"ve":[{"des":"XM68M6","nam":"Comirnaty","dis":"RA01.0","vd":[{"dvc":"2021-03-03","seq":1,"ctr":"UTO","adm":"RIVM","lot":"VC35679","dvn":"2021-03-24"},{"dvc":"2021-03-24","seq":2,"ctr":"UTO","adm":"RIVM","lot":"VC87540"}]}]}},"sig":{"alg":"ES256","cer":"MIIBeTCCAR2gAwIBAgIBaDAMBggqhkjOPQQDAgUAMB0xCzAJBgNVBAYTAlVUMQ4wDAYDVQQDDAVVVCBDQTAeFw0yMTA0MDcwNDMwMjZaFw0yNjEwMDcwNDMwMjZaMBoxCzAJBgNVBAYTAlVUMQswCQYDVQQDEwIwNjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI5bRQ3-vabXhHAs2IPi-k9rP_TS2J8aq5fTtUG1iOwXdBxx2n6c38TJ2MzBWT5PHCKVlq5JOCyJ1nDlCPd1S2yjTzBNMBIGA1UdJQQLMAkGB2eBCAEBDgIwHwYDVR0jBBgwFoAUymyksnX8rywn0RH7nDq-Bs2QOqowFgYHZ4EIAQEGAgQLMAkCAQAxBBMCTlYwDAYIKoZIzj0EAwIFAANIADBFAiBVaaJVHvWLX756yAGt04C89ZEWGr-BsHDgaRb0EH3d9gIhAO2UNvLNhEoUWT1I_zj_cG5mh2U-lWCMBUQ3zSQqWUcs","sigvl":"cxfyi2vq2XJfZF7ksEkIZJtKbGrRE570UZc_rNAlpfRHD_Xjq57r2h-QLvd_tCQGitsZevFmB0iXzEFdeeZ4zA=="}}';

    const UNTRUSTED_ISSUER = {
      displayName: { en: '' },
      entityType: 'issuer',
      status: 'current',
      validFromDT: "2021-01-01T01:00:00.000Z",
      didDocument: UTO_PEM,
      credentialType: [ 'icao.vacc', 'icao.test' ]
    };

    const result = await verify(JSON.parse(signed));
    expect(result.status).to.be.eq("verified");
    delete result.contents['sig'];
    expect(result.contents).to.eql(TEST_PAYLOAD);
    expect(result.issuer).to.eql(UNTRUSTED_ISSUER);
  });

  it("should hash the public cert correctly", async () => {
    // Signed by the original AUS source.  They encoded the JSON as a String
    const CERT = 'MIIBYDCCAQYCEQCAG8uscdLb0ppaneNN5sB7MAoGCCqGSM49BAMCMDIxIzAhBgNVBAMMGk5hdGlvbmFsIENTQ0Egb2YgRnJpZXNsYW5kMQswCQYDVQQGEwJGUjAeFw0yMTA0MjcyMDQ3MDVaFw0yNjAzMTIyMDQ3MDVaMDYxJzAlBgNVBAMMHkRTQyBudW1iZXIgd29ya2VyIG9mIEZyaWVzbGFuZDELMAkGA1UEBhMCRlIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARkJeqyO85dyR-UrQ5Ey8EdgLyf9NtsCrwORAj6T68_elL19aoISQDbzaNYJjdD77XdHtd-nFGTQVpB88wPTwgbMAoGCCqGSM49BAMCA0gAMEUCIQDvDacGFQO3tuATpoqf40CBv09nfglL3wh5wBwA1uA7lAIgZ4sOK2iaaTsFNqENAF7zi-d862ePRQ9Lwymr7XfwVm0=';
    const hash = getKID(CERT);
    expect(hash).to.eql("Rjene8QvRwBx9bytJQq5VY8+Qai4X4x0OpENSrX1sqk=");
  });

  it("should hash the Australian Key correctly", async () => {
    const AUS_CERT = 'MIIDhDCCAWygAwIBAgICGK0wDQYJKoZIhvcNAQELBQAwZTELMAkGA1UEBhMCQVUxDDAKBgNVBAoMA0dPVjENMAsGA1UECwwEREZBVDEMMAoGA1UECwwDQVBPMSswKQYDVQQDDCJQYXNzcG9ydCBDb3VudHJ5IFNpZ25pbmcgQXV0aG9yaXR5MB4XDTIxMDgzMTE0MDAwMFoXDTMxMDkzMDEzNTk1OVowHDELMAkGA1UEBhMCQVUxDTALBgNVBAMTBERGQVQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARSVpOyHuLjm01TB1iLBr3SrUp2GkQlM-mPqubbW3mjs0DTeRKrfVTSkkZNgOGj_DB_fo3p8qGy8UVgT4DQRVhIo1IwUDAWBgdngQgBAQYCBAswCQIBADEEEwJOVjAVBgNVHSUBAf8ECzAJBgdngQgBAQ4CMB8GA1UdIwQYMBaAFDYXwef1Z5VxLjd1cI5VgzGG6TgOMA0GCSqGSIb3DQEBCwUAA4ICAQCh_Qc5i6-vewGqinR9EdUpsl0P4jqg0pdx7hyOtPgYOwbTOegJyZOjyWZyuLlxGYuvCHqbrnATMedoIoUJzt8GxHA-4v5TUN2yEbRFXev8ur_0Y3uF4WXFr93Zl0LV78PBNZwXKfZEC6oTN_eVgtR37GdnYsWno0SuhR4fJo8JC_blivas8BJt78Hg8VhvWSK3uT0T58eYQjQhbsXV-BxJ2kSspdvkUF6-arLHh6DVS3ATPAGIm6fEvF4AxnLq5OSHOC3zZR0SR9XntYxEwjo_bW8O0Se8qa5mIBpXmvlwh0Ij6sqVwEskvkM30GmQGfZh5VjFujN2AZnwpjOjK0R-JvR3u6jsBJqVMgm75HgezOzayNiaqzhitrgg5KpO3gK_j3C-Doj5iPAm7I_63GyjUi8ZnqVUZ37UxM19uX2SvhTTQ70nL-zHNfHOyBXJgzMi4Zkor2uagHPz-W1XvNVwGEfFAu-nEyIOKBndHwnvSomL54yBv83X2yAQsoYggU18LNXMHUonTJ_ug7FU0LEX3qA1TeARJ4WBFNjysrBXQepVLowcbtvrhLFjocHjmCp3z17xUoKGI6daajCbvedXgeeSWSD5CuMAXpdN3Yml7VdW7PCK4DD0E_raw6d_wKNGSYAh0TBpNLxnunquai-gFIjgf4iRoys5F35KwmvpZw=='
    // Signed by the original AUS source.  They encoded the JSON as a String
    const hash = getKID(AUS_CERT);
    expect(hash).to.eql("AU#NhfB5/VnlXEuN3VwjlWDMYbpOA4=");
  });

  
});

import { Certificate, PrivateKey } from '@fidm/x509';
import { canonicalize } from 'json-canonicalize';
import * as ASN from '@fidm/asn1';

function base64URLtoBase64(thing) {
  return thing.replace(/-/g, '+').replace(/_/g, '/');
}

function base64toBase64URL(thing) {
   return thing.replace(/\+/g, '-').replace(/\//g, '_');
}

const SignatureValidator = {
    name: 'SignatureInfo',
    class: ASN.Class.UNIVERSAL,
    tag: ASN.Tag.SEQUENCE,
    capture: 'signatureInfo',
    value: [{
            name: 'SignatureInfo.r',
            class: ASN.Class.UNIVERSAL,
            tag: ASN.Tag.INTEGER,
            capture: 'r',
        }, {
            name: 'SignatureInfo.s',
            class: ASN.Class.UNIVERSAL,
            tag: ASN.Tag.INTEGER,
            capture: 's',
        }],
};

export async function sign(payload, certificate, privateKeyP8) {
  const privateKey = PrivateKey.fromPEM(privateKeyP8);
  const signatureDER = privateKey.sign(canonicalize(payload.data), 'sha256');
  
  const obj = ASN.ASN1.fromDER(signatureDER, true);
  const captures = {};
  const err = obj.validate(SignatureValidator, captures);

  const signatureRaw = Buffer.concat([captures.r.bytes, captures.s.bytes]);

  const clonePayload = { ...payload };
  clonePayload["sig"] = {};
  clonePayload["sig"]["alg"] = "ES256";
  clonePayload["sig"]["sigvl"] = base64toBase64URL(signatureRaw.toString('base64')); 
  clonePayload["sig"]["cer"] = base64toBase64URL(certificate.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace(/\n/g,''));

  return clonePayload;
}


export async function verify(payload) {
  let cert = "-----BEGIN CERTIFICATE-----\n" + base64URLtoBase64(payload.sig.cer) + "\n-----END CERTIFICATE-----";
  let signatureRaw = Buffer.from(base64URLtoBase64(payload.sig.sigvl), 'base64');

  let r = signatureRaw.slice(0,signatureRaw.length/2);
  let s = signatureRaw.slice(signatureRaw.length/2,signatureRaw.length);

  if (signatureRaw.length % 2 === 1 && r[0] === 0 && s[0] > 0 ) {
    r = signatureRaw.slice(0,signatureRaw.length/2+1);
    s = signatureRaw.slice(signatureRaw.length/2+1,signatureRaw.length);
  }

  const signatureDER = ASN.ASN1.Seq([
    // r
    new ASN.ASN1(ASN.Class.UNIVERSAL, ASN.Tag.INTEGER, r),
    // s
    new ASN.ASN1(ASN.Class.UNIVERSAL, ASN.Tag.INTEGER, s)
  ]).toDER();

  const clonePayload = { ...payload };
  try {
    const CERT = Certificate.fromPEM(cert);
    if (CERT.publicKey.verify(canonicalize(clonePayload.data), signatureDER, 'sha256')) {
      return clonePayload;
    }
  } catch (err) {
    console.error(err);
  }
  return null;
}

export async function pack(payload) {
  return JSON.stringify(payload);
}

export async function unpack(payload) {
  return JSON.parse(payload);
}

export async function unpackAndVerify(uri) {
  try {
    return await verify(await unpack(uri));
  } catch (err) {
    console.error(err);
  }
  return undefined;
}

export async function signAndPack(payload, certificate, privateKeyP8) {
  return await pack(await sign(payload, certificate, privateKeyP8));
}

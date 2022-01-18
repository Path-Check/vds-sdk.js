import webcrypto from 'isomorphic-webcrypto';
import { canonicalize } from 'json-canonicalize';
import { createHash as rawHash } from "sha256-uint8array";

import { getJWTFromPEM, getDERFromPEM, getOIDsFromPrivateKeyPEM, getIssuingCountry, getIssuerID, getCertSignature, getTBSCert } from './key-parser';
import { resolveKey, addCachedCerts } from './resolver';

function base64URLtoBase64(thing) {
  return thing.replace(/-/g, '+').replace(/_/g, '/');
}

function base64toBase64URL(thing) {
   return thing.replace(/\+/g, '-').replace(/\//g, '_');
}

const OIDs = {
  '1.2.840.10045.3.1.7': 'ES256', // The NIST 256 bit curve,
  '1.2.840.10045.4.3.2': 'ES256',
  '1.2.840.10045.4.3.3': 'ES384',
  '1.2.840.10045.4.3.4': 'ES512', 
  '1.3.132.0.34': 'ES256',        // The NIST 384 bit curve
  '1.3.132.0.35': 'ES512'         // The NIST 521 bit curve
};

const CRYPTO = {
  'ES256': { 'name': 'ECDSA', kty: 'EC', 'curve': 'P-256', 'digest': 'SHA-256' },
  'ES384': { 'name': 'ECDSA', kty: 'EC', 'curve': 'P-384', 'digest': 'SHA-384' },
  'ES512': { 'name': 'ECDSA', kty: 'EC', 'curve': 'P-521', 'digest': 'SHA-512' }, 
  'PS256': { 'name': 'RSA-PSS', kty: 'RSA', 'digest': 'SHA-256', saltLength: 32  },
  'PS384': { 'name': 'RSA-PSS', kty: 'RSA', 'digest': 'SHA-384', saltLength: 48  },
  'PS512': { 'name': 'RSA-PSS', kty: 'RSA', 'digest': 'SHA-512', saltLength: 64  }
};

const NOT_SUPPORTED = "not_supported";                  // QR Standard not supported by this algorithm
const INVALID_ENCODING = "invalid_encoding";            // could not decode Base45 for DCC, Base10 for SHC
const INVALID_COMPRESSION = "invalid_compression";      // could not decompress the byte array
const INVALID_SIGNING_FORMAT = "invalid_signing_format";// invalid COSE, JOSE, W3C VC Payload
const KID_NOT_INCLUDED = "kid_not_included";            // unable to resolve the issuer ID
const ISSUER_NOT_TRUSTED = "issuer_not_trusted";        // issuer is not found in the registry
const TERMINATED_KEYS = "terminated_keys";              // issuer was terminated by the registry
const EXPIRED_KEYS = "expired_keys";                    // keys expired
const REVOKED_KEYS = "revoked_keys";                    // keys were revoked by the issuer
const INVALID_SIGNATURE = "invalid_signature";          // signature doesn't match
const VERIFIED = "verified";                            // Verified content.

export async function sign(payload, certificate, privateKeyP8) {
  const toBeSigned = Buffer.from(canonicalize(payload.data));
  const oids = getOIDsFromPrivateKeyPEM(privateKeyP8);

  let alg = "ES256"; //Default 
  for (let i=0; i<oids.length; i++) {
    if (OIDs[oids[i]]) 
      alg = OIDs[oids[i]];
  }

  let algo = {
      name: CRYPTO[alg].name,
      namedCurve: CRYPTO[alg].curve,
      hash: {name: CRYPTO[alg].digest }
  };

  const importedKey = await webcrypto.subtle.importKey('pkcs8', getDERFromPEM(privateKeyP8), algo, false, ['sign']); 
  const signatureDER = Buffer.from(await webcrypto.subtle.sign(algo, importedKey, toBeSigned));

  const clonePayload = { ...payload };
  clonePayload["sig"] = {};
  clonePayload["sig"]["alg"] = alg;
  clonePayload["sig"]["sigvl"] = base64toBase64URL(signatureDER.toString('base64')); 
  clonePayload["sig"]["cer"] = base64toBase64URL(certificate.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace(/\n/g,''));

  return clonePayload;
}

function toPEM(base64urlCert) {
  return "-----BEGIN CERTIFICATE-----\n" + base64URLtoBase64(base64urlCert) + "\n-----END CERTIFICATE-----"
}

export function getKID(base64urlCert) { 
  const certPem = toPEM(base64urlCert)
  
  const country = getIssuingCountry(certPem)
  const kid = getIssuerID(certPem)

  if (country && kid) return country+"#"+kid

  return Buffer.from(rawHash().update(getDERFromPEM(certPem)).digest()).toString('base64');
}

async function doVerify(cert, toBeVerified, signature) {
  let jwk = getJWTFromPEM(cert);

  let algo = {
      name: jwk.name,
      sign: jwk.name,
      namedCurve: jwk.crv,
      saltLength: jwk.saltLength,
      hash: {
        name: jwk.digest
      }
  };
  
  let jwkData = {
    kty: jwk.kty,
    crv: jwk.crv,
    e: jwk.e,
    n: jwk.n,
    x: jwk.x,
    y: jwk.y
  };

  try {
    const importedKey = await webcrypto.subtle.importKey('jwk', jwkData, algo, false, ['verify']);
    return await webcrypto.subtle.verify(algo, importedKey, signature, toBeVerified); 
  } catch (err) {
    console.error(err);
    return;
  }
}

export async function verify(payload) {
  let toBeVerified;
  let signature;
  let cert;

  try {
    toBeVerified = Buffer.from(canonicalize(payload.data));
    signature = Buffer.from(base64URLtoBase64(payload.sig.sigvl), 'base64');
    cert = toPEM(payload.sig.cer);
  } catch (err) {
    console.error(err);
    return { status: INVALID_ENCODING}
  }

  let issuingKey
  try {
    issuingKey = getKID(payload.sig.cer)
  } catch (err) {
    console.error(err);
    return { status: KID_NOT_INCLUDED, contents: payload, raw: payload}
  }

  if (!issuingKey) return { status: KID_NOT_INCLUDED, contents: payload, raw: payload }

  let issuer = await resolveKey(issuingKey);
  if (!issuer) {
    return { status: ISSUER_NOT_TRUSTED, contents: payload, raw: payload };
  }

  switch (issuer.status) {
    case "revoked": return    { status: REVOKED_KEYS, contents: payload, issuer: issuer, raw: payload }
    case "terminated": return { status: TERMINATED_KEYS, contents: payload, issuer: issuer, raw: payload }
    case "expired": return    { status: EXPIRED_KEYS, contents: payload, issuer: issuer, raw: payload }
  }

  // Checking if the Issuer did generate the certificate on the QR
  // If the certificate is the same as in the registry, then it considers it trusted. 
  if (issuer.didDocument.replace(/\n/g, "") !== cert.replace(/\n/g, "")) {
    const certBytes = getTBSCert(cert)
    const certSignature = getCertSignature(cert)
    if (!await doVerify(issuer.didDocument, certBytes, certSignature)) {
      return { status: ISSUER_NOT_TRUSTED, contents: payload, issuer: issuer, raw: payload };
    }
  }

  if (await doVerify(cert, toBeVerified, signature)) {
    return { status: VERIFIED, contents: payload, issuer: issuer, raw: payload }
  } else {
    return { status: INVALID_SIGNATURE, contents: payload, issuer: issuer, raw: payload  }
  }
}

export async function pack(payload) {
  return JSON.stringify(payload);
}

export async function unpack(payload) {
  try {
    return JSON.parse(payload);
  } catch (err) {
    console.error(err);
    return undefined
  }
}

export async function unpackAndVerify(uri) {
  const iJson = await unpack(uri);
  if (!iJson) { 
    return { status: INVALID_ENCODING, qr: uri };
  }

  const verified = await verify(iJson);
  return {...verified, qr: uri};
}

export async function signAndPack(payload, certificate, privateKeyP8) {
  return await pack(await sign(payload, certificate, privateKeyP8));
}

export { addCachedCerts }
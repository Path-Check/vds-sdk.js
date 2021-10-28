import webcrypto from 'isomorphic-webcrypto';
import { canonicalize } from 'json-canonicalize';
import { createHash as rawHash } from "sha256-uint8array";

import { getJWTFromPEM, getDERFromPEM, getOIDsFromPrivateKeyPEM } from './key-parser';

export function getHashFromPEM(cer) {
  const cert = "-----BEGIN CERTIFICATE-----\n" + base64URLtoBase64(cer) + "\n-----END CERTIFICATE-----";
  return Buffer.from(rawHash().update(getDERFromPEM(cert)).digest()).toString('base64');
}

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
};

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

export async function verify(payload) {
  const toBeVerified = Buffer.from(canonicalize(payload.data));
  
  const cert = "-----BEGIN CERTIFICATE-----\n" + base64URLtoBase64(payload.sig.cer) + "\n-----END CERTIFICATE-----";
  const signature = Buffer.from(base64URLtoBase64(payload.sig.sigvl), 'base64');

  let algo = {
      name: CRYPTO[payload.sig.alg].name,
      sign: CRYPTO[payload.sig.alg].name,
      namedCurve: CRYPTO[payload.sig.alg].curve,
      hash: {name: CRYPTO[payload.sig.alg].digest }
  };

  let jwk = getJWTFromPEM(cert);
  
  let jwkData = {
    kty: CRYPTO[payload.sig.alg].kty,
    crv: CRYPTO[payload.sig.alg].curve,
    x: jwk.x,
    y: jwk.y
  };

  try {
    const importedKey = await webcrypto.subtle.importKey('jwk', jwkData, algo, false, ['verify']);
    const verified = await webcrypto.subtle.verify(algo, importedKey, signature, toBeVerified); 

    if (verified) {
      return payload;
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

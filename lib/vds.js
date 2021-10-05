import webcrypto from 'isomorphic-webcrypto';
import * as ASN from '@fidm/asn1';
import { canonicalize } from 'json-canonicalize';

import { getJWTFromPEM, getDERFromPEM } from './key-parser';

function base64URLtoBase64(thing) {
  return thing.replace(/-/g, '+').replace(/_/g, '/');
}

function base64toBase64URL(thing) {
   return thing.replace(/\+/g, '-').replace(/\//g, '_');
}

const CRYPTO = {
  'ES256': { 'name': 'ECDSA', kty: 'EC', 'curve': 'P-256', 'digest': 'SHA-256' },
  'ES384': { 'name': 'ECDSA', kty: 'EC', 'curve': 'P-384', 'digest': 'SHA-384' },
  'ES512': { 'name': 'ECDSA', kty: 'EC', 'curve': 'P-521', 'digest': 'SHA-512' }, 
};

export async function sign(payload, certificate, privateKeyP8) {
  const toBeSigned = Buffer.from(canonicalize(payload.data));

  const alg = "ES256";
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

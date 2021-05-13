'use strict'
const { Certificate, PrivateKey } = require('@fidm/x509');

async function sign(payload, certificate, privateKeyP8) {
  const privateKey = PrivateKey.fromPEM(privateKeyP8);
  const signature = privateKey.sign(JSON.stringify(payload), 'sha256').toString('base64');

  const clonePayload = { ...payload };
  clonePayload["sig"] = {};
  clonePayload["sig"]["alg"] = "ES256";
  clonePayload["sig"]["sigvl"] = signature; 
  clonePayload["sig"]["cer"] = certificate.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace(/\n/g,'');

  return clonePayload;
}

async function verify(payload) {
  let cert = "-----BEGIN CERTIFICATE-----\n" +payload.sig.cer + "\n-----END CERTIFICATE-----";
  let signature = new Buffer(payload.sig.sigvl, 'base64');

  const clonePayload = { ...payload };
  delete clonePayload["sig"];

  try {
    const CERT = Certificate.fromPEM(cert);
    if (CERT.publicKey.verify(JSON.stringify(clonePayload), signature, 'sha256')) {
      return clonePayload;
    }
  } catch (err) {
    console.error(err);
  }
  return null;
}

async function pack(payload) {
  return JSON.stringify(payload);
}

async function unpack(payload) {
  return JSON.parse(payload);
}

async function unpackAndVerify(uri) {
  try {
    return await verify(await unpack(uri));
  } catch (err) {
    console.error(err);
  }
  return undefined;
}

async function signAndPack(payload, publicKeyPem, privateKeyP8) {
  return await pack(await sign(payload, publicKeyPem, privateKeyP8));
}

module.exports = {
  sign, verify, pack, unpack, signAndPack, unpackAndVerify
};

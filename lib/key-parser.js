import * as ASN from '@fidm/asn1';

const RSA_OID     = "1.2.840.113549.1.1";  // has subcategories   
const COUNTRY_OID = "2.5.4.6"
const SUBJECT_KEY_IDENTIFIER_OID = "2.5.29.35"

/**
 * ASN.1 Template for PKCS#8 Public Key.
 */
const PublicKeyValidator = {
    name: 'PublicKeyInfo',
    class: ASN.Class.UNIVERSAL,
    tag: ASN.Tag.SEQUENCE,
    capture: 'publicKeyInfo',
    value: [{
            name: 'PublicKeyInfo.AlgorithmIdentifier',
            class: ASN.Class.UNIVERSAL,
            tag: ASN.Tag.SEQUENCE,
            value: [{
                    name: 'PublicKeyAlgorithmIdentifier.algorithm',
                    class: ASN.Class.UNIVERSAL,
                    tag: ASN.Tag.OID,
                    capture: 'publicKeyOID',
                }],
        }, {
            name: 'PublicKeyInfo.PublicKey',
            class: ASN.Class.UNIVERSAL,
            tag: ASN.Tag.BITSTRING,
            capture: 'publicKey',
        }],
};

// validator for an X.509v3 certificate
const x509CertificateValidator = {
    name: 'Certificate',
    class: ASN.Class.UNIVERSAL,
    tag: ASN.Tag.SEQUENCE,
    value: [{
            name: 'Certificate.TBSCertificate',
            class: ASN.Class.UNIVERSAL,
            tag: ASN.Tag.SEQUENCE,
            capture: 'tbsCertificate',
            value: [{
                    name: 'Certificate.TBSCertificate.version',
                    class: ASN.Class.CONTEXT_SPECIFIC,
                    tag: ASN.Tag.NONE,
                    optional: true,
                    value: [{
                            name: 'Certificate.TBSCertificate.version.integer',
                            class: ASN.Class.UNIVERSAL,
                            tag: ASN.Tag.INTEGER,
                            capture: 'certVersion',
                        }],
                }, {
                    name: 'Certificate.TBSCertificate.serialNumber',
                    class: ASN.Class.UNIVERSAL,
                    tag: ASN.Tag.INTEGER,
                    capture: 'certSerialNumber',
                }, {
                    name: 'Certificate.TBSCertificate.signature',
                    class: ASN.Class.UNIVERSAL,
                    tag: ASN.Tag.SEQUENCE,
                    value: [{
                            name: 'Certificate.TBSCertificate.signature.algorithm',
                            class: ASN.Class.UNIVERSAL,
                            tag: ASN.Tag.OID,
                            capture: 'certinfoSignatureOID',
                        }, {
                            name: 'Certificate.TBSCertificate.signature.parameters',
                            class: ASN.Class.UNIVERSAL,
                            tag: ASN.Tag.OCTETSTRING,
                            optional: true,
                            capture: 'certinfoSignatureParams',
                        }],
                }, {
                    name: 'Certificate.TBSCertificate.issuer',
                    class: ASN.Class.UNIVERSAL,
                    tag: ASN.Tag.SEQUENCE,
                    capture: 'certIssuer'
                }, {
                    name: 'Certificate.TBSCertificate.validity',
                    class: ASN.Class.UNIVERSAL,
                    tag: ASN.Tag.SEQUENCE,
                    value: [{
                            name: 'Certificate.TBSCertificate.validity.notBefore',
                            class: ASN.Class.UNIVERSAL,
                            tag: [ASN.Tag.UTCTIME, ASN.Tag.GENERALIZEDTIME],
                            capture: 'certValidityNotBefore',
                        }, {
                            name: 'Certificate.TBSCertificate.validity.notAfter',
                            class: ASN.Class.UNIVERSAL,
                            tag: [ASN.Tag.UTCTIME, ASN.Tag.GENERALIZEDTIME],
                            capture: 'certValidityNotAfter',
                        }],
                }, {
                    // Name (subject) (RDNSequence)
                    name: 'Certificate.TBSCertificate.subject',
                    class: ASN.Class.UNIVERSAL,
                    tag: ASN.Tag.SEQUENCE,
                    capture: 'certSubject',
                },
                // SubjectPublicKeyInfo
                PublicKeyValidator,
                {
                    // issuerUniqueID (optional)
                    name: 'Certificate.TBSCertificate.issuerUniqueID',
                    class: ASN.Class.CONTEXT_SPECIFIC,
                    tag: ASN.Tag.BOOLEAN,
                    optional: true,
                    value: [{
                            name: 'Certificate.TBSCertificate.issuerUniqueID.id',
                            class: ASN.Class.UNIVERSAL,
                            tag: ASN.Tag.BITSTRING,
                            capture: 'certIssuerUniqueId',
                        }],
                }, {
                    // subjectUniqueID (optional)
                    name: 'Certificate.TBSCertificate.subjectUniqueID',
                    class: ASN.Class.CONTEXT_SPECIFIC,
                    tag: ASN.Tag.INTEGER,
                    optional: true,
                    value: [{
                            name: 'Certificate.TBSCertificate.subjectUniqueID.id',
                            class: ASN.Class.UNIVERSAL,
                            tag: ASN.Tag.BITSTRING,
                            capture: 'certSubjectUniqueId',
                        }],
                }, {
                    // Extensions (optional)
                    name: 'Certificate.TBSCertificate.extensions',
                    class: ASN.Class.CONTEXT_SPECIFIC,
                    tag: ASN.Tag.BITSTRING,
                    capture: 'certExtensions',
                    optional: true,
                }],
        }, {
            // AlgorithmIdentifier (signature algorithm)
            name: 'Certificate.signatureAlgorithm',
            class: ASN.Class.UNIVERSAL,
            tag: ASN.Tag.SEQUENCE,
            value: [{
                    // algorithm
                    name: 'Certificate.signatureAlgorithm.algorithm',
                    class: ASN.Class.UNIVERSAL,
                    tag: ASN.Tag.OID,
                    capture: 'certSignatureOID',
                }, {
                    name: 'Certificate.TBSCertificate.signature.parameters',
                    class: ASN.Class.UNIVERSAL,
                    tag: ASN.Tag.OCTETSTRING,
                    optional: true,
                    capture: 'certSignatureParams',
                }],
        }, {
            name: 'Certificate.signatureValue',
            class: ASN.Class.UNIVERSAL,
            tag: ASN.Tag.BITSTRING,
            capture: 'certSignature',
        }],
};

/**
 * ASN.1 Template for PKCS#8 Private Key. https://tools.ietf.org/html/rfc5208
 */
const PrivateKeyValidator = {
  name: 'PrivateKeyInfo',
  class: ASN.Class.UNIVERSAL,
  tag: ASN.Tag.SEQUENCE,
  capture: 'privateKeyInfo',
  value: [{
    name: 'PrivateKeyInfo.Version',
    class: ASN.Class.UNIVERSAL,
    tag: ASN.Tag.INTEGER,
    capture: 'privateKeyVersion',
  }, {
    name: 'PrivateKeyInfo.AlgorithmIdentifier',
    class: ASN.Class.UNIVERSAL,
    tag: ASN.Tag.SEQUENCE,
    value: [{
      name: 'PrivateKeyAlgorithmIdentifier.algorithm',
      class: ASN.Class.UNIVERSAL,
      tag: ASN.Tag.OID,
      capture: 'privateKeyOID',
    },{
      name: 'PrivateKeyAlgorithmIdentifier.algorithm',
      class: ASN.Class.UNIVERSAL,
      tag: ASN.Tag.OID,
      capture: 'privateKeyOID2',
    }],
  }, {
    name: 'PrivateKeyInfo.PrivateKey',
    class: ASN.Class.UNIVERSAL,
    tag: ASN.Tag.OCTETSTRING,
    capture: 'privateKey',
  }],
}

const SubjectKeyIdentifierValidator = {
  name: 'SubjectKeyIdentifier',
  class: ASN.Class.UNIVERSAL,
  tag: ASN.Tag.SEQUENCE,
  value: [{
      name: 'SubjectKeyIdentifier.value',
      class: ASN.Class.CONTEXT_SPECIFIC,
      tag: ASN.Tag.NONE,
      capture: 'subjectKeyIdentifier',
  }]
}

export function getDERFromPEM(pem) {
  return ASN.PEM.parse(pem)[0].body;
}

function toBase64URL(buffer) {
  return buffer.toString('base64').replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_")
}

export function getOIDsFromPrivateKeyPEM(pem) {
  const obj = ASN.ASN1.fromDER(getDERFromPEM(pem), true);

  const privKeyCaptures = {};
  obj.validate(PrivateKeyValidator, privKeyCaptures);
  const oids = [
      ASN.ASN1.parseOID(privKeyCaptures.privateKeyOID.bytes), 
      ASN.ASN1.parseOID(privKeyCaptures.privateKeyOID2.bytes)
  ];

  return oids;
}

function getSubjectKeyIdentifier(exts) {
  if (!exts) return undefined
  for (const val of exts.mustCompound()) {
    for (const ext of val.mustCompound()) {
      const e = {}
      e.oid = ASN.ASN1.parseOID(ext.value[0].bytes)
      e.value = ext.value[ext.value.length-1].bytes
      if (e.oid == SUBJECT_KEY_IDENTIFIER_OID) {
        const captures = ASN.ASN1.parseDERWithTemplate(e.value, SubjectKeyIdentifierValidator)
        return captures.subjectKeyIdentifier.bytes.toString('base64')
      }
    }
  }
  return undefined
}

function RDNAttributesAsArray(rdn) {
  const rval = []

  // each value in 'rdn' in is a SET of RelativeDistinguishedName
  // var set, attr, obj
  for (const set of rdn.mustCompound()) {
    // each value in the SET is an AttributeTypeAndValue sequence
    // containing first a type (an OID) and second a value (defined by the OID)
    for (const attr of set.mustCompound()) {
      const values = attr.mustCompound()
      const obj = {}
      obj.oid = ASN.ASN1.parseOID(values[0].bytes)
      obj.value = values[1].value
      obj.valueTag = values[1].tag

      rval.push(obj)
    }
  }

  return rval
}

export function getIssuingCountry(certPem) {
  const obj = ASN.ASN1.fromDER(getDERFromPEM(certPem), true);
  const certCaptures = {};
  obj.validate(x509CertificateValidator, certCaptures);

  return RDNAttributesAsArray(certCaptures.certIssuer).find(ext => ext.oid === COUNTRY_OID).value;
}

export function getTBSCert(certPem) {
  const obj = ASN.ASN1.fromDER(getDERFromPEM(certPem), true);
  const certCaptures = {};
  obj.validate(x509CertificateValidator, certCaptures);
  return Buffer.from(certCaptures.tbsCertificate.DER)
}

export function getCertSignature(certPem) {
  const obj = ASN.ASN1.fromDER(getDERFromPEM(certPem), true);
  const certCaptures = {};
  obj.validate(x509CertificateValidator, certCaptures);
  return ASN.ASN1.parseBitString(certCaptures.certSignature.bytes).buf
}

export function getIssuerID(certPem) {
  const obj = ASN.ASN1.fromDER(getDERFromPEM(certPem), true);
  const certCaptures = {};
  obj.validate(x509CertificateValidator, certCaptures);

  return getSubjectKeyIdentifier(certCaptures.certExtensions)
}

export function getJWTFromPEM(pem) {
  const obj = ASN.ASN1.fromDER(getDERFromPEM(pem), true);

  let publicKey = { oid: undefined, keyRaw: undefined};
  if (pem.includes("CERTIFICATE")) {
    const certCaptures = {};
    obj.validate(x509CertificateValidator, certCaptures);

    const publicKeyCaptures = {};
    certCaptures.publicKeyInfo.validate(PublicKeyValidator, publicKeyCaptures);

    publicKey.oid = ASN.ASN1.parseOID(publicKeyCaptures.publicKeyOID.bytes)
    publicKey.keyRaw = ASN.ASN1.parseBitString(publicKeyCaptures.publicKey.bytes).buf;
  } else {
    const captures = {};
    obj.validate(PublicKeyValidator, captures);
    
    publicKey.oid = ASN.ASN1.parseOID(captures.publicKeyOID.bytes)
    publicKey.keyRaw = ASN.ASN1.parseBitString(captures.publicKey.bytes).buf;
  }

  // if RSA
  // Find better ways to parse key parameters. 

  if (publicKey.oid.includes(RSA_OID)) {
    let pk = publicKey.keyRaw
    const keyMod = toBase64URL(pk.slice(9, pk.length - 5));
    const keyExp = toBase64URL(pk.slice(pk.length - 3,pk.length));
    return {
      alg: OIDs[publicKey.oid], 
      name: CRYPTO[OIDs[publicKey.oid]].name, 
      kty: CRYPTO[OIDs[publicKey.oid]].kty, 
      digest: CRYPTO[OIDs[publicKey.oid]].digest,
      saltLength: CRYPTO[OIDs[publicKey.oid]].saltLength,
      n: keyMod, 
      e: keyExp
    };
  } else {
    let pk = publicKey.keyRaw
    const keyX = toBase64URL(pk.slice(1, 1+32));
    const keyY = toBase64URL(pk.slice(33,33+32));
    return {
      alg: OIDs[publicKey.oid], 
      name: CRYPTO[OIDs[publicKey.oid]].name, 
      kty: CRYPTO[OIDs[publicKey.oid]].kty, 
      digest: CRYPTO[OIDs[publicKey.oid]].digest,
      crv: CRYPTO[OIDs[publicKey.oid]].curve,
      x: keyX, 
      y: keyY
    };
  }
}

const OIDs = {
  '1.2.840.113549.2.7': 'HS1',
  '1.2.840.113549.2.9': 'HS256',
  '1.2.840.113549.2.10': 'HS384',
  '1.2.840.113549.2.11': 'HS512',
  
  '1.2.840.10045.2.1': 'ES256',    // The NIST 256 bit curve,
  '1.2.840.10045.3.1.7': 'ES256',  // The NIST 256 bit curve,
  '1.3.132.0.34': 'ES256',         // The NIST 384 bit curve
  '1.3.132.0.35': 'ES512',         // The NIST 521 bit curve

  '1.2.840.10045.4.1': 'ES1',      //ecdsaWithSha1
  '1.2.840.10045.4.3.1': 'ES224',  //ecdsaWithSha224
  '1.2.840.10045.4.3.2': 'ES256',  //ecdsaWithSha256
  '1.2.840.10045.4.3.3': 'ES384',  //ecdsaWithSha384
  '1.2.840.10045.4.3.4': 'ES512',  //ecdsaWithSha512
  
  '1.2.840.113549.1.1.1': 'RS256', // RSA Encryption, 'sha256?'
  
  '1.2.840.113549.1.1.10': 'PS256', // 'RSASSA-PSS', 'sha256'

  '1.2.840.113549.1.1.5': 'RS1', // 'sha1WithRsaEncryption', 'sha1'
  '1.2.840.113549.1.1.14': 'RS224', // 'sha224WithRsaEncryption', 'sha224'
  '1.2.840.113549.1.1.11': 'RS256', // 'sha256WithRsaEncryption', 'sha256'
  '1.2.840.113549.1.1.12': 'RS384', // 'sha384WithRsaEncryption', 'sha384'
  '1.2.840.113549.1.1.13': 'RS512', // 'sha512WithRsaEncryption', 'sha512'

  '1.2.840.10040.4.1': 'ED256',       // DSA
  '1.2.840.10040.4.3': 'ED1',        //dsaWithSha1
  '2.16.840.1.101.3.4.3.1': 'ED224', //dsaWithSha224
  '2.16.840.1.101.3.4.3.2': 'ED225'  //dsaWithSha256
};

const CRYPTO = {
  'HS1': { name: 'HMAC', kty: 'HMAC', digest: 'SHA-1' },
  'HS256': { name: 'HMAC', kty: 'HMAC', digest: 'SHA-256' },
  'HS384': { name: 'HMAC', kty: 'HMAC', digest: 'SHA-384' },
  'HS512': { name: 'HMAC', kty: 'HMAC', digest: 'SHA-512' },

  'ES1': { name: 'ECDSA', kty: 'EC', curve: 'P-224', digest: 'SHA-1' },
  'ES224': { name: 'ECDSA', kty: 'EC', curve: 'P-224', digest: 'SHA-224' },
  'ES256': { name: 'ECDSA', kty: 'EC', curve: 'P-256', digest: 'SHA-256' },
  'ES384': { name: 'ECDSA', kty: 'EC', curve: 'P-384', digest: 'SHA-384' },
  'ES512': { name: 'ECDSA', kty: 'EC', curve: 'P-521', digest: 'SHA-512' }, 
  
  'PS1': { name: 'RSA-PSS', kty: 'RSA', digest: 'SHA-1', saltLength: 32  },
  'PS224': { name: 'RSA-PSS', kty: 'RSA', digest: 'SHA-224', saltLength: 32  },
  'PS256': { name: 'RSA-PSS', kty: 'RSA', digest: 'SHA-256', saltLength: 32  },
  'PS384': { name: 'RSA-PSS', kty: 'RSA', digest: 'SHA-384', saltLength: 48  },
  'PS512': { name: 'RSA-PSS', kty: 'RSA', digest: 'SHA-512', saltLength: 64  },

  'RS1': { name: 'RSASSA-PKCS1-v1_5', kty: 'RSA', digest: 'SHA-1', saltLength: 32  },
  'RS224': { name: 'RSASSA-PKCS1-v1_5', kty: 'RSA', digest: 'SHA-224', saltLength: 32  },
  'RS256': { name: 'RSASSA-PKCS1-v1_5', kty: 'RSA', digest: 'SHA-256', saltLength: 32  },
  'RS384': { name: 'RSASSA-PKCS1-v1_5', kty: 'RSA', digest: 'SHA-384', saltLength: 48  },
  'RS512': { name: 'RSASSA-PKCS1-v1_5', kty: 'RSA', digest: 'SHA-512', saltLength: 64  },
};

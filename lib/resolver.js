import fetch from 'cross-fetch'

let TRUST_REGISTRY = {}

let LAST_FETCH = undefined;
const ONE_DAY_IN_MSECONDS = 86400000;

/** add kid, public cert PEM pairs  */
export function addCachedCerts(array) {
  for (let [key, value] of Object.entries(array)) {
    if (!value.includes("CERTIFICATE") && !value.includes("PUBLIC KEY")) {
      value = '-----BEGIN CERTIFICATE-----\n' + value + '\n-----END CERTIFICATE-----';
    }
    TRUST_REGISTRY[key] = {
      "displayName": {  "en": "" },
      "entityType": "issuer",
      "status": "current",
      "credentialType": ["icao.vacc","icao.test"],
      "validFromDT":  "2021-01-01T01:00:00.000Z",
      "didDocument": value
    }
  }
}

/** add kid, public key PEM pairs  */
export function addCachedKeys(array) {
  for (let [key, value] of Object.entries(array)) {
    if (!value.includes("CERTIFICATE") && !value.includes("PUBLIC KEY")) {
      value = '-----BEGIN PUBLIC KEY-----\n' + value + '\n-----END PUBLIC KEY-----';
    }
    TRUST_REGISTRY[key] = {
      "displayName": {  "en": "" },
      "entityType": "issuer",
      "status": "current",
      "credentialType": ["icao.vacc","icao.test"],
      "validFromDT":  "2021-01-01T01:00:00.000Z",
      "didDocument": value
    }
  }
}

export async function resolveKey(kID) {
  if (!TRUST_REGISTRY[kID] && (!LAST_FETCH || new Date().getTime() > LAST_FETCH.getTime() + ONE_DAY_IN_MSECONDS )) {
    // Loading PathCheck Registry
    console.log('KeyID not found: ', kID, ' fetching certificates from PathCheck\'s Trust Registry')

    try {
      const res = await fetch('https://raw.githubusercontent.com/Path-Check/trust-registry/main/registry.json', {method: 'GET', mode: 'no-cors'})
      const data = await res.text()
      TRUST_REGISTRY = Object.assign({}, TRUST_REGISTRY, JSON.parse(data)["ICAO"]);
    } catch (e) {
      console.log(e);
    }

    LAST_FETCH = new Date();
  }

  if (TRUST_REGISTRY[kID] && TRUST_REGISTRY[kID].status == "current") {
    return TRUST_REGISTRY[kID];
  }

  return undefined
}

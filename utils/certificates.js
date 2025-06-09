// CREDIT: https://blog.jverkamp.com/2025/05/29/parsing-pem-certificates-asn.1-in-javascript/
const crypto = require('crypto');

// https://www.cs.auckland.ac.nz/~pgut001/dumpasn1.cfg
const KNOWN_OID_VALUES = {
  "1 2 840 10045 2 1": "ecPublicKey",
  "1 2 840 10045 3 1 7": "c2tnb191v3",
  "1 2 840 113549 1 1 1": "rsaEncryption",
  "1 2 840 113549 1 1 11": "sha256WithRSAEncryption",
  "1 2 840 113549 1 1 5": "sha1WithRSAEncryption",
  "1 3 6 1 4 1 11129 2 4 2": "googleSignedCertificateTimestamp",
  "1 3 6 1 5 5 7 1 1": "authorityInfoAccess",
  "2 5 29 14": "subjectKeyIdentifier",
  "2 5 29 15": "keyUsage",
  "2 5 29 17": "subjectAltName",
  "2 5 29 19": "basicConstraints",
  "2 5 29 31": "cRLDistributionPoints",
  "2 5 29 32": "certificatePolicies",
  "2 5 29 35": "authorityKeyIdentifier",
  "2 5 29 37": "extKeyUsage",
  "2 5 4 10": "organizationName",
  "2 5 4 11": "organizationalUnitName",
  "2 5 4 3": "commonName",
  "2 5 4 6": "countryName",
  "2 5 4 7": "localityName",
  "2 5 4 8": "stateOrProvinceName",
  "1 2 840 10045 4 3 2": "ecdsaWithSHA256",
};

function parsePEM(pem) {
  const pemRegex = /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/;
  const match = pem.match(pemRegex);
  if (!match) return null;
  
  const base64 = match[1].replace(/\s+/g, "");
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}

function readASN1(data, offset = 0) {
  const start = offset;
  const tag = data[offset++];
  const lengthByte = data[offset++];
  let length;

  if (lengthByte & 0x80) {
    const numBytes = lengthByte & 0x7f;
    length = 0;
    for (let i = 0; i < numBytes; i++) {
      length = (length << 8) | data[offset++];
    }
  } else {
    length = lengthByte;
  }

  const value = data.slice(offset, offset + length);
  const isConstructed = (tag & 0x20) !== 0;
  let children = [];
  
  if (isConstructed) {
    let childOffset = 0;
    while (childOffset < value.length) {
      const child = readASN1(value, childOffset);
      children.push(child);
      childOffset += child.totalLength;
    }
  }

  return {
    tag,
    isConstructed,
    length,
    totalLength: offset + length - start,
    value,
    children,
  };
}

function decodeOID(bytes) {
  const values = [];
  let value = 0;
  let first = true;

  for (let byte of bytes) {
    if (first) {
      values.push(Math.floor(byte / 40));
      values.push(byte % 40);
      first = false;
      continue;
    }
    value = (value << 7) | (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      values.push(value);
      value = 0;
    }
  }

  return values.join(" ");
}

function findSignatureAlgorithm(node) {
  // The signature algorithm is typically inside a SEQUENCE (tag 0x10)
  if ((node.tag & 0x1f) === 0x10 && node.children.length >= 1) { // SEQUENCE
    for (const child of node.children) {
      if ((child.tag & 0x1f) === 0x06) { // OBJECT IDENTIFIER (OID)
        const oid = decodeOID(child.value);
        return KNOWN_OID_VALUES[oid] || oid;
      }
    }
  }

  for (const child of node.children) {
    const result = findSignatureAlgorithm(child);
    if (result) return result;
  }

  return null;
}

function extractHashFromAlgorithm(algorithmName) {
  if (!algorithmName) return null;

  const hashPattern = /(?:sha|SHA)(\d+)/i.exec(algorithmName);
  if (!hashPattern) return "Unknown";

  const hashBits = hashPattern[1];
  switch (hashBits) {
    case "1": return "SHA-1";
    case "256": return "SHA-256";
    case "384": return "SHA-384";
    case "512": return "SHA-512";
    default: return `SHA-${hashBits}`;
  }
}

function getPEMCertificate(rawCert) {
  const x509 = new crypto.X509Certificate(rawCert);
  const pem = x509.toString();
  return parsePEM(pem);
}

function getSignatureAlgorithm(der) {
  if (!der) return null;
  
  const root = readASN1(der);
  return findSignatureAlgorithm(root);
}

function getSignatureHashAlgorithm(pem) {
  const algorithmName = getSignatureAlgorithm(pem);
  return extractHashFromAlgorithm(algorithmName);
}

module.exports = { 
  getPEMCertificate, 
  getSignatureAlgorithm, 
  getSignatureHashAlgorithm
};

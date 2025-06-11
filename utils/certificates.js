// CREDIT: https://blog.jverkamp.com/2025/05/29/parsing-pem-certificates-asn.1-in-javascript/
const crypto = require('crypto');

// TODO: Takes a while, consider caching
async function fetchOidValues() {
  let fetchedOidValues = {};

  try {
    const response = await fetch('https://www.cs.auckland.ac.nz/~pgut001/dumpasn1.cfg');
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data = await response.text();
    const oidMap = {};
    const sections = data.split('\n\n');
    
    for (const section of sections) {
      const lines = section.split('\n');
      let oid, description;
      
      for (const line of lines) {
        if (line.startsWith('OID = ')) {
          oid = line.replace('OID = ', '').trim();
        } else if (line.startsWith('Description = ')) {
          description = line.replace('Description = ', '').trim();
        }
      }
      
      if (oid && description) {
        const formattedOid = oid.includes('.') ? oid.replace(/\./g, ' ') : oid;
        oidMap[formattedOid] = description;
      }
    }

    fetchedOidValues = oidMap;
  } catch (err) {
    console.error("Failed to fetch OID values:", err);
  }

  return fetchedOidValues;
}

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

function findSignatureAlgorithm(node, knownOIDValues) {
  // The signature algorithm is typically inside a SEQUENCE (tag 0x10)
  if ((node.tag & 0x1f) === 0x10 && node.children.length >= 1) { // SEQUENCE
    for (const child of node.children) {
      if ((child.tag & 0x1f) === 0x06) { // OBJECT IDENTIFIER (OID)
        const oid = decodeOID(child.value);
        return knownOIDValues[oid] || oid;
      }
    }
  }

  for (const child of node.children) {
    const result = findSignatureAlgorithm(child, knownOIDValues);
    if (result) return result;
  }

  return null;
}

function getPEMCertificate(rawCert) {
  const x509 = new crypto.X509Certificate(rawCert);
  const pem = x509.toString();
  return parsePEM(pem);
}

function getSignatureAlgorithm(rawCert, knownOIDValues) {
  const der = getPEMCertificate(rawCert);
  if (!der) return null;
  
  const root = readASN1(der);
  return findSignatureAlgorithm(root, knownOIDValues);
}

function getSignatureHashAlgorithm(algorithmName) {
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

module.exports = {
  fetchOidValues,
  getSignatureAlgorithm, 
  getSignatureHashAlgorithm
};

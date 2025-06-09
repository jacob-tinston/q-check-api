const dns = require('dns').promises;
const { connectTLS, findMinTLSVersion } = require('./tls');
const { 
  getPEMCertificate,
  getSignatureAlgorithm, 
  getSignatureHashAlgorithm 
} = require('./certificates');

const probeDomain = async (domain) => {
  const result = {
    domain,
    tls: { minVersion: null, negotiatedVersion: null },
    cipher: null,
    certificateChain: [],
  };

  // Resolve to IP first to avoid SNI issues
  const { address } = await dns.lookup(domain);

  const socketParams = {
    host: address,
    servername: domain,
    port: 443,
    rejectUnauthorized: false, // Still want to probe sites with expired/self-signed certs
    enableTrace: false, // Avoids noisy logs
  };

  result.tls.minVersion = await findMinTLSVersion(socketParams);

  const socket = await connectTLS(socketParams);

  result.tls.negotiatedVersion = socket.getProtocol();
  result.cipher = socket.getCipher();

  const peerCert = socket.getPeerCertificate(true);
  if (peerCert) {
    let cert = peerCert;
    while (cert) {
      const pem = getPEMCertificate(cert.raw);

      result.certificateChain.push({
        subject: cert.subject,
        issuer: cert.issuer,
        signatureAlgorithm: getSignatureAlgorithm(pem),
        signatureHashAlgorithm: getSignatureHashAlgorithm(pem),
        publicKeyLength: cert.bits,
      });

      cert = cert.issuerCertificate && cert.issuerCertificate !== cert
        ? cert.issuerCertificate
        : null;
    }
  }

  socket.destroy();
  return result;
}

module.exports = { probeDomain };

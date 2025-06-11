const dns = require('dns').promises;
const { connectTLS, findMinTLSVersion } = require('./tls');
const { 
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
      const signatureAlgorithm = await getSignatureAlgorithm(cert.raw);
      const signatureHashAlgorithm = getSignatureHashAlgorithm(signatureAlgorithm);

      result.certificateChain.push({
        subject: cert.subject,
        issuer: cert.issuer,
        signatureAlgorithm: signatureAlgorithm,
        signatureHashAlgorithm: signatureHashAlgorithm,
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

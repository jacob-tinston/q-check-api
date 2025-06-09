const tls = require('tls');
const dns = require('dns').promises;

const TLS_VERSIONS = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];

const connectTLS = async (params) => {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(params, () => {
      resolve(socket);
    });

    socket.on('error', (err) => {
      socket.destroy();
      reject(err);
    });
  });
}

const findMinTLSVersion = async (params) => {
  for (const version of TLS_VERSIONS) {
    try {
      const socket = await connectTLS({
        ...params,
        minVersion: version,
        maxVersion: version,
      });

      socket.destroy();
      return version;
    } catch (err) {
      console.warn(`TLS version ${version} not supported for ${params.servername}`);
    }
  }
}

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
      result.certificateChain.push({
        subject: cert.subject,
        issuer: cert.issuer,
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

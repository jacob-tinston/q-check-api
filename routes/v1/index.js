const express = require('express');
const tls = require('tls');
const dns = require('dns');
const router = express.Router();

function probeDomain(domain) {
  return new Promise((resolve, reject) => {
    const result = {
      domain,
      tls: { min: null, max: null, negotiated: null },
      cipher: null,
      certificateChain: [],
    };

    // Resolve to IP first to avoid SNI issues
    dns.lookup(domain, (err, address) => {
      if (err) return reject(err);

      // TODO: Change to probe min supported version
      const socket = tls.connect({
        host: address,
        servername: domain,
        port: 443,
        rejectUnauthorized: false, // Still want to probe sites with expired/self-signed certs
        enableTrace: false, // Avoids noisy logs
      }, () => {
        result.tls.negotiated = socket.getProtocol();
        result.cipher = socket.getCipher();

        // Get the full cert chain - exposes ANY weak hashing, not just the leaf
        const peerCert = socket.getPeerCertificate(true);
        if (peerCert) {
          let cert = peerCert;
          while (cert) {
            result.certificateChain.push({
              subject: cert.subject,
              issuer: cert.issuer
            });
            cert = cert.issuerCertificate && cert.issuerCertificate !== cert ? cert.issuerCertificate : null;
          }
        }

        socket.end();
        resolve(result);
      });

      socket.on('error', err => {
        reject(err);
      });
    });
  });
}

router.get('/scan', async (req, res, next) => {
  const domain = req.query.domain;
  if (!domain) {
    return res.status(400).json({ error: 'Missing query parameter: domain' });
  }

  try {
    const data = await probeDomain(domain);

    // TODO: Scoring logic
    
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

module.exports = router;

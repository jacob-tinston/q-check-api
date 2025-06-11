const tls = require('tls');

// const TLS_VERSIONS = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']; // node:tls doesn't support < TLSv1.2
const TLS_VERSIONS = ['TLSv1.2', 'TLSv1.3'];

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

const probeTLSVersionsAndCiphers = async (params) => {
  let minTLSVersion = null;
  let ciphers = [];

  for (const version of TLS_VERSIONS) {
    try {
      const socket = await connectTLS({
        ...params,
        minVersion: version,
        maxVersion: version,
      });

      if (!minTLSVersion) minTLSVersion = version;
      ciphers.push(socket.getCipher());

      socket.destroy();
    } catch (err) {
      console.warn(`TLS version ${version} not supported for ${params.servername}`);
    }
  }
  return { minTLSVersion, ciphers };
}

module.exports = {
  connectTLS,
  probeTLSVersionsAndCiphers,
};

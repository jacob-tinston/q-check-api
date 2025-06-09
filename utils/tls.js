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

module.exports = {
  connectTLS,
  findMinTLSVersion,
};

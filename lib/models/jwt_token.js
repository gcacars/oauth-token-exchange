import JWT from '../../node_modules/oidc-provider/lib/helpers/jwt.js';

async function parseJWT(value, { client, issuer }) {
  const decoded = JWT.decode(value);
  const { payload, header: { alg } } = decoded;

  JWT.assertPayload(payload, {
    audience: issuer,
    issuer: client.clientUri,
    ignoreExpiration: true,
  });

  const keyStore = alg.startsWith('HS') ? client.symmetricKeyStore : client.asymmetricKeyStore;
  await JWT.verify(value, keyStore);
  return payload;
}

export default parseJWT;

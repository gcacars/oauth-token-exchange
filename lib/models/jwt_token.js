import JWT, { verify } from '../../node_modules/oidc-provider/lib/helpers/jwt.js';

async function parseJWT(value, validation, client) {
  let assertion = validation;
  const decoded = JWT.decode(value);
  const { payload, header: { alg } } = decoded;

  if (Array.isArray(validation.issuer)) {
    assertion = {
      ...validation,
      issuer: validation.issuer.find((i) => i === payload.iss) || validation.issuer[0],
    };
  }

  JWT.assertPayload(payload, assertion);
  return { payload;
}

async function tryDecode(value) {
  try {
    return JWT.decode(value);
  } catch (err) {
    return undefined;
  }
}

async function verifyJWT(client) {
  const keyStore = alg.startsWith('HS') ? client.symmetricKeyStore : client.asymmetricKeyStore;
  await JWT.verify(value, keyStore);
}

export default parseJWT;
export {
  parseJWT,
  tryDecode,
  verifyJWT,
};

/**
 * For the type specified find in the provider for the token instance.
 *
 * @author Gabriel Anderson
 * @param {string} subjectToken The token informed in request parameter
 * @param {string} subjectTokenType The token type
 * @param {import('oidc-provider').KoaContextWithOIDC} ctx The provider Koa context
 * @param {import('../../node_modules/oidc-provider/lib/helpers/jwt').default} jwtHelper
 *   A JWT validation helper
 * @return {*} The provider's token instance or a object for unknown tokens.
 */
async function findTokenByType(subjectToken, subjectTokenType, ctx, jwtHelper) {
  const {
    AccessToken, IdToken, RefreshToken, client, issuer,
  } = ctx.oidc;

  let token;

  switch (subjectTokenType) {
    case 'urn:ietf:params:oauth:token-type:access_token':
      return AccessToken.find(subjectToken, { ignoreExpiration: true });

    case 'urn:ietf:params:oauth:token-type:refresh_token':
      return RefreshToken.find(subjectToken, { ignoreExpiration: true });

    case 'urn:ietf:params:oauth:token-type:id_token':
      return IdToken.find(subjectToken, { ignoreExpiration: true });

    case 'urn:ietf:params:oauth:token-type:jwt': {
      const decoded = jwtHelper.decode(subjectToken);
      const { payload, header: { alg } } = decoded;
      jwtHelper.assertPayload(payload, {
        audience: issuer,
        issuer: client.clientId,
        ignoreExpiration: true,
      });
      const keyStore = alg.startsWith('HS') ? client.symmetricKeyStore : client.asymmetricKeyStore;
      await jwtHelper.verify(subjectToken, keyStore);
      return payload;
    }

    default:
      token = {
        samlToken: true,
        kind: subjectTokenType,
        value: subjectToken,
        isExpired: false,
      };
      break;
  }

  return token;
}

export default findTokenByType;

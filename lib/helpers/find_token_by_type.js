import JWT from '../../node_modules/oidc-provider/lib/helpers/jwt.js';
import actorToken from '../models/actor_token.js';

/**
 * For the type specified find in the provider for the token instance.
 *
 * @author Gabriel Anderson
 * @param {import('oidc-provider').Provider} provider Provider's instance
 * @param {('subject'|'actor')} profile The use of the token
 * @param {string} tokenValue The token informed in request parameter
 * @param {string} tokenType The token type
 * @param {import('oidc-provider').KoaContextWithOIDC} ctx The provider Koa context
 * @return {*} The provider's token instance or a object for unknown tokens.
 */
async function findTokenByType(provider, profile, tokenValue, tokenType, ctx, instance) {
  const { client, issuer } = ctx.oidc;
  const {
    AccessToken, IdToken, RefreshToken, BaseToken, Client,
  } = provider;

  let token;
  const tokenIsJwt = tokenValue.startsWith('ey') && tokenValue.replace(/[^\\.]/g, '').length === 2;
  const tokenFormat = tokenIsJwt ? 'urn:ietf:params:oauth:token-type:jwt' : tokenType;
  // const tokenIssuer = tokenIsJwt ? await tryDecode(tokenValue)?.payload?.iss : undefined;

  /*
  if (tokenIsJwt && tokenIssuer && tokenIssuer !== issuer) {
    tokenFormat = 'urn:ietf:params:oauth:token-type:jwt';
  }
  */

  switch (tokenFormat) {
    case 'urn:ietf:params:oauth:token-type:access_token':
      token = await AccessToken.find(tokenValue, { ignoreExpiration: true });
      break;

    case 'urn:ietf:params:oauth:token-type:refresh_token':
      token = await RefreshToken.find(tokenValue, { ignoreExpiration: true });
      break;

    case 'urn:ietf:params:oauth:token-type:id_token':
      token = await IdToken.find(tokenValue, { ignoreExpiration: true });
      break;

    case 'urn:ietf:params:oauth:token-type:jwt': {
      // Decode
      const decoded = JWT.decode(tokenValue);
      const { payload, header: { alg } } = decoded;

      // Verify
      let match = {
        audience: client.clientUri,
        issuer: [issuer, client.clientUri],
        ignoreExpiration: true,
      };

      if (profile === 'actor') {
        // Delegation
        match = {
          audience: issuer,
          issuer: [client.clientUri, issuer],
          ignoreExpiration: true,
        };
      }

      if (Array.isArray(match.issuer)) {
        match.issuer = match.issuer.find((i) => i === payload.iss) || match.issuer[0];
      }

      JWT.assertPayload(payload, match);

      // Token issuer in a valid origin for this client?
      if (payload.iss && payload.iss !== issuer
        && ![client.clientUri, ...client.redirectUris].includes(payload.iss)) {
        throw new Error(`Token issuer is not a known issuer: ${payload.iss}`);
      }

      // Check signature
      //await JWT.verify(tokenValue, instance.keystore);

      // Get token instance
      token = new (actorToken(BaseToken))({
        client,
        expiresIn: payload.exp,
        ...payload,
      });
      break;
    }

    default:
      return undefined;
  }

  return token;
}

export default findTokenByType;

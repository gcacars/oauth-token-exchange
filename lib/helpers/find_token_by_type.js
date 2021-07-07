import util from 'util';
import JWT from '../models/jwt_token.js';
import actorToken from '../models/actor_token.js';

/**
 * For the type specified find in the provider for the token instance.
 *
 * @author Gabriel Anderson
 * @param {import('oidc-provider').Provider} provider Provider's instance
 * @param {string} tokenValue The token informed in request parameter
 * @param {string} tokenType The token type
 * @param {import('oidc-provider').KoaContextWithOIDC} ctx The provider Koa context
 * @param {import('../../node_modules/oidc-provider/lib/helpers/jwt').default} jwtHelper
 *   A JWT validation helper
 * @return {*} The provider's token instance or a object for unknown tokens.
 */
async function findTokenByType(provider, tokenValue, tokenType, ctx) {
  const { client, issuer } = ctx.oidc;
  const {
    AccessToken, IdToken, RefreshToken, BaseToken,
  } = provider;

  let token;

  switch (tokenType) {
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
      const payload = await JWT(tokenValue, { client, issuer });

      if (payload.sub && payload.sub !== client.clientId) {
        throw new Error('sub e clientId');
      }

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

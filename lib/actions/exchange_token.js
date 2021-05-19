import { errors } from 'oidc-provider';

import findTokenByType from '../helpers/find_token_by_type.js';
import validateTokenType from '../helpers/validate_token_type.js';

import calculateThumbprint from '../../node_modules/oidc-provider/lib/helpers/calculate_thumbprint.js';
import difference from '../../node_modules/oidc-provider/lib/helpers/_/difference.js';
import instance from '../../node_modules/oidc-provider/lib/helpers/weak_cache.js';
import formatters from '../../node_modules/oidc-provider/lib/helpers/formatters.js';
import presence from '../../node_modules/oidc-provider/lib/helpers/validate_presence.js';
import JWT from '../../node_modules/oidc-provider/lib/helpers/jwt.js';

const { InvalidGrant, InvalidScope, InvalidTarget } = errors;
const { 'x5t#S256': thumbprint } = calculateThumbprint;

/**
 * Exchange a token for another.
 *
 * @author Gabriel Anderson
 * @param {import('oidc-provider').KoaContextWithOIDC} ctx
 * @param {function} next
 */
async function exchangeTokenHandler(ctx, next) {
  let delegation = false;
  presence(ctx, 'subject_token', 'subject_token_type');

  const {
    params, client, entity, provider, requestParamScopes,
  } = ctx.oidc;

  // Optional actor
  if (params.actor_token) {
    presence(ctx, 'actor_token_type');
    delegation = true;
  }

  const conf = instance(provider).configuration();

  const {
    features: {
      introspection,
      mTLS: { getCertificate },
      resourceIndicators,
    },
    issueRefreshToken,
  } = conf;

  // Request
  const subjectTokenValue = params.subject_token;
  const subjectTokenType = validateTokenType(params.subject_token_type, 'subject_token');

  let actorToken;
  const actorTokenValue = delegation ? params.actor_token : null;
  const actorTokenType = delegation ? validateTokenType(params.actor_token_type, 'actor_token_type') : null;

  const subjectToken = await findTokenByType(subjectTokenValue, subjectTokenType, ctx, JWT);

  if (!subjectToken) {
    throw new InvalidGrant(`subject ${subjectTokenType} token not found`);
  }

  if (delegation) {
    actorToken = await findTokenByType(actorTokenValue, actorTokenType, ctx, JWT);

    if (!actorToken) {
      throw new InvalidGrant(`actor ${actorTokenType} token not found`);
    }
  }

  // mTLS
  let cert;
  if (client.tlsClientCertificateBoundAccessTokens || subjectToken['x5t#S256']) {
    cert = getCertificate(ctx);
    if (!cert) {
      throw new InvalidGrant('mutual TLS client certificate not provided');
    }
  }

  if (subjectToken['x5t#S256'] && subjectToken['x5t#S256'] !== thumbprint(cert)) {
    throw new InvalidGrant('failed x5t#S256 verification for subject token');
  }

  if (delegation && actorToken['x5t#S256'] && actorToken['x5t#S256'] !== thumbprint(cert)) {
    throw new InvalidGrant('failed x5t#S256 verification for actor token');
  }

  // Tokens
  if (subjectToken.isExpired) throw new InvalidGrant('subject token is expired');
  if (actorToken.isExpired) throw new InvalidGrant('actor token is expired');

  if (params.scope && !subjectToken.samlToken) {
    const missing = difference([...requestParamScopes], [...subjectToken.scopes]);

    if (missing.length !== 0) {
      throw new InvalidScope(`subject token missing requested ${formatters.pluralize('scope', missing.length)}`, missing.join(' '));
    }
  }

  entity('SubjectToken', subjectToken);
  if (delegation) entity('ActorToken', actorToken);

  const {
    Account, AccessToken, IdToken, RefreshToken,
  } = provider;

  // Subject
  const subject = await Account.findAccount(ctx, subjectToken.accountId);

  if (!subject) {
    throw new InvalidGrant('subject account not found');
  }

  entity('Subject', subject);

  // Actor
  if (delegation) {
    const actor = await Account.findAccount(ctx, actorToken.accountId);

    if (!actor) {
      throw new InvalidGrant('actor account not found');
    }

    entity('Actor', actor);
  }

  // access tokens
  const accessTokenType = 'urn:ietf:params:oauth:token-type:access_token';
  const tokenType = params.requested_token_type || accessTokenType;
  const isAccessToken = tokenType === accessTokenType;

  // resource
  let { resource } = params;

  if (isAccessToken && Array.isArray(resource)) {
    resource = await resourceIndicators.defaultResource(ctx, client, resource);
  }

  if (isAccessToken && Array.isArray(resource)) {
    throw new InvalidTarget(
      'only a single resource indicator value must be requested/resolved during token exchange that resolves to an access token'
    );
  }

  if (resource && !subjectToken.resourceIndicators.has(resource)) {
    throw new InvalidTarget();
  }

  if (resource) { // FIX
    const resourceServerInfo = await resourceIndicators
      .getResourceServerInfo(ctx, resource, client);
    subjectToken.resourceServer = new provider.ResourceServer(resource, resourceServerInfo);
    subjectToken.scope = grant.getResourceScopeFiltered(resource, code.scopes);
  } else {
    subjectToken.claims = code.claims;
    subjectToken.scope = grant.getOIDCScopeFiltered(code.scopes);
  }

  // create token
  let token;
  let scope;

  switch (tokenType) {
    case 'urn:ietf:params:oauth:token-type:refresh_token': {
      const newToken = new RefreshToken({
        accountId: token.accountId,
        acr: token.acr,
        amr: token.amr,
        authTime: token.authTime,
        claims: token.claims,
        client,
        expiresWithSession: token.expiresWithSession,
        iiat: token.iiat,
        grantId: token.grantId,
        gty: token.gty,
        nonce: token.nonce,
        resource: token.resource,
        rotations: typeof token.rotations === 'number' ? token.rotations + 1 : 1,
        scope: token.scope,
        sessionUid: token.sessionUid,
        sid: token.sid,
        'x5t#S256': token['x5t#S256'],
        jkt: token.jkt,
      });

      /*
      if (refreshToken.gty && !refreshToken.gty.endsWith(gty)) {
        refreshToken.gty = `${refreshToken.gty} ${gty}`;
      }
      */

      entity('RefreshToken', newToken);
      token = await newToken.save();
      break;
    }

    case 'urn:ietf:params:oauth:token-type:id_token': {
      const newToken = new IdToken({
        ...await account.claims('id_token', code.scope, claims, rejected),
        acr: code.acr,
        amr: code.amr,
        auth_time: code.authTime,
      }, { ctx });

      entity('IdToken', newToken);
      token = await newToken.issue({ use: 'idtoken' });
      break;
    }

    case accessTokenType: {
      const newToken = new AccessToken({
        accountId: account.accountId,
        client,
        expiresWithSession: code.expiresWithSession,
        grantId: code.grantId,
        gty,
        sessionUid: code.sessionUid,
        sid: code.sid,
      });

      if (client.tlsClientCertificateBoundAccessTokens) {
        let cert = getCertificate(ctx);
        if (!cert) {
          throw new InvalidGrant('mutual TLS client certificate not provided');
        }

        newToken.setThumbprint('x5t', cert);
      }

      entity('AccessToken', newToken);
      token = await newToken.save();
      break;
    }

    default:
      break;
  }

  // refresh token?
  let refreshToken;
  if (await issueRefreshToken(ctx, client, subjectToken, actorToken)) { // FIX: docs
    const rt = new RefreshToken({
      accountId: account.accountId,
      acr: code.acr,
      amr: code.amr,
      authTime: code.authTime,
      claims: code.claims,
      client: client,
      expiresWithSession: code.expiresWithSession,
      grantId: code.grantId,
      gty,
      nonce: code.nonce,
      resource: code.resource,
      rotations: 0,
      scope: code.scope,
      sessionUid: code.sessionUid,
      sid: code.sid,
    });

    if (client.tokenEndpointAuthMethod === 'none') {
      if (at.jkt) {
        rt.jkt = at.jkt;
      }

      if (client.tlsClientCertificateBoundAccessTokens) {
        rt['x5t#S256'] = at['x5t#S256'];
      }
    }

    entity('RefreshToken', rt);
    refreshToken = await rt.save();
  }

  const result = {
    access_token: token,
    issued_token_type: tokenType,
    token_type: accessTokenType ? 'Bearer' : 'N_A',
    expires_in: 1111111111,
  };

  if (scope !== params.scope) {
    result.scope = scope;
  }

  if (refreshToken) {
    result.refresh_token = refreshToken;
  }

  return result;
}

export default exchangeTokenHandler;

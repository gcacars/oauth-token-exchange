import { errors } from 'oidc-provider';

import findTokenByType from '../helpers/find_token_by_type.js';
import validateTokenType from '../helpers/validate_token_type.js';

import calculateThumbprint from '../../node_modules/oidc-provider/lib/helpers/calculate_thumbprint.js';
import difference from '../../node_modules/oidc-provider/lib/helpers/_/difference.js';
import instance from '../../node_modules/oidc-provider/lib/helpers/weak_cache.js';
import formatters from '../../node_modules/oidc-provider/lib/helpers/formatters.js';
import presence from '../../node_modules/oidc-provider/lib/helpers/validate_presence.js';
import JWT from '../../node_modules/oidc-provider/lib/helpers/jwt.js';

import OpaqueToken from '../../node_modules/oidc-provider/lib/models/formats/opaque.js';
import JwtToken from '../../node_modules/oidc-provider/lib/models/formats/jwt.js';
import DelegatedAccessToken from '../models/delegated_access_token.js';
import DelegatedRefreshToken from '../models/delegated_refresh_token.js';

const gty = 'urn:ietf:params:oauth:grant-type:token-exchange';
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
    params, client, provider, requestParamScopes, issuer,
  } = ctx.oidc;

  // Optional actor
  if (params.actor_token) {
    presence(ctx, 'actor_token_type');
    delegation = true;
  }

  const providerInstance = instance(provider);
  providerInstance.dynamic.DelegatedAccessToken = providerInstance.dynamic.AccessToken;
  const conf = providerInstance.configuration();

  const {
    features: {
      introspection,
      mTLS: { getCertificate },
      resourceIndicators,
    },
    issueRefreshToken,
  } = conf;

  const {
    renewTtlOnTokenExchange = false,
  } = this.config;

  // Request
  const subjectTokenValue = params.subject_token;
  const subjectTokenType = validateTokenType(params.subject_token_type, 'subject_token');

  let actorToken;
  const actorTokenValue = delegation ? params.actor_token : null;
  const actorTokenType = delegation ? validateTokenType(params.actor_token_type, 'actor_token_type') : null;

  const subjectToken = await findTokenByType(
    provider, subjectTokenValue, subjectTokenType, ctx, JWT,
  );

  if (!subjectToken) {
    throw new InvalidGrant(`subject ${subjectTokenType} token not found`);
  }

  // When actor token is JWT, we don't have a token in memory
  if (delegation) {
    actorToken = await findTokenByType(provider, actorTokenValue, actorTokenType, ctx, JWT);

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

  if (delegation && actorToken && actorToken['x5t#S256'] && actorToken['x5t#S256'] !== thumbprint(cert)) {
    throw new InvalidGrant('failed x5t#S256 verification for actor token');
  }

  // Tokens
  if (subjectToken.isExpired) throw new InvalidGrant('subject token is expired');
  if (delegation && actorToken && actorToken.isExpired) throw new InvalidGrant('actor token is expired');

  const grant = await ctx.oidc.provider.Grant.find(subjectToken.grantId, {
    ignoreExpiration: true,
  });

  if (!grant) {
    throw new InvalidGrant('grant not found');
  }

  if (grant.isExpired) {
    throw new InvalidGrant('grant is expired');
  }

  ctx.oidc.entity('SubjectToken', subjectToken);
  if (delegation && actorToken) ctx.oidc.entity('ActorToken', actorToken);

  const {
    Account, AccessToken, IdToken, RefreshToken, BaseToken,
  } = provider;

  // Subject
  const subject = await Account.findAccount(ctx, subjectToken.accountId); // FIX claims.sub?

  if (!subject) {
    throw new InvalidGrant('subject account not found');
  }

  ctx.oidc.entity('Subject', subject);

  // Actor
  if (delegation && actorToken) {
    const actor = await Account.findAccount(ctx, actorToken.accountId);

    if (!actor) {
      throw new InvalidGrant('actor account not found');
    }

    ctx.oidc.entity('Actor', actor);
  }

  // access tokens
  const accessTokenType = 'urn:ietf:params:oauth:token-type:access_token';
  const tokenType = params.requested_token_type || accessTokenType;
  const isAccessToken = tokenType === accessTokenType;

  // resource
  let { resource, scope } = params;

  if (scope === undefined) scope = '';

  if (isAccessToken && Array.isArray(resource)) {
    resource = await resourceIndicators.defaultResource(ctx, client, resource);

    if (isAccessToken && Array.isArray(resource)) {
      throw new InvalidTarget(
        'only a single resource indicator value must be requested/resolved during token exchange that resolves to an access token',
      );
    }
  }

  if (resource && !grant.resources[resource]) {
    throw new InvalidTarget();
  }

  if (resource) { // FIX
    const resourceServerInfo = await resourceIndicators
      .getResourceServerInfo(ctx, resource, client);
    subjectToken.resourceServer = new provider.ResourceServer(resource, resourceServerInfo);
    const resourceScopes = resourceServerInfo.scope.split(' ');

    // Filter available scopes for that resource
    scope = scope.split(' ').filter((s) => resourceScopes.includes(s)).join(' ');

    if (scope) {
      const missing = difference([...requestParamScopes], [...resourceScopes]);

      if (missing.length !== 0) {
        throw new InvalidScope(`subject token missing requested ${formatters.pluralize('scope', missing.length)}`, missing.join(' '));
      }
    }
  } else {
    // subjectToken.claims = code.claims;
    // subjectToken.scope = grant.getOIDCScopeFiltered(code.scopes);
  }

  // create token
  let token;
  let newToken;

  switch (tokenType) {
    case 'urn:ietf:params:oauth:token-type:refresh_token': {
      newToken = new RefreshToken({
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
      break;
    }

    case 'urn:ietf:params:oauth:token-type:id_token': {
      newToken = new IdToken({
        ...await account.claims('id_token', scope, claims, rejected),
        acr: subjectToken.acr,
        amr: subjectToken.amr,
        auth_time: subjectToken.authTime,
      }, { ctx });
      break;
    }

    case accessTokenType: {
      newToken = new (DelegatedAccessToken(AccessToken))({
        accountId: subjectToken.accountId,
        client, // FIX verificar qual o client certo (se houver audience)
        expiresWithSession: subjectToken.expiresWithSession,
        grantId: subjectToken.grantId,
        gty,
        sessionUid: subjectToken.sessionUid,
        sid: subjectToken.sid,
      });
      break;
    }

    case 'urn:ietf:params:oauth:token-type:jwt': {
      newToken = new BaseToken({ client });
      newToken.getValueAndPayload = () => ({

      });
      const opaque = new OpaqueToken(provider);
      const jwt = new JwtToken(provider, { opaque });
      const tokenX = Object.assign(jwt, {
        clientId: client.clientId,
        exp: Date.now() + subjectToken.remainingTTL,
      });
      const val = await tokenX.save();

      break;
    }

    default:
      break;
  }

  // Token complement
  if (client.tlsClientCertificateBoundAccessTokens) {
    newToken.setThumbprint('x5t', cert);
  }

  if (resource) {
    newToken.resourceServer = subjectToken.resourceServer;
    newToken.scope = scope;
  } else {
    newToken.claims = subjectToken.claims;
    newToken.scope = scope;
  }

  // Delegation tokens
  if (delegation) {
    if (!newToken.extra) newToken.extra = {};

    newToken.extra.act = {
      iss: issuer,
    };

    if (actorToken && actorToken.sub) {
      newToken.extra.act.sub = actorToken.sub;
    }
  }

  // Save tokens
  switch (tokenType) {
    case 'urn:ietf:params:oauth:token-type:refresh_token': {
      ctx.oidc.entity('RefreshToken', newToken);
      token = await newToken.save();
      break;
    }

    case 'urn:ietf:params:oauth:token-type:id_token': {
      ctx.oidc.entity('IdToken', newToken);
      token = await newToken.issue({ use: 'idtoken' });
      break;
    }

    case accessTokenType: {
      ctx.oidc.entity('AccessToken', newToken);
      token = await newToken.save();
      break;
    }

    case 'urn:ietf:params:oauth:token-type:jwt': {
      ctx.oidc.entity('JwtToken', newToken);
      token = await newToken.save();
      break;
    }

    default:
      break;
  }

  // Should issue a refresh token?
  let refreshToken;
  if (await issueRefreshToken(ctx, client, subjectToken, actorToken)) {
    const rt = new (DelegatedRefreshToken(RefreshToken))({
      accountId: subjectToken.accountId,
      acr: subjectToken.acr,
      amr: subjectToken.amr,
      authTime: subjectToken.authTime,
      claims: subjectToken.claims,
      client,
      expiresWithSession: subjectToken.expiresWithSession,
      grantId: subjectToken.grantId,
      gty,
      nonce: subjectToken.nonce || params.nonce,
      resource,
      rotations: 0,
      scope,
      sessionUid: subjectToken.sessionUid,
      sid: subjectToken.sid,
    });

    if (client.tokenEndpointAuthMethod === 'none') {
      if (subjectToken.jkt) {
        rt.jkt = subjectToken.jkt;
      }

      if (client.tlsClientCertificateBoundAccessTokens) {
        rt['x5t#S256'] = subjectToken['x5t#S256'];
      }
    }

    // Delegation tokens
    if (delegation) {
      rt.act = {
        iss: issuer,
      };

      if (actorToken && actorToken.sub) {
        rt.act.sub = actorToken.sub;
      }
    }

    ctx.oidc.entity('RefreshToken', rt);
    refreshToken = await rt.save();
  }

  // Response
  const result = {
    access_token: token,
    issued_token_type: tokenType,
    token_type: accessTokenType ? 'Bearer' : 'N_A',
    expires_in: newToken.remainingTTL,
  };

  if (scope !== params.scope) {
    result.scope = scope;
  }

  if (refreshToken) {
    result.refresh_token = refreshToken;
  }

  ctx.body = result;
  await next();
}

export default exchangeTokenHandler;

import { Provider, errors } from 'oidc-provider';
import TokenExchange from './index.js';

const config = {
  async findAccount(ctx, id) {
    return {
      accountId: id,
      async claims(use, scope) { return { sub: id }; },
    };
  },
  claims: { act: null, may_act: null },
  clientBasedCORS: () => true,
  cookies: {
    keys: ['aaaa1111'],
  },
  extraTokenClaims(ctx, token) {
    const { entities: { ActorToken }, issuer } = ctx.oidc;

    if (ActorToken && ['AccessToken'].includes(token.kind)) {
      return {
        act: {
          iss: ActorToken.accountId ? issuer : undefined,
          sub: ActorToken.accountId,
        },
      };
    }

    return {};
  },
  features: {
    clientCredentials: {
      enabled: true,
    },
    resourceIndicators: {
      enabled: true,
      defaultResource: (ctx, client, oneOf) => (oneOf ? oneOf[0] : ['https://api.example.com']),
      getResourceServerInfo: (ctx, resourceIndicator, client) => {
        if (client.clientId === 'app') {
          return {
            scope: 'api:read api:write',
            audience: resourceIndicator,
            accessTokenTTL: 45 * 60, // 45 seconds
            accessTokenFormat: 'jwt',
            jwt: {
              sign: {
                alg: 'RS256',
              },
              encrypt: false,
            },
          };
        }

        throw new errors.InvalidTarget();
      },
    },
    introspection: {
      enabled: true,
      // allowedPolicy:
    },
  },
  tokenEndpointAuthMethods: ['none', 'client_secret_basic'],
  scopes: ['openid', 'profile'],
  async issueRefreshToken(ctx, client, codeOrSubjectToken, actorToken) {
    if (ctx.oidc.entities.SubjectToken) {
      if (actorToken) {
        // ...
        return true;
      }
      return false;
    }

    return true;
  },
  clients: [{
    client_id: 'app',
    client_secret: 'LFFAAj-CNXEVhYSNhKsSg7TcRwUjpG2FcIAkLpR8v8ttz6QOa8OPfLBHzRUNAKYYZYRF6EgHxwMxAWGOi9bo6DS-W86GGhV-ODKvUruTmBvwCf10VPyv2VLg6DpjNNRMSaNxLTMaQRdGuX8u2RZyjAUuddoroHZ17lEtShx-JAINuH9YLdwJY7W8Lq8oQ2Y61pryPdlDHfPcl772og_4wf6JpKJqZJrmL79eG61CtqT7yNBy1IkzyiPbt6aP1q9og6xwbsFslHczRluBHi0_65p520mP3f3R3_-5RXRsE2mN8WQGXQVeJLf0dW9WfOQr1xVAtv0ifXnDdYodc9G0nQ',
    client_uri: 'https://app-rp.dev.br',
    // Register grant type for this client or set it in the `clientDefaults`.
    grant_types: ['authorization_code', 'urn:ietf:params:oauth:grant-type:token-exchange', 'client_credentials'],
    redirect_uris: [
      'https://app-rp.dev.br/',
      'https://app-rp.dev.br/authp',
      'https://app-rp.dev.br/s.html',
    ],
    token_endpoint_auth_method: 'none',
    /*
    jwks: {
      keys: [
        {
          kty: 'oct',
          use: 'sig',
          kid: 'sig-1621859151',
          k: 'LFFAAj-CNXEVhYSNhKsSg7TcRwUjpG2FcIAkLpR8v8ttz6QOa8OPfLBHzRUNAKYYZYRF6EgHxwMxAWGOi9bo6DS-W86GGhV-ODKvUruTmBvwCf10VPyv2VLg6DpjNNRMSaNxLTMaQRdGuX8u2RZyjAUuddoroHZ17lEtShx-JAINuH9YLdwJY7W8Lq8oQ2Y61pryPdlDHfPcl772og_4wf6JpKJqZJrmL79eG61CtqT7yNBy1IkzyiPbt6aP1q9og6xwbsFslHczRluBHi0_65p520mP3f3R3_-5RXRsE2mN8WQGXQVeJLf0dW9WfOQr1xVAtv0ifXnDdYodc9G0nQ',
          alg: 'HS256',
        },
      ],
    },
    */
  }],
};

const provider = new Provider('http://localhost:3000', config);
TokenExchange(provider, {
  // If the new token must respect the TTL configuration and must not
  // use the time remaining from subject token if it's less then
  // specified in TTL configuration (default).
  renewTtlOnTokenExchange: false,
});

// Listen to token creation event. e.g. to do other actions
provider.on('grant.success', (ctx) => {
  const { entities } = ctx.oidc;

  if (entities.SubjectToken) {
    // ...
  }

  if (entities.ActorToken) {
    // ...
  }
});

provider.on('server_error', (ctx, err) => {
  console.log(err);
});

provider.on('jwks.error', (ctx, err) => {
  console.log(err);
});

provider.listen(3000, () => {
  console.log('oidc-provider listening on port 3000, check http://localhost:3000/.well-known/openid-configuration');
});

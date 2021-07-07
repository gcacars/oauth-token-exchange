# OAuth 2.0 Token Exchange

[RFC8693](https://datatracker.ietf.org/doc/html/rfc8693) implementation extension for [`oidc-provider`](https://github.com/panva/node-oidc-provider) package.

## Changes to OIDC Provider

```javascript
import { Provider } from 'oidc-provider';
import TokenExchange from 'oauth-token-exchange';

const config = {
  features: {
    resourceIndicators: {
      enabled: true,
      // defaultResource:
      // getResourceServerInfo
    },
    introspection: {
      enabled: true,
      // allowedPolicy:
    },
  },
  ttl: {
    AccessTokenTTL(ctx, token, client) {

    },
  },
  clients: [{
    client_id: 'app',
    // Register grant type for this client or set it in the `clientDefaults`.
    grant_types: ['urn:ietf:params:oauth:grant-type:token-exchange'],
  }],
};

const provider = new Provider('http://localhost:3000', config);
TokenExchange(provider);
```

### To the token endpoint

In the request:

* new grant type and flow: `urn:ietf:params:oauth:grant-type:token-exchange`
* supported parameters: `actor_token`, `actor_token_type`, `audience`, `subject_token`, `subject_token_type`, `requested_token_type`

> to support the `resource` parameter, `features.resourceIndicators` must be enabled.

#### Token response

* `issued_token_type` parameter
* `token_type` may return `"N_A"`

### In the token

* Claims: `act`, `may_act`

### Introspection

If `features.introspection` is enabled, the claims `act` and `may_act` may be present.

## Token types

* `urn:ietf:params:oauth:token-type:access_token` (OAuth 2 Access Token)
* `urn:ietf:params:oauth:token-type:refresh_token` (OAuth 2 Refresh Token)
* `urn:ietf:params:oauth:token-type:id_token` (OpenID Connect ID Token)
* `urn:ietf:params:oauth:token-type:jwt` (generic JWT token)

> `urn:ietf:params:oauth:token-type:saml1` and `urn:ietf:params:oauth:token-type:saml2` (OASIS SAML Core) is not implemented!

## Options

### renewTtlOnTokenExchange

A boolean indicating if the new token must respect the TTL configuration and must not use the time remaining from subject token if it's less then specified in TTL configuration (default).

## Events

It has no custom events, just listen to the original [oidc-provider](https://github.com/panva/node-oidc-provider/blob/main/docs/events.md) package events:

```javascript
// Listen to token creation event. e.g. to do other actions
provider.on('grant.success', (ctx) => {
  const { entities } = ctx.oidc;
  
  if (entities.has('SubjectToken')) {
    // ...
  }

  if (entities.has('ActorToken')) {
    // ...
  }
});
```

## Full example

```javascript
import { Provider } from 'oidc-provider';
import TokenExchange from 'oauth-token-exchange';

const config = {
  clientBasedCORS: () => true,
  cookies: {
    keys: ['aaaa1111'],
  },
  features: {
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
  ttl: {
    AccessTokenTTL(ctx, token, client) {

    },
  },
  clients: [{
    client_id: 'app',
    // Register grant type for this client or set it in the `clientDefaults`.
    grant_types: ['urn:ietf:params:oauth:grant-type:token-exchange'],
  }],
};

const provider = new Provider('http://localhost:3000', config);
TokenExchange(provider, {
  renewTtlOnTokenExchange: false,
});

provider.on('grant.success', (ctx) => {
  const { entities } = ctx.oidc;
  
  if (entities.has('SubjectToken')) {
    // ...
  }

  if (entities.has('ActorToken')) {
    // ...
  }
});
```

> Make sure to not use this in a **production** environment. It has several security issues.

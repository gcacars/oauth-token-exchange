import exchangeTokenHandler from './actions/exchange_token.js';

const grantType = 'urn:ietf:params:oauth:grant-type:token-exchange';
const parameters = [
  'audience', 'resource', 'scope', 'requested_token_type', 'subject_token', 'subject_token_type',
  'actor_token', 'actor_token_type',
];
const allowedDuplicateParameters = ['audience', 'resource'];

/**
 *
 *
 * @author Gabriel Anderson
 * @param {import('oidc-provider').Provider} provider
 * @param {object} config
 */
function init(provider, config) {
  if (provider) {
    const handler = exchangeTokenHandler.bind({
      provider,
      config,
    });

    provider.registerGrantType(
      grantType, handler, parameters, allowedDuplicateParameters,
    );
  }
}

export default init;

import tokenExchangeHandler from './actions/exchange_token.js';

const grantType = 'urn:ietf:params:oauth:grant-type:token-exchange';
const parameters = [
  'audience', 'resource', 'scope', 'requested_token_type', 'subject_token', 'subject_token_type',
  'actor_token', 'actor_token_type',
];
const allowedDuplicateParameters = ['audience', 'resource'];

function init(provider) {
  if (provider) {
    provider.registerGrantType(
      grantType, tokenExchangeHandler, parameters, allowedDuplicateParameters,
    );
  }
}

export default init;

import { errors } from 'oidc-provider';

const validTypes = [
  'urn:ietf:params:oauth:token-type:access_token',
  'urn:ietf:params:oauth:token-type:refresh_token',
  'urn:ietf:params:oauth:token-type:id_token',
  'urn:ietf:params:oauth:token-type:saml1',
  'urn:ietf:params:oauth:token-type:saml2',
  'urn:ietf:params:oauth:token-type:jwt',
];

/**
 * Validate if the type informed is valid token type.
 *
 * @author Gabriel Anderson
 * @param {string} type The type informed in request parameters
 * @param {string} param The parameter where type is informed
 * @returns {string} The validated token type.
 * @throws {errors.InvalidRequest} Throws a InvalidRequest error if the token type isn't recognized.
 */
function validateTokenType(type, param) {
  if (!validTypes.includes(type)) {
    throw new errors.InvalidRequest(`${type} is not a valid token type for parameter ${param}`);
  }

  // TODO: implement support?
  if (type.includes('saml')) {
    throw new errors.RequestNotSupported(
      'type is not supported', `Token type ${type} is not currently supported`,
    );
  }

  return type;
}

export default validateTokenType;

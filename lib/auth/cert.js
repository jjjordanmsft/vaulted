'use strict';
var
  Vaulted = {},
  Promise = require('bluebird'),
  fs = require('fs'),
  _ = require('lodash');

/**
  * @module auth/cert
  * @extends Vaulted
  * @desc Provides implementation for the Vault Certificate auth APIs
  *
 */

module.exports = function extend(Proto) {
  Vaulted.getAuthCertEndpoint = _.partialRight(
    _.partial(Proto.validateEndpoint, 'auth/%s/certs/:id'), 'cert');
  Vaulted.getAuthCertListEndpoint = _.partialRight(
    _.partial(Proto.validateEndpoint, 'auth/%s/certs'), 'cert');
  Vaulted.getAuthCertCRLEndpoint = _.partialRight(
    _.partial(Proto.validateEndpoint, 'auth/%s/crls/:id'), 'cert');
  Vaulted.getAuthCertLoginEndpoint = _.partialRight(
    _.partial(Proto.validateEndpoint, 'auth/%s/login'), 'cert');
  Vaulted.getAuthCertConfigEndpoint = _.partialRight(
    _.partial(Proto.validateEndpoint, 'auth/%s/config'), 'cert');
  _.extend(Proto, Vaulted);
};

/**
 * @method addAuthCertificate
 * @desc Sets a CA cert and associated parameters in a role name.
 *
 * @param {string} [options.id] - name of the role to create or update
 * @param {string} [options.body.certificate] - The PEM-format CA certificate.
 * @param {string} [options.body.policies] - A comma-separated list of policies to set on tokens issued when authenticating against this certificate.
 * @param {string} [options.body.display_name] - The display_name to set on tokens issued when authenticating against this certificate.  If unset, defaults to the name of the role.
 * @param {string} [options.body.ttl] - TTL period of the token
 *
 * @resolve {Auth} Resolves with token details.
 * @reject {Error} An error indicating what went wrong
 * @return {Promise}
 */
Vaulted.addAuthCertificate = Promise.method(function addAuthCertificate(options, mountName) {
  options = options || {};
  
  return this.getAuthCertEndpoint(mountName)
    .post({
      headers: this.headers,
      id: options.id,
      body: options.body,
      _token: options.token
    });
});

/**
 * @method getAuthCertificate
 * @desc Gets information associated with the named role.
 *
 * @param {string} [options.id] - name of the role to query
 *
 * @resolve {Role} Resolves with information related to the role.
 * @reject {Error} An error indicating what went wrong
 * @return {Promise}
 */
Vaulted.getAuthCertificate = Promise.method(function getAuthCertificate(options, mountName) {
  options = options || {};
  
  return this.getAuthCertEndpoint(mountName)
    .get({
      headers: this.headers,
      id: options.id,
      _token: options.token
    });
});

/**
 * @method listAuthCertificates
 * @desc Lists configured certificate names
 *
 * @resolve {Certificates} Resolves with a list of certificates and related information
 * @reject {Error} An error indicating what went wrong
 * @return {Promise}
 */
Vaulted.listAuthCertificates = Promise.method(function listAuthCertificates(options, mountName) {
  options = options || {};
  return this.getAuthCertListEndpoint(mountName)
    .list({
      headers: this.headers,
      _token: options.token
    });
});

/**
 * @method deleteAuthCertficiate
 * @desc Deletes the named role and CA cert from the backend mount
 *
 * @param {string} [options.id] - name of the role to delete
 *
 * @resolve {Empty} Resolves on success with no data
 * @reject {Error} An error indicating what went wrong
 * @return {Promise}
 */
Vaulted.deleteAuthCertificate = Promise.method(function deleteAuthCertificate(options, mountName) {
  options = options || {};
  
  return this.getAuthCertEndpoint(mountName)
    .delete({
      headers: this.headers,
      id: options.id,
      _token: options.token
    });
});

/**
 * @method setAuthCRL
 * @desc Sets a named CRL
 *
 * @param {string} [options.id] - name of the CRL to create or update
 * @param {string} [options.body.crl] - The PEM-format CRL
 *
 * @resolve {Empty} Resolves on success with no data
 * @reject {Error} An error indicating what went wrong
 * @return {Promise}
 */
Vaulted.setAuthCRL = Promise.method(function setAuthCRL(options, mountName) {
  options = options || {};
  
  return this.getAuthCertCRLEndpoint(mountName)
    .post({
      headers: this.headers,
      id: options.id,
      body: options.body,
      _token: options.token
    });
});

/**
 * @method getAuthCRL
 * @desc Gets information associated with the named CRL (currently, the serial numbers contained within).
 *
 * @param {string} [options.id] - name of the CRL to query
 *
 * @resolve {CRLs} Resolves with a list of serials inside the CRL
 * @reject {Error} An error indicating what went wrong
 * @return {Promise}
 */
Vaulted.getAuthCRL = Promise.method(function getAuthCRL(options, mountName) {
  options = options || {};
  
  return this.getAuthCertCRLEndpoint(mountName)
    .get({
      headers: this.headers,
      id: options.id,
      _token: options.token
    });
});

/**
 * @method deleteAuthCRL
 * @desc Deletes the named CRL from the backend mount.
 *
 * @param {string} [options.id] - name of the CRL to delete
 *
 * @resolve {Empty} Resolves on success with no data
 * @reject {Error} An error indicating what went wrong
 * @return {Promise}
 */
Vaulted.deleteAuthCRL = Promise.method(function deleteAuthCRL(options, mountName) {
  options = options || {};
  
  return this.getAuthCertCRLEndpoint(mountName)
    .delete({
      headers: this.headers,
      id: options.id,
      _token: options.token
    });
});

/**
 * @method certificateLogin
 * @desc Logs in with the specified certificate and applies the token to this client.
 *
 * @param {string} [options.ssl_cert_file] - The path to a file containing a PEM-formatted client certificate
 * @param {string} [options.ssl_pem_file] - The path to a file containing a PEM-formatted private key matching the specified certificate
 * @param {string} [options.cert] - A PEM-formatted certificate
 * @param {string} [options.key] - A PEM-formatted private key matching the specified certificate
 *
 * @resolve {Auth} Resolves with token details
 * @reject {Error} An error indicating what went wrong
 * @return {Promise}
 */
Vaulted.certificateLogin = Promise.method(function certificateLogin(options, mountName) {
  options = options || {};
  var agentOptions = {};
  
  if (options.ssl_cert_file) {
    agentOptions.cert = fs.readFileSync(options.ssl_cert_file);
  } else if (options.cert) {
    agentOptions.cert = options.cert;
  }
  
  if (options.ssl_pem_file) {
    agentOptions.key = fs.readFileSync(options.ssl_pem_file);
  } else if (options.key) {
    agentOptions.key = options.key;
  }
  
  var _this = this;
  return this.getAuthCertLoginEndpoint(mountName)
    .post(agentOptions)
    .then(function (result) {
      _this.setToken(result.auth.client_token);
      return result;
    });
});

/**
 * @method configureAuthCertificates
 * @desc Configures options for the certificate authentication backend
 *
 * @param {string} [options.body.disable_binding] - If set, during renewal, skips the matching of presented identity with the client identity used during login. Defaults to false
 *
 * @resolve {Empty} Resolves on success with no data
 * @reject {Error} An error indicating what went wrong
 * @return {Promise}
 */
Vaulted.configureAuthCertificates = Promise.method(function configureAuthCertificates(options, mountName) {
  options = options || {};
  
  return this.getAuthCertConfigEndpoint(mountName)
    .post({
      headers: this.headers,
      body: options.body,
      _token: options.token
    });
});

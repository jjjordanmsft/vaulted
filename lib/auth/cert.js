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

Vaulted.getAuthCertificate = Promise.method(function getAuthCertificate(options, mountName) {
  options = options || {};
  
  return this.getAuthCertEndpoint(mountName)
    .get({
      headers: this.headers,
      id: options.id,
      _token: options.token
    });
});

Vaulted.listAuthCertificates = Promise.method(function listAuthCertificates(mountName) {
  options = options || {};
  
  return this.getAuthCertListEndpoint(mountName)
    .list({
      headers: this.headers,
      _token: options.token
    });
});

Vaulted.deleteAuthCertificate = Promise.method(function deleteAuthCertificate(options, mountName) {
  options = options || {};
  
  return this.getAuthCertEndpoint(mountName)
    .delete({
      headers: this.headers,
      id: options.id,
      _token: options.token
    });
});

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

Vaulted.getAuthCRL = Promise.method(function getAuthCRL(options, mountName) {
  options = options || {};
  
  return this.getAuthCertCRLEndpoint(mountName)
    .get({
      headers: this.headers,
      id: options.id,
      _token: options.token
    });
});

Vaulted.deleteAuthCRL = Promise.method(function deleteAuthCRL(options, mountName) {
  options = options || {};
  
  return this.getAuthCertCRLEndpoint(mountName)
    .delete({
      headers: this.headers,
      id: options.id,
      _token: options.token
    });
});

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

Vaulted.configureAuthCertificates = Promise.method(function configureAuthCertificates(options, mountName) {
  options = options || {};
  
  return this.getAuthCertConfigEndpoint(mountName)
    .post({
      headers: this.headers,
      body: options.body,
      _token: options.token
    });
});

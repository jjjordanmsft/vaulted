'use strict';
var debuglog = require('util').debuglog('vaulted-tests');
var _ = require('lodash');
var Promise = require('bluebird');
var rp = require('request-promise');
var fs = require('fs');
var path = require('path');
var os = require('os');
var forge = require('node-forge');

var helpers = module.exports = {
  chai: require('chai'),
  assert: require('chai').assert,
  expect: require('chai').expect,
  should: require('chai').should(),
  cap: require('chai-as-promised'),
  debuglog: debuglog,
  VAULT_HOST: process.env.VAULT_HOST || 'vault',
  VAULT_PORT: process.env.VAULT_PORT || 8200,
  CONSUL_HOST: process.env.CONSUL_HOST || '127.0.0.1',
  CONSUL_PORT: process.env.CONSUL_PORT || 8500
};

var Vault = require('../lib/vaulted');

var BACKUP_FILE = path.join(os.tmpdir(), 'keys.json');

helpers.isTrue = function isTrue(value) {
  return _.isString(value) && (value.toLowerCase() === 'true' || value.toLowerCase() === 'yes');
};

helpers.getVault = function getVault() {
  return new Vault({
    vault_host: helpers.VAULT_HOST,
    vault_port: helpers.VAULT_PORT,
    vault_ssl: false
  });
};

helpers.getEmptyVault = function getEmptyVault() {
  return new Vault({});
};

helpers.getPreparedVault = function getPreparedVault() {
  var backupData = helpers.recover();
  var myVault = this.getVault();
  return myVault.prepare(backupData.root_token);
};

helpers.getReadyVault = function getReadyVault() {
  return helpers.getPreparedVault().then(helpers.setupVault);
};

helpers.setupVault = function (myVault) {

  var backupData = helpers.recover();
  if (backupData.root_token) {
    myVault.setToken(backupData.root_token);
  }

  return myVault.prepare().bind(myVault).then(function () {
    if (myVault.initialized && !myVault.status.sealed) {
      return myVault;
    }
    return myVault.init().then(function (data) {
      if (data.root_token) {
        myVault.setToken(data.root_token);
        helpers.backup(data);
      }
      return myVault.unSeal({
        body: {
          key: _.sample(_.union(data.keys || [], backupData.keys || []))
        }
      }).then(function () {
        return helpers.setupVault(myVault);
      });
    });
  }).catch(function onError(err) {
    debuglog('(before) vault setup failed: %s', err.message);
  });

};

helpers.backup = function backup(data) {
  fs.writeFileSync(BACKUP_FILE, JSON.stringify(data), {
    mode: parseInt('0700', 8)
  });
  debuglog('backup file written');
};

helpers.recover = function recover() {
  try {
    return JSON.parse(fs.readFileSync(BACKUP_FILE));
  } catch (err) {
    // file most likely does not exist so just ignore it.
    if (err.code !== 'ENOENT') {
      debuglog('unable to read backup: %s', err.message);
    }
    return {};
  }
};

helpers.isVaultReady = function isVaultReady(vault) {
  return Promise.delay(500).then(function () {
    return vault.checkHealth().then(function (status) {
      debuglog('Vault Ready: ', status);
    }).catch(function (err) {
      if (err.statusCode === 429) {
        debuglog('Vault was not ready after first check so try again!');
        return Promise.delay(500).then(function () {
          vault.checkHealth();
        });
      }
    });
  });
};

helpers.createConsulToken = function createConsulToken() {
  var TEST_CONSUL_HOST = process.env.TEST_CONSUL_HOST || '127.0.0.1';
  var TEST_CONSUL_PORT = process.env.TEST_CONSUL_PORT || 8500;
  var options = {
    method: 'PUT',
    uri: 'http://' + TEST_CONSUL_HOST + ':' + TEST_CONSUL_PORT + '/v1/acl/create',
    json: true,
    headers: {
      'X-Consul-Token': 'secret'
    },
    body: {
      Name: 'mgmtkey',
      Type: 'management'
    }
  };
  return rp(options).then(function (data) {
    return data.ID;
  }).catch(function (err) {
    debuglog('createConsulToken failed: ', err);
    return null;
  });
};

helpers.getToken = function getToken(vault) {

  var configConsulAccess = function (token) {
    return vault.configConsulAccess({
      body: {
        address: helpers.CONSUL_HOST + ':' + helpers.CONSUL_PORT,
        token: token
      }
    });
  };

  var createConsulRole = function () {
    return vault.createConsulRole({
      id: 'writer',
      body: {
        policy: 'path "secret/*" { policy = "write" }',
        lease: '1h'
      }
    });
  };

  var generateConsulRoleToken = function () {
    return vault.generateConsulRoleToken({
      id: 'writer'
    });
  };

  return helpers.createConsulToken()
    .then(configConsulAccess)
    .then(createConsulRole)
    .then(generateConsulRoleToken)
    .then(function (role) {
      debuglog('generated token: ', role);
      return role;
    }).catch(function (err) {
      debuglog('getToken error: ', err);
      return null;
    });

};

var cert_serial = 0;
helpers.generateCertificate = function generateCertificate(options) {
  options = options || {};
  
  // Key pair
  var keypair = forge.pki.rsa.generateKeyPair(options.bits || 512);
  
  // CSR
  var expiresAfter = typeof options.expire === 'number' ? options.expire : 60 * 60 * 1000;
  var cert = forge.pki.createCertificate();
  cert.publicKey = keypair.publicKey;
  cert.serialNumber = ('' + (cert_serial++));
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date(cert.validity.notBefore.getTime() + expiresAfter);
  var attrs = [
    {
      name: 'commonName',
      value: options.commonName || 'vaulted-tests.example'
    },
    {
      name: 'countryName',
      value: options.countryName || 'US'
    },
    {
      shortName: 'ST',
      value: options.state || 'California'
    },
    {
      name: 'localityName',
      value: options.localityName || 'San Francisco'
    },
    {
      shortName: 'OU',
      value: options.organizationalUnit || 'vaulted-test'
    }
  ];
  
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([{
    name: 'basicConstraints',
    cA: true
  }, {
    name: 'keyUsage',
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: true
  }, {
    name: 'extKeyUsage',
    serverAuth: true,
    clientAuth: true,
    codeSigning: true,
    emailProtection: true,
    timeStamping: true
  }, {
    name: 'nsCertType',
    client: true,
    server: true,
    email: true,
    objsign: true,
    sslCA: true,
    emailCA: true,
    objCA: true
  }, {
    name: 'subjectAltName',
    altNames: []
  }, {
    name: 'subjectKeyIdentifier'
  }]);
  
  cert.sign(keypair.privateKey);
  
  return {
    certificate: forge.pki.certificateToPem(cert),
    publicKey: forge.pki.publicKeyToPem(keypair.publicKey),
    privateKey: forge.pki.privateKeyToPem(keypair.privateKey)
  };
};


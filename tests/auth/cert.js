'use strict';
require('../helpers').should;

var
  helpers = require('../helpers'),
  debuglog = helpers.debuglog,
  _ = require('lodash'),
  chai = helpers.chai,
  
  expect = helpers.expect;

chai.use(helpers.cap);


describe('auth/cert', function () {
  var newVault = helpers.getEmptyVault();
  var myVault;
  var myRootToken;
  var certs = [];
  
  before(function () {
    return helpers.getReadyVault().then(function (vault) {
      myVault = vault;
      myRootToken = vault.token;
      return myVault.createAuthMount({
        id: 'cert',
        body: {
          type: 'cert'
        }
      });
    });
  });
  
  // Generate a stable of self-signed certificates for test use.
  for (var i = 0; i < 5; i++) {
    certs.push(helpers.generateCertificate({bits: 512, commonName: "vaulted-test-" + i + ".example"}));
  }
  
  describe('#addAuthCertificate', function () {
  
    it('should reject with an Error if not initialized or unsealed', function () {
      return newVault.addAuthCertificate({
        id: 'firstCert',
        body: {
          certificate: certs[0].certificate,
          policies: "root"
        }
      }).should.be.rejectedWith(/Vault has not been initialized/);
    });
    
    it('should reject if no certificate is supplied', function () {
      return myVault.addAuthCertificate({
        id: 'noCert',
        body: {
        }
      }).should.be.rejectedWith(/Missing required input certificate/);
    });
    
    it('should reject when no ID is supplied', function () {
      return myVault.addAuthCertificate({
        body: {
          certificate: certs[0].certificate,
          policies: "root"
        }
      }).should.be.rejectedWith(/Endpoint requires an id/);
    });
    
    it('should accept when certificate parameters are present', function () {
      return myVault.addAuthCertificate({
        id: 'firstcert',
        body: {
          certificate: certs[0].certificate,
          policies: "root"
        }
      }).then(function (result) {
        expect(result).to.be.undefined;
        return myVault.listAuthCertificates().then(function (listResult) {
          expect(listResult).to.not.be.undefined;
          listResult.data.keys.should.contain('firstcert');
        });
      });
    });
    
  });
  
  describe('#getAuthCertificate', function () {
    
    it('should reject with an Error if not initialized or unsealed', function () {
      return newVault.getAuthCertificate({
        id: 'firstcert'
      }).should.be.rejectedWith(/Vault has not been initialized/);
    });
    
    it('should reject with 404 if a nonexistent id is supplied', function () {
      return myVault.getAuthCertificate({
        id: 'noCert'
      }).should.be.rejectedWith(/404/);
    });
    
    it('should reject if no id is supplied', function () {
      return myVault.getAuthCertificate({}).should.be.rejectedWith(/Endpoint requires an id/);
    });
    
    it('should return the certificate PEM for a valid certificate', function () {
      return myVault.getAuthCertificate({
        id: 'firstcert'
      }).then(function (result) {
        expect(result).to.not.be.undefined;
        result.should.have.property('data');
        result.data.should.have.property('certificate');
        result.data.certificate.should.equal(certs[0].certificate);
      });
    });
    
  });
  
  describe('#listAuthCertificates', function () {
    
    it('should reject with an Error if not initialized or unsealed', function () {
      return newVault.listAuthCertificates().should.be.rejectedWith(/Vault has not been initialized/);
    });
    
    it('should list certificates', function () {
      return myVault.listAuthCertificates().then(function (result) {
        expect(result).to.not.be.undefined;
        result.should.have.property('data');
        result.data.should.have.property('keys');
      });
    });
    
  });
  
  describe('#deleteAuthCertificate', function () {
    
    it('should reject with an Error if not initialized or unsealed', function () {
      return newVault.deleteAuthCertificate({id: 'firstcert'}).should.be.rejectedWith(/Vault has not been initialized/);
    });
    
    it('should reject with 404 if a nonexistent id is supplied', function () {
      return myVault.deleteAuthCertificate({id: 'this_cert_does_not_exist'}).should.be.rejectedWith(/404/);
    });
    
    it('should reject if no id is supplied', function () {
      return myVault.deleteAuthCertificate({}).should.be.rejectedWith(/Endpoint requires an id/);
    });
    
    it('should delete an existing certificate', function () {
      return myVault.deleteAuthCertificate({id: 'firstcert'}).then(function (result) {
        expect(result).to.be.undefined;
        return myVault.listAuthCertificates().then(function (listResult) {
          expect(listResult).to.not.be.undefined;
          listResult.data.keys.should.not.contain('firstcert');
        });
      });
    });
    
  });
  
  describe('#getAuthCRL', function () {
  });
  
  describe('#deleteAuthCRL', function () {
  });
  
  describe('#certificateLogin', function () {
    
    before(function () {
      return myVault.addAuthCertificate({
        id: 'logincert',
        body: {
          certificate: certs[2].certificate,
          policies: 'root'
        }
      });
    });

    afterEach(function () {
      myVault.setToken(myRootToken);
    });
    
    it('should reject with an Error if not initialized or unsealed', function () {
      return newVault.certificateLogin({
        cert: certs[2].certificate,
        key: certs[2].privateKey
      }).should.be.rejectedWith(/Vault has not been initialized/);
    });
    
    it('should reject when an invalid certificate is supplied', function () {
      return myVault.certificateLogin({
        cert: "bad certificate",
        key: certs[2].privateKey
      }).should.be.rejected;
    });
    
    it('should reject when an invalid key is supplied', function () {
      return myVault.certificateLogin({
        cert: certs[2].certificate,
        key: "bad private key"
      }).should.be.rejected;
    });
    
    it('should reject when no certificate is supplied', function () {
      return myVault.certificateLogin({
        key: certs[2].privateKey
      }).should.be.rejected;
    });
    
    it('should reject when no key is supplied', function () {
      return myVault.certificateLogin({
        cert: certs[2].certificate
      }).should.be.rejected;
    });
    
    it('should login when a valid certificate and key are supplied', function () {
      console.log(myVault);
      return myVault.certificateLogin({
        cert: certs[2].certificate,
        key: certs[2].privateKey
      }).then(function (result) {
        expect(result).to.not.be.undefined;
        result.should.have.property('auth');
        result.auth.should.have.property('client_token');
        result.auth.client_token.to.equal(myVault.token);
      });
    });
    
  });
  
  describe('#configureAuthCertificate', function () {
  });

  after(function () {
    return myVault.deleteAuthMount({
      id: 'cert'
    });
  });
});


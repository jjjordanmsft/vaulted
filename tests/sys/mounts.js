'use strict';
require('../helpers').should;

var
  helpers = require('../helpers'),
  debuglog = helpers.debuglog,
  _ = require('lodash'),
  chai = helpers.chai;

chai.use(helpers.cap);


describe('mounts', function () {
  var newVault = helpers.getEmptyVault();
  var myVault;

  before(function () {
    return helpers.getReadyVault().then(function (vault) {
      myVault = vault;
    });

  });

  describe('#getMounts', function () {

    it('should reject with an Error if not initialized or unsealed', function () {
      return newVault.getMounts().should.be.rejectedWith(/Vault has not been initialized/);
    });

    it('should update internal state with list of mounts', function () {
      return myVault.getMounts().then(function (mounts) {
        debuglog(mounts);
        mounts.should.not.be.empty;
        mounts.should.contain.keys('sys/');
      });
    });

  });

  describe('#createMount', function () {

    it('should reject with an Error if not initialized or unsealed', function () {
      return newVault.createMount({
        id: 'other',
        body: {
          type: 'consul'
        }
      }).should.be.rejectedWith(/Vault has not been initialized/);
    });

    it('should reject with an Error if no options provided', function () {
      return myVault.createMount()
        .should.be.rejectedWith(/requires an id/);
    });

    it('should reject with an Error if option id empty', function () {
      return myVault.createMount({
        id: ''
      }).should.be.rejectedWith(/requires an id/);
    });

    it('should reject with an Error if option body empty', function () {
      return myVault.createMount({
        id: 'xzy',
        body: null
      }).should.be.rejectedWith(/Missing required input/);
    });

    it('should reject with an Error if option body without type', function () {
      return myVault.createMount({
        id: 'xzy',
        body: {}
      }).should.be.rejectedWith(/Missing required input/);
    });

    it('should reject with an Error if option body with empty type', function () {
      return myVault.createMount({
        id: 'xzy',
        body: {
          type: ''
        }
      }).should.be.rejectedWith(/Missing required input/);
    });

    it('should use the options object when provided', function (done) {
      myVault.createMount({
        id: 'options',
        body: {
          type: 'generic',
          config: {
            'max_lease_ttl': '5m',
            'default_lease_ttl': '2m'
          }
        }
      }).then(function (mounts) {
        mounts.should.not.be.empty;
        mounts.should.contain.keys('options/');

        var foundMount = mounts['options/'];
        foundMount.should.contain.keys('config');
        foundMount.config.should.have.all.keys('default_lease_ttl', 'max_lease_ttl');
        foundMount.config.default_lease_ttl.should.equal(2 * 60);
        foundMount.config.max_lease_ttl.should.equal(5 * 60);
        done();
      })
    });

    it('should resolve to updated list of mounts', function (done) {
      var existingMounts = _.cloneDeep(myVault.mounts);
      return myVault.createMount({
        id: 'other',
        body: {
          type: 'consul'
        }
      }).then(function (mounts) {
        debuglog(mounts);
        existingMounts.should.not.be.empty;
        mounts.should.not.be.empty;
        existingMounts.should.not.contain.keys('other/');
        mounts.should.contain.keys('other/');
        done();
      });
    });

  });

  describe('#reMount', function () {

    it('should reject no options provided', function () {
      return myVault.reMount()
        .should.be.rejectedWith(/Missing required input/);
    });

    it('should reject empty option from', function () {
      return myVault.reMount({
        from: ''
      }).should.be.rejectedWith(/Missing required input/);
    });

    it('should reject no option to', function () {
      return myVault.reMount({
        from: 'xyz'
      }).should.be.rejectedWith(/Missing required input/);
    });

    it('should reject empty option to', function () {
      return myVault.reMount({
        from: 'xyz',
        to: ''
      }).should.be.rejectedWith(/Missing required input/);
    });

    it('should reject with an Error if not initialized or unsealed', function () {
      newVault.mounts = _.cloneDeep(myVault.mounts);
      return newVault.reMount({
        from: 'other',
        to: 'sample'
      }).should.be.rejectedWith(/Vault has not been initialized/);
    });

    it('should resolve to updated list of mounts (when slash provided)', function () {
      var existingMounts = _.cloneDeep(myVault.mounts);
      return myVault.reMount({
        from: 'other/',
        to: 'samplex'
      }).then(function (mounts) {
        debuglog(mounts);
        existingMounts.should.not.be.empty;
        mounts.should.not.be.empty;
        existingMounts.should.contain.keys('other/');
        existingMounts.should.not.contain.keys('samplex/');
        mounts.should.not.contain.keys('other/');
        mounts.should.contain.keys('samplex/');
      });
    });

    it('should resolve to updated list of mounts', function () {
      var existingMounts = _.cloneDeep(myVault.mounts);
      return myVault.reMount({
        from: 'samplex',
        to: 'sample'
      }).then(function (mounts) {
        debuglog(mounts);
        existingMounts.should.not.be.empty;
        mounts.should.not.be.empty;
        existingMounts.should.contain.keys('samplex/');
        existingMounts.should.not.contain.keys('sample/');
        mounts.should.not.contain.keys('samplex/');
        mounts.should.contain.keys('sample/');
      });
    });

  });

  describe('#deleteMount', function () {

    it('should reject with an Error if not initialized or unsealed', function () {
      return newVault.deleteMount({
        id: 'sample'
      }).should.be.rejectedWith(/Vault has not been initialized/);
    });

    it('should reject if no options provided', function () {
      return myVault.deleteMount()
        .should.be.rejectedWith(/requires an id/);
    });

    it('should reject if no option id provided', function () {
      return myVault.deleteMount({
        id: ''
      }).should.be.rejectedWith(/requires an id/);
    });

    it('should resolve to updated instance with mount removed', function () {
      var existingMounts = _.cloneDeep(myVault.mounts);
      return myVault.deleteMount({
        id: 'sample'
      }).then(function (mounts) {
        debuglog(mounts);
        existingMounts.should.not.be.empty;
        mounts.should.not.be.empty;
        existingMounts.should.contain.keys('sample/');
        mounts.should.not.contain.keys('sample/');
        mounts.should.contain.keys('sys/');
      });
    });

  });

  describe('#getMountTune', function() {
    var tuneMount;

    before(function (done) {
      myVault.createMount({
        id: 'tunemount',
        body: {
          type: 'generic'
        }
      }).then(function(mounts) {
        tuneMount = mounts['tunemount/'];
        done();
      })
    });

    after(function (done) {
      myVault.deleteMount({
        id: 'tunemount'
      }).then(function() {
        tuneMount = null;
        done();
      })
    });

    it('should reject with an Error if not initialized or unsealed', function () {
      newVault.getMountTune({
        id: 'something'
      }).should.be.rejectedWith(/Vault has not been initialized/);
    });

    it('should reject when no mount id is given', function () {
      myVault.getMountTune().should.be.rejected;
    });

    it('should reject when invalid mount id is given', function () {
      myVault.getMountTune({
        id: 'idontexist'
      }).should.be.rejected;
    });

    it('should return the tune config', function (done) {
      myVault.getMountTune({
        id: 'tunemount'
      }).then(function(config) {
        config.should.exist;
        config.should.be.an.instanceof(Object);
        config.should.have.keys('default_lease_ttl', 'max_lease_ttl');
        done();
      });
    });

  });

  describe('#tuneMount', function () {
    var tuneMount;

    beforeEach(function (done) {
      myVault.createMount({
        id: 'tunemount',
        body: {
          type: 'generic'
        }
      }).then(function(mounts) {
        tuneMount = mounts['tunemount/'];
        done();
      })
    });

    afterEach(function (done) {
      myVault.deleteMount({
        id: 'tunemount'
      }).then(function() {
        done();
      })
    });

    it('should reject with an Error if not initialized or unsealed', function () {
      newVault.tuneMount({
        id: 'something'
      }).should.be.rejectedWith(/Vault has not been initialized/);
    });

    it('should be rejected when the mount does not exist', function () {
      myVault.tuneMount({
        id: 'somethingwhichdoesntexist'
      }).should.be.rejected;
    });

    it('should return a promise which resolves to the mount with newly tuned config', function (done) {
      myVault.tuneMount({
        id: 'tunemount',
        body: {
          default_lease_ttl: '10m',
          max_lease_ttl: '20m'
        }
      }).then(function(mount) {
        mount.should.exist;
        mount.should.have.property('config');
        var config = mount.config;
        config.should.have.keys('default_lease_ttl','max_lease_ttl');
        config.default_lease_ttl.should.equal(10 * 60);
        config.max_lease_ttl.should.equal(20 * 60);
        done();
      });
    });

    it('should default to 0 when params are not sent to tune', function(done) {
      myVault.tuneMount({
        id: 'tunemount',
        body: {}
      }).then(function(mount) {
        mount.should.exist;
        mount.should.have.keys('config', 'description', 'type');
        mount.config.should.be.an.instanceof(Object);
        var config = mount.config
        config.should.have.keys('default_lease_ttl','max_lease_ttl');
        config.default_lease_ttl.should.equal(0);
        config.max_lease_ttl.should.equal(0);
        done();
      });
    });

    it('should reject when invalid values are sent for TTLs', function () {
      myVault.tuneMount({
        id: 'tunemount',
        body: {
          default_lease_ttl: 6000,
          max_lease_ttl: 4000
        }
      }).should.be.rejected;
    });

  });

});

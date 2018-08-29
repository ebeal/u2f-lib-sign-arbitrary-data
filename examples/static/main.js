var app = angular.module("App", []);

// Api service performs signature functions and stores the submitted data until signing
// For all calls the same username is used, for production this should be unique
app.service("ApiService", function($http) {
  var ApiService = {};

    /**
     * Register makes the http request to obtain the u2f enrollment request from server
     * @returns u2f request from server
     */
    ApiService.register = function() {
      var data = {username: 'testuser'}
      return $http({
        method: 'GET',
        url: '/enroll',
        params: data
      });
    },
    // After the u2f enrollment request is received it is signed by the u2f device
    // The response from the u2f device is returned to the server for confirmation
    ApiService.confirm = function(data) {
      var params = {username: 'testuser'};
      return $http({
        method:'POST',
        url: '/bind',
        params: params,
        data: data
      });
    },
    // Once a device is registered it can be used to sign
    // If there is submitted data the http request will be made with it
    // the server will take the submitted data, hash it with it's sha-256 fn and
    // it will return that as the challenge portion of the u2f request
    // if there is no submitted data the server will generate it's own data to use
    // for the challenge it returns in the u2f request
    ApiService.sign = function() {
      var params = {username: 'testuser'};
      var httpRequest = {
        method: 'POST',
        url: '/sign',
        params: params
      };
      if (ApiService.submittedData) {
        httpRequest.data = ApiService.submittedData;
      }
      return $http(httpRequest);
    },
    // The u2f device is then used to sign the u2f request from the server
    // the response from the u2f device is returned to the server for verification
    ApiService.verify = function(data) {
      var params = {username: 'testuser'}
      return $http({
        method: 'POST',
        url: '/verify',
        params: params,
        data: data
      });
    },
    ApiService.submitData = function(data) {
      ApiService.submittedData = data;
    }
  return ApiService;
});

app.controller("BaseCtrl", function($scope, U2fService, ApiService) {

  $scope.currentState = 'register';
  $scope.u2fRegisterService = new U2fService.register();
  $scope.u2fUnlockService = new U2fService.unlock();

  $scope.changeState = function(newState) {
    $scope.currentState = newState;
  };

  $scope.register = function() {
    $scope.showBlink = true;

    $scope.u2fRegisterService.start()
    .then(function(response) {
      console.log('Registration response from u2f device: ', response)
      $scope.verifiedU2f = true;
      $scope.showBlink = false;

      $scope.otpCode = response;
      $scope.confirmRegister();
    }).catch(function(error) {
      $scope.showBlink = false;
      $scope.registerError = error.message;
    });
  }

  $scope.confirmRegister = function() {
    ApiService.confirm($scope.otpCode)
    .then(function(response) {
      console.log('Registration confirmation response from requester (server): ', response);
      $scope.serverVerified = true;
    }).catch(function(error){
      $scope.showBlink = false;
      $scope.registerError = error.message;
    });
  }

  $scope.submitData = function() {
    ApiService.submitData($scope.arbitraryData);
    $scope.showBlink = true;
    $scope.u2fUnlockService.start()
    .then(function(u2fResponse) {
      console.log('Signature response from u2f device: ',u2fResponse);
      $scope.success = true;
      $scope.showBlink = false;
      $scope.confirmSign(u2fResponse);
    }).catch(function(error) {
      $scope.signError = error.message;
    });
  };

  $scope.confirmSign = function(u2fResponse) {
    ApiService.verify(u2fResponse)
    .then(function(verifyResponse) {
      console.log('Signature confirmation response from requester (server): ', verifyResponse);
      if(verifyResponse.status === 200) {
        $scope.signedData = JSON.stringify(JSON.parse(verifyResponse.config.data), null, 2);
      }
    }).catch(function (error) {
      $scope.signError = error.message;
    });
  }
});

app.factory('U2fService',
function (
  $q,
  ApiService
) {
  // Feature detection (yes really)
  var isBrowser = (typeof navigator !== 'undefined') && !!navigator.userAgent;
  var isSafari = isBrowser && navigator.userAgent.match(/Safari\//) &&
    !navigator.userAgent.match(/Chrome\//);
  var isEDGE = isBrowser && navigator.userAgent.match(/Edge\/1[2345]/);
  var _backend = null;
  function getBackend() {
    if (!_backend) {
      _backend = new Promise(function (resolve, reject) {
        function notSupported() {
          resolve({ u2f: null });
        }
        if (!isBrowser) { return notSupported(); }
        if (isSafari)
        // Safari doesn't support U2F, and the Safari-FIDO-U2F
        // extension lacks full support (Multi-facet apps), so we
        // block it until proper support.
        { return notSupported(); }
        var hasNativeSupport = (typeof window.u2f !== 'undefined') &&
          (typeof window.u2f.sign === 'function');
        if (hasNativeSupport) { return resolve({ u2f: window.u2f }); }
        if (isEDGE)
        // We don't want to check for Google's extension hack on EDGE
        // as it'll cause trouble (popups, etc)
        { return notSupported(); }
        if (location.protocol === 'http:')
        // U2F isn't supported over http, only https
        { return notSupported(); }
        if (typeof MessageChannel === 'undefined')
        // Unsupported browser, the chrome hack would throw
        { return notSupported(); }
        // Test for google extension support
        chromeApi.isSupported(function (ok) {
          if (ok) { resolve({ u2f: chromeApi }); }
          else { notSupported(); }
        });
      });
    }
    return _backend;
  }

  function isSupported() {
    return getBackend()
      .then(function (backend) { return !!backend.u2f; });
  }


  function _ensureSupport(backend) {
    if (!backend.u2f) {
      if (location.protocol === 'http:') {
        throw new Error('U2F isn\'t supported over http, only https');
      }
      throw new Error('U2F not supported');
    }
  }

  function ensureSupport() {
    return getBackend()
      .then(_ensureSupport);
  }

  function determineError(errorCode, ineligible) {
    switch (errorCode) {
      case 1:
        return 'There was a problem registering your U2F device.  Please try again';
      case 2:
        return 'There was a problem registering your U2F device.  Please try again';
      case 3:
        return 'There was a problem registering your U2F device.  Please try again';
      case 4:
        return ineligible || 'Incorrect device used. Please verify you have the correct device and try again';
      case 5:
        return 'Please touch the device to continue';
    }
  }

  // Attempt auto-retry generator function
  function attempt(action, ineligible) {
    var retry = function (action) {
      var self = this;
      return action().then(function (response) {
        /*jshint maxcomplexity:9 */
        if (self.canceled) {
          throw new Error('Device registration cancelled');
        }
        if (response.errorCode) {
          var errorMessage = determineError(response.errorCode, ineligible);
          throw new Error(errorMessage);
        }

        return JSON.stringify(response);
      });
    };
    return function () {
      var args = arguments;
      var run = function () {
        return action.apply(this, args);
      };
      return retry.call(this, run.bind(this));
    };
  }

  // Task runs until successful or canceled
  function U2fTask(action, ineligible) {
    this.action = action;
    this.ineligible = ineligible;
  }

  // Run executes the action
  U2fTask.prototype.run = function run() {
    return attempt.call(this, this.action, this.ineligible).apply(this, arguments);
  };

  // Cancel execution
  U2fTask.prototype.cancel = function cancel() {
    this.canceled = true;
  };

  // Service can be started, stopped and restarted again
  function U2fService(action, ineligible) {
    this.action = action;
    this.ineligible = ineligible;
  }

  // Start executing the action until successful, canceling pending action
  U2fService.prototype.start = function () {
    if (this.task) {
      this.task.cancel();
    }
    this.task = new U2fTask(this.action, this.ineligible);
    return this.task.run.apply(this.task, arguments);
  };

  // Stop executing
  U2fService.prototype.stop = function () {
    if (this.task) {
      this.task.cancel();
    }
  };

  // U2F Device registration service
  function U2fRegisterService() {
    U2fService.call(this, function () {
      return ApiService.register()
        .then(function (request) {
          console.log('Registration request from requester (server): ', request.data);
          request = request.data;
          return $q(function (resolve) {
            u2f.register(request.appId, request.registerRequests, request.registeredKeys, resolve, 20000);
          });
        });
    }, 'This device is already registered');
  }
  U2fRegisterService.prototype = Object.create(U2fService.prototype);
  U2fRegisterService.prototype.constructor = U2fRegisterService;

  // U2F Authentication service
  function U2fAuthService() {
    U2fService.call(this, function (request) {
      return request().then(function (request) {
        console.log('Signature request from requester (server): ', request.data);
        request = request.data;
        return $q(function (resolve) {
          u2f.sign(request.appId, request.challenge, request.registeredKeys, resolve, 20000);
        });
      });
    }, 'This device is not registered for this account, please register the device in user settings');
  }
  U2fAuthService.prototype = Object.create(U2fService.prototype);
  U2fAuthService.prototype.constructor = U2fAuthService;

  // U2F Unlock service
  function U2fUnlockService() {
    U2fAuthService.call(this);
  }
  U2fUnlockService.prototype = Object.create(U2fAuthService.prototype);
  U2fUnlockService.prototype.constructor = U2fUnlockService;
  U2fUnlockService.prototype.start = function () {
    return U2fAuthService.prototype.start.call(this, ApiService.sign);
  };

  return {
    register: U2fRegisterService,
    auth: U2fAuthService,
    unlock: U2fUnlockService,
    isSupported: isSupported,
    ensureSupport: ensureSupport
  };
});

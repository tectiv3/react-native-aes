'use strict';

var ReactNative = require('react-native');
var {
    NativeModules
} = ReactNative;

module.exports = NativeModules.Aes : {
    encrypt: (text, key, callback)=>callback(text),
    decrypt: (code, key, callback)=>callback(code),
};

'use strict';
import { NativeModules } from 'react-native';

module.exports = NativeModules.Aes : {
    encrypt: (text, key, callback)=>callback(cipher),
    decrypt: (code, key, callback)=>callback(text),
    generateKey: (password, callback)=>callback(key),
    hmac: (text, key, callback)=>callback(hash),
};

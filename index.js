'use strict';
import { NativeModules } from 'react-native';

module.exports = NativeModules.Aes : {
    encrypt: (text, key)    => cipher,
    decrypt: (code, key)    => text,
    generateKey: (password) => key,
    hmac: (text, key)       => hash,
};

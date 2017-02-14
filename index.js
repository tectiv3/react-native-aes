'use strict';
import { NativeModules } from 'react-native';

module.exports = NativeModules.Aes : {
    encrypt: (text, key)    => promise,
    decrypt: (code, key)    => promise,
    generateKey: (password) => promise,
    hmac: (text, key)       => promise,
    sha256: (text)          => promise,
};

# React Native AES

AES encryption/decryption for react-native

## Installation
```sh
npm install --save react-native-aes-crypto
```
### Installation (iOS)
* See [Linking Libraries](http://facebook.github.io/react-native/docs/linking-libraries-ios.html)
OR
* Drag RCTAes.xcodeproj to your project on Xcode.
* Click on your main project file (the one that represents the .xcodeproj) select Build Phases and drag libRCTAes.a from the Products folder inside the RCTAes.xcodeproj.

### Installation (Android)
#### Untested!
```gradle
...
include ':react-native-aes'
project(':react-native-aes').projectDir = new File(rootProject.projectDir, '../node_modules/react-native-aes/android/RCTAes')
```

* In `android/app/build.gradle`

```gradle
...
dependencies {
    ...
    compile project(':react-native-aes')
}
```

* register module (in MainApplication.java)

```java
......
import com.tectiv3.aes.RCTAesPackage;

......

@Override
protected List<ReactPackage> getPackages() {
   ......
   new RCTAesPackage(),
   ......
}
```

## Usage

### Example

```js
import { NativeModules, Platform } from 'react-native';
var Aes = NativeModules.Aes;


const generateKey = (password, salt) => {
    if (Platform.OS === 'ios') {
        return Aes.pbkdf2(password, salt);
    }
        
    return new Promise((resolve, reject) => {
        Aes.pbkdf2(password, salt, key => resolve(key), error => reject(error));
    });
};

const encrypt = (text, keyBase64) => {
    var ivBase64 = "base64 random 16 bytes string";
    if (Platform.OS === 'ios') {
        return Aes.encrypt(text, keyBase64, ivBase64).then(cipher => ({ cipher, iv: ivBase64 }));
    } else {
        return new Promise((resolve, reject) => {
            Aes.encrypt(text, keyBase64, ivBase64, cipher => resolve({ cipher, iv: ivBase64 }), error => reject(error));
        });
    }    
};

const decrypt = (encryptedData, key) => {
    if (Platform.OS === 'ios') {
        return Aes.decrypt(encryptedData.cipher, key, encryptedData.iv);
    } else {
        return new Promise((resolve, reject) => {
            Aes.decrypt(
                encryptedData.cipher, key, encryptedData.iv,
                decryptedData => resolve(decryptedData),
                error => reject(error)
            );
        });
    }    
};

try {
    generateKey("Arnold", "salt").then(key => {
        console.log('Key:', key);
        encrypt("These violent delights have violent ends", key).then(({cipher, iv}) => {
            console.log("Encrypted: ", cipher);
            
            decrypt({ cipher, iv }, key).then(text => {
                console.log("Decrypted:", text);
            });
            
            Aes.hmac256(cipher, key).then(hash => {
                console.log("HMAC", hash);
            });
        });
    });
} catch (e) {
    console.error(e);
}
```

#### Or

```js
async function asyncDecrypt(cipher, key, iv) {
    try {
        var text = await decrypt({ cipher, iv }, key);
        console.log(text);
        return text;
    } catch (e) {
        console.error(e);
    }
}
```

### methods

- `encrypt(text, key, iv)`
- `decrypt(base64, key, iv)`
- `pbkdf2(text, salt)`
- `hmac256(cipher, key)`
- `sha1(text)`
- `sha256(text)`
- `sha512(text)`

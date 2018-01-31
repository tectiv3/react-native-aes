# React Native AES

AES encryption/decryption for react-native

## Installation
```sh
npm install react-native-aes-crypto
```
or
```sh
yarn add react-native-aes-crypto
```
### Linking Automatically
```sh
react-native link
```
### Linking Manually

#### iOS
* See [Linking Libraries](http://facebook.github.io/react-native/docs/linking-libraries-ios.html)
OR
* Drag RCTAes.xcodeproj to your project on Xcode.
* Click on your main project file (the one that represents the .xcodeproj) select Build Phases and drag libRCTAes.a from the Products folder inside the RCTAes.xcodeproj.

#### (Android)
##### Untested!
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
import { Platform } from 'react-native';
import Aes from 'react-native-aes-crypto'

const generateKey = (password, salt) => Aes.pbkdf2(password, salt);

const encrypt = (text, keyBase64) => {
    var ivBase64 = "base64 random 16 bytes string";
    return Aes.encrypt(text, keyBase64, ivBase64).then(cipher => ({ cipher, iv: ivBase64 }));
};

const decrypt = (encryptedData, key) => Aes.decrypt(encryptedData.cipher, key, encryptedData.iv);

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

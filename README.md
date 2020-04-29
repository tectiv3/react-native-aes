# React Native AES

AES encryption/decryption for react-native

## Installation

```sh
npm install --save react-native-aes-crypto
```

or

```sh
yarn add react-native-aes-crypto
```

### Installation (iOS)

##### Using CocoaPods (React Native 0.60 and higher)

```sh
cd ios
pod install
```

##### Using React Native Link (React Native 0.59 and lower)

Run `react-native link react-native-aes-crypto` after which you should be able to use this library on iOS.

### Installation (Android)

##### React Native 0.60 and higher
- Linking is done automatically

##### Using React Native Link (React Native 0.59 and lower)
-   In `android/settings.gradle`

```gradle
...
include ':react-native-aes-crypto'
project(':react-native-aes-crypto').projectDir = new File(rootProject.projectDir, '../node_modules/react-native-aes-crypto/android')
```

-   In `android/app/build.gradle`

```gradle
...
dependencies {
    ...
    compile project(':react-native-aes-crypto')
}
```

-   register module (in MainApplication.java)

```java
......
import com.tectiv3.aes.RCTAesPackage;

......

@Override
protected List<ReactPackage> getPackages() {
   ......
   new RCTAesPackage(),
   // or 
   // packages.add(new RCTAesPackage());
   ......
}
```

## Usage

### Example

```js
import { NativeModules, Platform } from 'react-native'
var Aes = NativeModules.Aes

const generateKey = (password, salt, cost, length) => Aes.pbkdf2(password, salt, cost, length)

const encryptData = (text, key) => {
    return Aes.randomKey(16).then(iv => {
        return Aes.encrypt(text, key, iv).then(cipher => ({
            cipher,
            iv,
        }))
    })
}

const decryptData = (encryptedData, key) => Aes.decrypt(encryptedData.cipher, key, encryptedData.iv)

try {
    generateKey('Arnold', 'salt', 5000, 256).then(key => {
        console.log('Key:', key)
        encryptData('These violent delights have violent ends', key)
            .then(({ cipher, iv }) => {
                console.log('Encrypted:', cipher)

                decryptData({ cipher, iv }, key)
                    .then(text => {
                        console.log('Decrypted:', text)
                    })
                    .catch(error => {
                        console.log(error)
                    })

                Aes.hmac256(cipher, key).then(hash => {
                    console.log('HMAC', hash)
                })
            })
            .catch(error => {
                console.log(error)
            })
    })
} catch (e) {
    console.error(e)
}
```

#### Or

```js
async function asyncDecrypt(cipher, key, iv) {
    try {
        var text = await decryptData({ cipher, iv }, key)
        console.log(text)
        return text
    } catch (e) {
        console.error(e)
    }
}
```

### methods

-   `encrypt(text, key, iv)`
-   `decrypt(base64, key, iv)`
-   `pbkdf2(text, salt, cost, length)`
-   `hmac256(cipher, key)`
-   `sha1(text)`
-   `sha256(text)`
-   `sha512(text)`
-   `randomUuid()`
-   `randomKey(length)`

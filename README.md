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

-   Linking is done automatically

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

### Demo project

[link](https://github.com/tectiv3/react-native-aes-demo)

### Example

```js
import { NativeModules, Platform } from 'react-native'
import Aes from 'react-native-aes-crypto'

const generateKey = (password, salt, cost, length) => Aes.pbkdf2(password, salt, cost, length)

const encryptData = (text, key) => {
    return Aes.randomKey(16).then(iv => {
        return Aes.encrypt(text, key, iv, 'aes-256-cbc').then(cipher => ({
            cipher,
            iv,
        }))
    })
}

const decryptData = (encryptedData, key) => Aes.decrypt(encryptedData.cipher, key, encryptedData.iv, 'aes-256-cbc')

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

-   `encrypt(text, key, iv, algorithm)`
-   `decrypt(base64, key, iv, algorithm)`
-   `pbkdf2(text, salt, cost, length, algorithm)`
-   `hmac256(cipher, key)`
-   `hmac512(cipher, key)`
-   `sha1(text)`
-   `sha256(text)`
-   `sha512(text)`
-   `randomUuid()`
-   `randomKey(length)`

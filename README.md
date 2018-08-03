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
import AES from 'react-native-aes-crypto';

function generateKey(password, salt) {
    return AES.pbkdf2(password, salt);
}

async function encrypt(text, key) {
    const iv = 'base 64 random 16 bytes string';
    try {
        const ciphertext = await AES.encrypt(text, key, iv);
        return { ciphertext, iv };
    } catch (error) {
        throw error;
    }
}

function decrypt(ciphertext, key, iv) {
    return AES.decrypt(ciphertext, key, iv);
}

function hmac(ciphertext, key) {
    return AES.hmac256(ciphertext, key);
}

(async () => {
    try {
        const generatedKey = await generateKey('password', 'salt');
        console.log(`generatedKey: ${generatedKey}`);

        const { ciphertext, iv } = await encrypt('Hello, world!', generatedKey);
        console.log(`ciphertext: ${ciphertext}, iv: ${iv}`);

        const decryptedText = await decrypt(ciphertext, generatedKey, iv);
        console.log(`decrypted: ${decryptedText}`);

        const hash = await hmac(ciphertext, generatedKey);
        console.log(`hash: ${hash}`);
    } catch (error) {
        throw error;
    }
})();
```

### methods

- `encrypt(text, key, iv)`
- `decrypt(base64, key, iv)`
- `pbkdf2(text, salt)`
- `hmac256(cipher, key)`
- `sha1(text)`
- `sha256(text)`
- `sha512(text)`

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
import { NativeModules } from 'react-native';
var Aes = NativeModules.Aes;

try {
    Aes.generateKey("Arnold").then(key => {
        console.log('Key:', key);
        Aes.encrypt("These violent delights have violent ends", key).then(cipher => {
            console.log("Encrypted: ", cipher);
            Aes.decrypt(cipher, key).then(text => {
                console.log("Decrypted:", text);
            });
            Aes.hmac(cipher, key).then(hash => {
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
async function decrypt(cipher, key) {
    try {
        var text = await Aes.decrypt(cipher, key);
        console.log(text);
        return text;
    } catch (e) {
        console.error(e);
    }
}
```

### methods

- `encrypt(text, key)`
- `decrypt(base64, key)`
- `generateKey(text)`
- `hmac(cipher, key)`

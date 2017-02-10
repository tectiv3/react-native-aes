# React Native Aes

AES crypto for react-native

## Installation
```sh
npm install --save react-native-aes
```
### Installation (iOS)
* Drag RCTAes.xcodeproj to your project on Xcode.
* Click on your main project file (the one that represents the .xcodeproj) select Build Phases and drag libRCTAes.a from the Products folder inside the RCTAes.xcodeproj.
* Look for Header Search Paths and make sure it contains both $(SRCROOT)/../../../react-native/React as recursive.

### Installation (Android)
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
import com.tectiv3.aes.RCTAesPackage;  // <--- import

......

@Override
protected List<ReactPackage> getPackages() {
   ......
   new RCTAesPackage(),            // <------ add here
   ......
}


## Usage

### Example

```js
var Aes = require('react-native-aes');

Aes.encrypt("These violent delights have violent ends", "Arnold", function(base64) {
    console.log(base64);
    Aes.decrypt(base64, "Arnold", function(text) {
        console.log(text);
    }, function(){
        console.log("error");
    });
}, function() {
    console.log("error");
});
```

### method
- `encrypt(text, key, callback)`
- `encrypt(base64, key, callback)`


## Server Side
* see https://github.com/tectiv3/react-native-aes/blob/master/server
* support java, nodejs, js, php

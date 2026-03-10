# react-native-aes-crypto

## Purpose
A React Native native module providing AES encryption/decryption and related cryptographic functions for iOS and Android.

## Version
3.3.0

## Tech Stack
- **JS layer**: Minimal bridge — `index.js` exports `NativeModules.Aes`, TypeScript definitions in `index.d.ts`
- **iOS**: Objective-C (`.h`/`.m` files), CocoaPods distribution, minimum iOS 9.0 + visionOS 1.0
- **Android**: Java, Gradle build system
- **Package name**: `react-native-aes-crypto`

## API Surface
- `pbkdf2` / `pbkdf2Sync` — key derivation (sha1/sha256/sha512)
- `encrypt` / `decrypt` — AES-CBC and AES-CTR (128/192/256)
- `hmac256` / `hmac512` — HMAC signing
- `randomKey` / `randomUuid` — random generation
- `sha1` / `sha256` / `sha512` — hashing

## Codebase Structure
```
index.js          — JS bridge (re-exports NativeModules.Aes)
index.d.ts        — TypeScript type declarations
package.json      — npm package config
react-native-aes.podspec — CocoaPods spec

ios/
  Aes/
    Aes.h / Aes.m           — RN bridge module
    lib/
      AesCrypt.h / AesCrypt.m — Core crypto implementation
  Aes.xcodeproj/             — Xcode project

android/
  build.gradle
  src/main/java/com/tectiv3/aes/
    Aes.java          — RN bridge module
    AesPackage.java   — RN package registration
```

## Git
- Main branch: `master`
- Development branch: `develop`
- Current branch: `develop`

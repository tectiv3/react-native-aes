# Code Style and Conventions

## JavaScript
- Uses `'use strict'` and ES module imports
- Minimal JS — just a bridge re-export from NativeModules

## TypeScript Definitions
- Module-level function declarations (not class-based)
- Type aliases for algorithm enums

## Objective-C (iOS)
- Standard RN native module pattern with `RCT_EXPORT_METHOD`
- Separate bridge module (`Aes.m`) from implementation (`AesCrypt.m`)

## Java (Android)
- Standard RN `ReactContextBaseJavaModule` pattern
- Package: `com.tectiv3.aes`
- Separate bridge (`Aes.java`) from package registration (`AesPackage.java`)

## General
- No linting or formatting tools configured
- No automated tests
- MIT licensed

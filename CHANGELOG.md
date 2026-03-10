# Changelog

## [4.0.0] - 2026-03-10

### Breaking Changes
- Minimum React Native 0.75, iOS 13.0, Android API 23
- IV is now required — passing null/empty throws instead of using zeros
- `pbkdf2Sync` removed — use async `pbkdf2` instead
- CTR mode output changed from hex to base64 (now consistent with CBC)
- Unknown algorithm strings now throw instead of falling back silently
- Package now uses named exports alongside default export

### Security Fixes
- **CRITICAL**: Reject null/empty IV (previously fell back to all-zero IV)
- **CRITICAL**: Fix CTR mode padding (NoPadding instead of PKCS5/7)
- **HIGH**: Validate key length against algorithm selection
- **HIGH**: Strict algorithm whitelist — reject unknown values
- **MEDIUM**: PBKDF2 returns nil on error instead of empty string (iOS)
- **MEDIUM**: Enforce minimum PBKDF2 key length (128 bits)
- **MEDIUM**: Fix iOS CTR cryptor handle leak on error paths
- **MEDIUM**: Fix iOS CTR CCCryptorFinal buffer pointer arithmetic
- **LOW**: Fix Android shaX charset to explicit UTF-8
- **LOW**: Add malloc NULL checks for hash/HMAC buffers (iOS)

### Added
- AES-GCM authenticated encryption (`encryptGcm`, `decryptGcm`)
- TypeScript source with full type safety and input validation
- TurboModule support (React Native New Architecture)
- Codegen spec for type-safe native bridge
- JS-side input validation with descriptive error messages
- Security guidance in README
- Unit tests for input validation

### Changed
- Android rewritten in Kotlin
- Android: BouncyCastle replaces unmaintained SpongyCastle
- Android: compileSdk 34, minSdk 23
- iOS: deployment target 13.0
- Build system: react-native-builder-bob
- Proper error codes instead of generic "-1"

### Removed
- `pbkdf2Sync` (blocked JS thread)
- SpongyCastle dependency
- Legacy `react-native link` support
- `Aes.xcodeproj` (CocoaPods-only now)

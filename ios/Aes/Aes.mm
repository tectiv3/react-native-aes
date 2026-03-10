#import "Aes.h"
#import "AesCrypt.h"

@implementation Aes

RCT_EXPORT_MODULE()

+ (BOOL)requiresMainQueueSetup {
    return NO;
}

RCT_EXPORT_METHOD(encrypt:(NSString *)data key:(NSString *)key iv:(NSString *)iv algorithm:(NSString *)algorithm
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSString *base64 = [AesCrypt encrypt:data key:key iv:iv algorithm:algorithm];
    if (base64 == nil) {
        reject(@"encrypt_fail", @"Encrypt error", nil);
    } else {
        resolve(base64);
    }
}

RCT_EXPORT_METHOD(decrypt:(NSString *)base64 key:(NSString *)key iv:(NSString *)iv algorithm:(NSString *)algorithm
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSString *data = [AesCrypt decrypt:base64 key:key iv:iv algorithm:algorithm];
    if (data == nil) {
        reject(@"decrypt_fail", @"Decrypt failed", nil);
    } else {
        resolve(data);
    }
}

RCT_EXPORT_METHOD(pbkdf2:(NSString *)password salt:(NSString *)salt
                  cost:(NSInteger)cost length:(NSInteger)length algorithm:(NSString *)algorithm
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSString *data = [AesCrypt pbkdf2:password salt:salt cost:cost length:length algorithm:algorithm];
    if (data == nil) {
        reject(@"keygen_fail", @"Key generation failed", nil);
    } else {
        resolve(data);
    }
}

RCT_EXPORT_METHOD(hmac256:(NSString *)base64 key:(NSString *)key
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSString *data = [AesCrypt hmac256:base64 key:key];
    if (data == nil) {
        reject(@"hmac_fail", @"HMAC error", nil);
    } else {
        resolve(data);
    }
}

RCT_EXPORT_METHOD(hmac512:(NSString *)base64 key:(NSString *)key
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSString *data = [AesCrypt hmac512:base64 key:key];
    if (data == nil) {
        reject(@"hmac_fail", @"HMAC error", nil);
    } else {
        resolve(data);
    }
}

RCT_EXPORT_METHOD(sha1:(NSString *)text
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSString *data = [AesCrypt sha1:text];
    if (data == nil) {
        reject(@"sha1_fail", @"Hash error", nil);
    } else {
        resolve(data);
    }
}

RCT_EXPORT_METHOD(sha256:(NSString *)text
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSString *data = [AesCrypt sha256:text];
    if (data == nil) {
        reject(@"sha256_fail", @"Hash error", nil);
    } else {
        resolve(data);
    }
}

RCT_EXPORT_METHOD(sha512:(NSString *)text
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSString *data = [AesCrypt sha512:text];
    if (data == nil) {
        reject(@"sha512_fail", @"Hash error", nil);
    } else {
        resolve(data);
    }
}

RCT_EXPORT_METHOD(randomUuid:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSString *data = [AesCrypt randomUuid];
    if (data == nil) {
        reject(@"uuid_fail", @"Uuid error", nil);
    } else {
        resolve(data);
    }
}

RCT_EXPORT_METHOD(randomKey:(NSInteger)length
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSString *data = [AesCrypt randomKey:length];
    if (data == nil) {
        reject(@"random_fail", @"Random key error", nil);
    } else {
        resolve(data);
    }
}

RCT_EXPORT_METHOD(encryptGcm:(NSString *)data key:(NSString *)key iv:(NSString *)iv
                  aad:(NSString *)aad tagLength:(NSInteger)tagLength
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSString *result = [AesCrypt encryptGcm:data key:key iv:iv aad:aad tagLength:tagLength];
    if (result == nil) {
        reject(@"encrypt_gcm_fail", @"GCM encrypt error", nil);
    } else {
        resolve(result);
    }
}

RCT_EXPORT_METHOD(decryptGcm:(NSString *)ciphertext key:(NSString *)key iv:(NSString *)iv
                  aad:(NSString *)aad tagLength:(NSInteger)tagLength
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSString *result = [AesCrypt decryptGcm:ciphertext key:key iv:iv aad:aad tagLength:tagLength];
    if (result == nil) {
        reject(@"decrypt_gcm_fail", @"GCM decrypt error", nil);
    } else {
        resolve(result);
    }
}

#ifdef RCT_NEW_ARCH_ENABLED
- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
    return std::make_shared<facebook::react::NativeAesSpecJSI>(params);
}
#endif

@end

//
//  RCTAes.m
//  RCTAes
//
//  Created by tectiv3 on 10/02/17.
//  Copyright (c) 2017 tectiv3. All rights reserved.
//


#import "RCTAes.h"
#import "AesCrypt.h"

@implementation RCTAes

RCT_EXPORT_MODULE()

RCT_EXPORT_METHOD(encrypt:(NSString *)data key:(NSString *)key
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSString *base64 = [AesCrypt encrypt:data key:key];
    if (base64 == nil) {
        reject(@"encrypt_fail", @"Encrypt error", error);
    } else {
        resolve(base64);
    }
}

RCT_EXPORT_METHOD(decrypt:(NSString *)base64 key:(NSString *)key
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSString *data = [AesCrypt decrypt:base64 key:key];
    if (data == nil) {
        reject(@"decrypt_fail", @"Decrypt failed", error);
    } else {
        resolve(data);
    }
}

RCT_EXPORT_METHOD(generateKey:(NSString *)password
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSString *data = [AesCrypt generateKey:password];
    if (data == nil) {
        reject(@"keygen_fail", @"Key generation failed", error);
    } else {
        resolve(data);
    }
}

RCT_EXPORT_METHOD(hmac:(NSString *)base64 key:(NSString *)key
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSString *data = [AesCrypt hmac:base64 key:key];
    if (data == nil) {
        reject(@"hmac_fail", @"HMAC error", error);
    } else {
        resolve(data);
    }
}

@end

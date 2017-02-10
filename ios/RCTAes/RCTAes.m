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

RCT_EXPORT_METHOD(encrypt:(NSString *)data key:(NSString *)key success:(RCTResponseSenderBlock)success error:(RCTResponseSenderBlock)error) {
    NSString *base64 = [AesCrypt encrypt:data key:key];
    if (base64 == nil) {
        error(@[]);
    } else {
        success(@[base64]);
    }
}

RCT_EXPORT_METHOD(decrypt:(NSString *)base64 key:(NSString *)key success:(RCTResponseSenderBlock)success error:(RCTResponseSenderBlock)error) {
    NSString *data = [AesCrypt decrypt:base64 key:key];
    if (data == nil) {
        error(@[]);
    } else {
        success(@[data]);
    }
}

RCT_EXPORT_METHOD(generateKey:(NSString *)password success:(RCTResponseSenderBlock)success error:(RCTResponseSenderBlock)error) {
    NSString *data = [AesCrypt generateKey:password];
    if (data == nil) {
        error(@[]);
    } else {
        success(@[data]);
    }
}
@end

//
//  AesCrypt.m
//
//  Created by tectiv3 on 10/02/17.
//  Copyright © 2017 tectiv3. All rights reserved.
//

#import <CommonCrypto/CommonCryptor.h>
#import "AesCrypt.h"

@implementation AesCrypt

+ (NSString *) encrypt: (NSString *)clearText  key: (NSString *)key {
    char keyPtr[kCCKeySizeAES256 + 1]; // room for terminator (unused)
    bzero( keyPtr, sizeof(keyPtr) ); // fill with zeroes (for padding)

    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];

    const char *dataIn = [clearText UTF8String];

    size_t bufferSize = strlen(dataIn) + kCCBlockSizeAES128;
    void *buffer = calloc(bufferSize, sizeof(char));

    bzero(buffer, sizeof(buffer));
    size_t numBytesEncrypted = 0;

    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding, keyPtr, kCCKeySizeAES256, NULL, dataIn, strlen(dataIn), buffer, bufferSize, &numBytesEncrypted);

    NSString *result;
    if (cryptStatus == kCCSuccess) {
        NSData *nsdata = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesEncrypted];
        result = [nsdata base64EncodedStringWithOptions:0];
    } else {
        NSLog(@"%d", cryptStatus);
    }

    free(buffer);
    return result;
}

+ (NSString *) decrypt: (NSString *)cipherText key: (NSString *)key {

    char keyPtr[kCCKeySizeAES256 + 1]; // room for terminator (unused)
    bzero( keyPtr, sizeof(keyPtr) ); // fill with zeroes (for padding)

    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];

    NSData* cipherData = [[NSData alloc] initWithBase64EncodedString:cipherText options:0];
    NSUInteger dataLength = [cipherData length];

    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = calloc(bufferSize, sizeof(char));
    size_t numBytesDecrypted = 0;

    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding, keyPtr, kCCKeySizeAES256, NULL, [cipherData bytes], dataLength, buffer, bufferSize, &numBytesDecrypted);
    NSString* result = nil;

    if (cryptStatus == kCCSuccess) {
        NSData* data = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesDecrypted];
        result = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    } else {
        NSLog(@"%d", cryptStatus);
    }

    free(buffer);
    return result;
}

@end

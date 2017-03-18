//
//  AesCrypt.m
//
//  Created by tectiv3 on 10/02/17.
//  Copyright © 2017 tectiv3. All rights reserved.
//

#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonKeyDerivation.h>

#import "AesCrypt.h"

@implementation AesCrypt

+ (NSString *) toHex:(NSData *)nsdata {
    NSString * hexStr = [NSString stringWithFormat:@"%@", nsdata];
    
    for(NSString * toRemove in [NSArray arrayWithObjects:@"<", @">", @" ", nil])
        hexStr = [hexStr stringByReplacingOccurrencesOfString:toRemove withString:@""];
    
    return hexStr;
}

+ (NSString *) pbkdf2:(NSString *)password salt: (NSString *)salt {
    // Data of String to generate Hash key(hexa decimal string).
    NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
    NSData *saltData = [salt dataUsingEncoding:NSUTF8StringEncoding];

    // Hash key (hexa decimal) string data length.
    NSMutableData *hashKeyData = [NSMutableData dataWithLength:CC_SHA512_DIGEST_LENGTH];

    // Key Derivation using PBKDF2 algorithm.
    int status = CCKeyDerivationPBKDF(
                    kCCPBKDF2,
                    passwordData.bytes,
                    passwordData.length,
                    saltData.bytes,
                    saltData.length,
                    kCCPRFHmacAlgSHA512,
                    5000,
                    hashKeyData.mutableBytes,
                    hashKeyData.length);

    if (status == kCCParamError) {
        NSLog(@"Key derivation error");
        return @"";
    }

    return [self toHex:hashKeyData];
}

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
        NSLog(@"Encrypt error, %d", cryptStatus);
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
        NSLog(@"Decrypt error, %d", cryptStatus);
    }

    free(buffer);
    return result;
}

+ (NSString *) hmac: (NSString *)input key: (NSString *)key {
    NSData* keyData = [[NSData alloc] initWithBase64EncodedString:key options:0];
    NSData* inputData = [[NSData alloc] initWithBase64EncodedString:input options:0];
    void* buffer = malloc(CC_SHA1_DIGEST_LENGTH);
    CCHmac(kCCHmacAlgSHA1, [keyData bytes], [keyData length], [inputData bytes], [inputData length], buffer);
    NSData *nsdata = [NSData dataWithBytesNoCopy:buffer length:CC_SHA1_DIGEST_LENGTH freeWhenDone:YES];
    return [self toHex:nsdata];
}

+ (NSString *) sha256: (NSString *)input {
    NSData* inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char* buffer = malloc(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256([inputData bytes], (CC_LONG)[inputData length], buffer);
    NSData *nsdata = [NSData dataWithBytesNoCopy:buffer length:CC_SHA256_DIGEST_LENGTH freeWhenDone:YES];
    return [self toHex:nsdata];
}

+ (NSString *) sha512: (NSString *)input {
    NSData* inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char* buffer = malloc(CC_SHA512_DIGEST_LENGTH);
    CC_SHA512([inputData bytes], (CC_LONG)[inputData length], buffer);
    NSData *nsdata = [NSData dataWithBytesNoCopy:buffer length:CC_SHA512_DIGEST_LENGTH freeWhenDone:YES];
    return [self toHex:nsdata];
}

@end

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
    const unsigned char *bytes = (const unsigned char *)nsdata.bytes;
    NSMutableString *hex = [NSMutableString new];
    for (NSInteger i = 0; i < nsdata.length; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
    }
    return [hex copy];
}

+ (NSData *) fromHex: (NSString *)string {
    NSMutableData *data = [[NSMutableData alloc] init];
    unsigned char whole_byte;
    char byte_chars[3] = {'\0','\0','\0'};
    for (int i = 0; i < ([string length] / 2); i++) {
        byte_chars[0] = [string characterAtIndex:i*2];
        byte_chars[1] = [string characterAtIndex:i*2+1];
        whole_byte = strtol(byte_chars, NULL, 16);
        [data appendBytes:&whole_byte length:1];
    }
    return data;
}

+ (NSString *) pbkdf2:(NSString *)password salt: (NSString *)salt cost: (NSInteger)cost length: (NSInteger)length algorithm:(NSString *)algorithm {
    NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
    NSData *saltData = [salt dataUsingEncoding:NSUTF8StringEncoding];

    if (length < 128) {
        NSLog(@"PBKDF2 error: key length must be at least 128 bits");
        return nil;
    }

    NSMutableData *hashKeyData = [NSMutableData dataWithLength:length/8];

    CCPseudoRandomAlgorithm algorithmL;
    if ([algorithm.lowercaseString isEqualToString:@"sha1"]) {
        algorithmL = kCCPRFHmacAlgSHA1;
    } else if ([algorithm.lowercaseString isEqualToString:@"sha256"]) {
        algorithmL = kCCPRFHmacAlgSHA256;
    } else if ([algorithm.lowercaseString isEqualToString:@"sha512"]) {
        algorithmL = kCCPRFHmacAlgSHA512;
    } else {
        NSLog(@"PBKDF2 error: unsupported algorithm %@", algorithm);
        return nil;
    }

    int status = CCKeyDerivationPBKDF(
                    kCCPBKDF2,
                    passwordData.bytes,
                    passwordData.length,
                    saltData.bytes,
                    saltData.length,
                    algorithmL,
                    (unsigned int)cost,
                    hashKeyData.mutableBytes,
                    hashKeyData.length);

    if (status == kCCParamError) {
        NSLog(@"Key derivation error");
        return nil;
    }

    return [self toHex:hashKeyData];
}

+ (NSData *) AESCBC: (NSString *)operation data: (NSData *)data key: (NSString *)key iv: (NSString *)iv algorithm: (NSString *)algorithm {
    NSData *keyData = [self fromHex:key];
    NSData *ivData = [self fromHex:iv];

    if (ivData.length != kCCBlockSizeAES128) {
        NSLog(@"AES error: IV must be exactly 16 bytes, got %lu", (unsigned long)ivData.length);
        return nil;
    }

    NSArray *aesAlgorithms = @[@"aes-128-cbc", @"aes-192-cbc", @"aes-256-cbc"];
    size_t item = [aesAlgorithms indexOfObject:algorithm];
    size_t keyLength;
    switch (item) {
        case 0:
            keyLength = kCCKeySizeAES128;
            break;
        case 1:
            keyLength = kCCKeySizeAES192;
            break;
        default:
            keyLength = kCCKeySizeAES256;
            break;
    }

    if (keyData.length != keyLength) {
        NSLog(@"AES error: key length %lu does not match algorithm requirement %zu",
              (unsigned long)keyData.length, keyLength);
        return nil;
    }

    size_t numBytes = 0;
    NSMutableData *buffer = [[NSMutableData alloc] initWithLength:[data length] + kCCBlockSizeAES128];

    CCCryptorStatus cryptStatus = CCCrypt(
                                          [operation isEqualToString:@"encrypt"] ? kCCEncrypt : kCCDecrypt,
                                          kCCAlgorithmAES,
                                          kCCOptionPKCS7Padding,
                                          keyData.bytes, keyLength,
                                          ivData.bytes,
                                          data.bytes, data.length,
                                          buffer.mutableBytes, buffer.length,
                                          &numBytes);

    if (cryptStatus == kCCSuccess) {
        [buffer setLength:numBytes];
        return buffer;
    }
    NSLog(@"AES error, %d", cryptStatus);
    return nil;
}

+ (NSData *) AESCTR: (NSString *)operation data: (NSData *)data key: (NSString *)key iv: (NSString *)iv algorithm: (NSString *)algorithm {
    NSData *keyData = [self fromHex:key];
    NSData *ivData = [self fromHex:iv];

    if (ivData.length != kCCBlockSizeAES128) {
        NSLog(@"AES error: IV must be exactly 16 bytes, got %lu", (unsigned long)ivData.length);
        return nil;
    }

    NSArray *aesAlgorithms = @[@"aes-128-ctr", @"aes-192-ctr", @"aes-256-ctr"];
    size_t item = [aesAlgorithms indexOfObject:algorithm];
    size_t keyLength;
    switch (item) {
        case 0:  keyLength = kCCKeySizeAES128; break;
        case 1:  keyLength = kCCKeySizeAES192; break;
        default: keyLength = kCCKeySizeAES256; break;
    }

    if (keyData.length != keyLength) {
        NSLog(@"AES error: key length %lu does not match algorithm requirement %zu",
              (unsigned long)keyData.length, keyLength);
        return nil;
    }

    NSMutableData *buffer = [[NSMutableData alloc] initWithLength:[data length]];
    size_t numBytes = 0;

    CCCryptorRef cryptor = NULL;
    CCCryptorStatus createStatus = CCCryptorCreateWithMode(
        [operation isEqualToString:@"encrypt"] ? kCCEncrypt : kCCDecrypt,
        kCCModeCTR,
        kCCAlgorithmAES,
        ccNoPadding,
        ivData.bytes,
        keyData.bytes,
        keyLength,
        NULL, 0, 0,
        kCCModeOptionCTR_BE,
        &cryptor);

    if (createStatus != kCCSuccess) {
        NSLog(@"AES CTR error creating cryptor: %d", createStatus);
        return nil;
    }

    CCCryptorStatus updateStatus = CCCryptorUpdate(
        cryptor, data.bytes, data.length,
        buffer.mutableBytes, buffer.length, &numBytes);

    if (updateStatus != kCCSuccess) {
        CCCryptorRelease(cryptor);
        NSLog(@"AES CTR error during update: %d", updateStatus);
        return nil;
    }

    size_t finalBytes = 0;
    CCCryptorStatus finalStatus = CCCryptorFinal(
        cryptor,
        buffer.mutableBytes + numBytes,
        buffer.length - numBytes,
        &finalBytes);

    CCCryptorRelease(cryptor);

    if (finalStatus != kCCSuccess) {
        NSLog(@"AES CTR error during final: %d", finalStatus);
        return nil;
    }

    buffer.length = numBytes + finalBytes;
    return buffer;
}

+ (NSString *) encrypt: (NSString *)clearText key: (NSString *)key iv: (NSString *)iv algorithm: (NSString *)algorithm {
    NSSet *cbcAlgorithms = [NSSet setWithArray:@[@"aes-128-cbc", @"aes-192-cbc", @"aes-256-cbc"]];
    NSSet *ctrAlgorithms = [NSSet setWithArray:@[@"aes-128-ctr", @"aes-192-ctr", @"aes-256-ctr"]];

    if ([ctrAlgorithms containsObject:algorithm]) {
        NSData *result = [self AESCTR:@"encrypt" data:[clearText dataUsingEncoding:NSUTF8StringEncoding] key:key iv:iv algorithm:algorithm];
        return [result base64EncodedStringWithOptions:0];
    } else if ([cbcAlgorithms containsObject:algorithm]) {
        NSData *result = [self AESCBC:@"encrypt" data:[clearText dataUsingEncoding:NSUTF8StringEncoding] key:key iv:iv algorithm:algorithm];
        return [result base64EncodedStringWithOptions:0];
    }
    return nil;
}

+ (NSString *) decrypt: (NSString *)cipherText key: (NSString *)key iv: (NSString *)iv algorithm: (NSString *)algorithm {
    NSSet *ctrAlgorithms = [NSSet setWithArray:@[@"aes-128-ctr", @"aes-192-ctr", @"aes-256-ctr"]];
    NSSet *cbcAlgorithms = [NSSet setWithArray:@[@"aes-128-cbc", @"aes-192-cbc", @"aes-256-cbc"]];

    NSData *cipherData = [[NSData alloc] initWithBase64EncodedString:cipherText options:0];
    if (!cipherData) return nil;

    if ([ctrAlgorithms containsObject:algorithm]) {
        NSData *result = [self AESCTR:@"decrypt" data:cipherData key:key iv:iv algorithm:algorithm];
        return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
    } else if ([cbcAlgorithms containsObject:algorithm]) {
        NSData *result = [self AESCBC:@"decrypt" data:cipherData key:key iv:iv algorithm:algorithm];
        return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
    }
    return nil;
}

+ (NSString *) hmac256: (NSString *)input key: (NSString *)key {
    NSData *keyData = [self fromHex:key];
    NSData *inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    void *buffer = malloc(CC_SHA256_DIGEST_LENGTH);
    if (buffer == NULL) {
        return nil;
    }
    CCHmac(kCCHmacAlgSHA256, [keyData bytes], [keyData length], [inputData bytes], [inputData length], buffer);
    NSData *nsdata = [NSData dataWithBytesNoCopy:buffer length:CC_SHA256_DIGEST_LENGTH freeWhenDone:YES];
    return [self toHex:nsdata];
}

+ (NSString *) hmac512: (NSString *)input key: (NSString *)key {
    NSData *keyData = [self fromHex:key];
    NSData *inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    void *buffer = malloc(CC_SHA512_DIGEST_LENGTH);
    if (buffer == NULL) {
        return nil;
    }
    CCHmac(kCCHmacAlgSHA512, [keyData bytes], [keyData length], [inputData bytes], [inputData length], buffer);
    NSData *nsdata = [NSData dataWithBytesNoCopy:buffer length:CC_SHA512_DIGEST_LENGTH freeWhenDone:YES];
    return [self toHex:nsdata];
}

+ (NSString *) sha1: (NSString *)input {
    NSData *inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *result = [[NSMutableData alloc] initWithLength:CC_SHA1_DIGEST_LENGTH];
    CC_SHA1([inputData bytes], (CC_LONG)[inputData length], result.mutableBytes);
    return [self toHex:result];
}

+ (NSString *) sha256: (NSString *)input {
    NSData *inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char *buffer = malloc(CC_SHA256_DIGEST_LENGTH);
    if (buffer == NULL) {
        return nil;
    }
    CC_SHA256([inputData bytes], (CC_LONG)[inputData length], buffer);
    NSData *result = [NSData dataWithBytesNoCopy:buffer length:CC_SHA256_DIGEST_LENGTH freeWhenDone:YES];
    return [self toHex:result];
}

+ (NSString *) sha512: (NSString *)input {
    NSData *inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char *buffer = malloc(CC_SHA512_DIGEST_LENGTH);
    if (buffer == NULL) {
        return nil;
    }
    CC_SHA512([inputData bytes], (CC_LONG)[inputData length], buffer);
    NSData *result = [NSData dataWithBytesNoCopy:buffer length:CC_SHA512_DIGEST_LENGTH freeWhenDone:YES];
    return [self toHex:result];
}

+ (NSString *) encryptGcm:(NSString *)clearText key:(NSString *)key iv:(NSString *)iv
                       aad:(NSString *)aad tagLength:(NSInteger)tagLengthBits {
    NSData *keyData = [self fromHex:key];
    NSData *ivData = [self fromHex:iv];
    NSData *aadData = [aad dataUsingEncoding:NSUTF8StringEncoding];
    NSData *plainData = [clearText dataUsingEncoding:NSUTF8StringEncoding];

    if (keyData.length != 16 && keyData.length != 24 && keyData.length != 32) {
        NSLog(@"AES-GCM error: key must be 16, 24, or 32 bytes");
        return nil;
    }
    if (ivData.length != 12) {
        NSLog(@"AES-GCM error: IV must be exactly 12 bytes, got %lu", (unsigned long)ivData.length);
        return nil;
    }

    size_t tagLength = tagLengthBits / 8;
    NSMutableData *cipherData = [NSMutableData dataWithLength:plainData.length];
    NSMutableData *tagData = [NSMutableData dataWithLength:tagLength];

    CCCryptorStatus status = CCCryptorGCMOneshotEncrypt(
        kCCAlgorithmAES,
        keyData.bytes, keyData.length,
        ivData.bytes, ivData.length,
        aadData.bytes, aadData.length,
        plainData.bytes, plainData.length,
        cipherData.mutableBytes,
        tagData.mutableBytes, tagLength);

    if (status != kCCSuccess) {
        NSLog(@"AES-GCM encrypt error: %d", status);
        return nil;
    }

    NSMutableData *result = [NSMutableData dataWithData:cipherData];
    [result appendData:tagData];
    return [result base64EncodedStringWithOptions:0];
}

+ (NSString *) decryptGcm:(NSString *)cipherText key:(NSString *)key iv:(NSString *)iv
                       aad:(NSString *)aad tagLength:(NSInteger)tagLengthBits {
    NSData *keyData = [self fromHex:key];
    NSData *ivData = [self fromHex:iv];
    NSData *aadData = [aad dataUsingEncoding:NSUTF8StringEncoding];
    NSData *combined = [[NSData alloc] initWithBase64EncodedString:cipherText options:0];

    if (!combined) return nil;

    if (keyData.length != 16 && keyData.length != 24 && keyData.length != 32) {
        NSLog(@"AES-GCM error: key must be 16, 24, or 32 bytes");
        return nil;
    }
    if (ivData.length != 12) {
        NSLog(@"AES-GCM error: IV must be exactly 12 bytes, got %lu", (unsigned long)ivData.length);
        return nil;
    }

    size_t tagLength = tagLengthBits / 8;
    if (combined.length < tagLength) {
        NSLog(@"AES-GCM error: ciphertext too short for tag");
        return nil;
    }

    NSUInteger cipherLength = combined.length - tagLength;
    NSData *cipherData = [combined subdataWithRange:NSMakeRange(0, cipherLength)];
    NSData *tagData = [combined subdataWithRange:NSMakeRange(cipherLength, tagLength)];

    NSMutableData *plainData = [NSMutableData dataWithLength:cipherLength];

    CCCryptorStatus status = CCCryptorGCMOneshotDecrypt(
        kCCAlgorithmAES,
        keyData.bytes, keyData.length,
        ivData.bytes, ivData.length,
        aadData.bytes, aadData.length,
        cipherData.bytes, cipherData.length,
        plainData.mutableBytes,
        tagData.bytes, tagLength);

    if (status != kCCSuccess) {
        NSLog(@"AES-GCM decrypt error: %d", status);
        return nil;
    }

    return [[NSString alloc] initWithData:plainData encoding:NSUTF8StringEncoding];
}

+ (NSString *) randomUuid {
    return [[NSUUID UUID] UUIDString];
}

+ (NSString *) randomKey: (NSInteger)length {
    NSMutableData *data = [NSMutableData dataWithLength:length];
    int result = SecRandomCopyBytes(kSecRandomDefault, length, data.mutableBytes);
    if (result != noErr) {
        return nil;
    }
    return [self toHex:data];
}

@end

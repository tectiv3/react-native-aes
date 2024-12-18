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

+ (NSString *) pbkdf2:(NSString *)password salt: (NSString *)salt cost: (NSInteger)cost length: (NSInteger)length algorithm:(NSString *)algorithm{
    // Data of String to generate Hash key(hexa decimal string).
    NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
    NSData *saltData = [salt dataUsingEncoding:NSUTF8StringEncoding];

    // Hash key (hexa decimal) string data length.
    NSMutableData *hashKeyData = [NSMutableData dataWithLength:length/8];

    CCPseudoRandomAlgorithm algorithmL = kCCPRFHmacAlgSHA512;
    if([algorithm.lowercaseString isEqualToString:@"sha1"]){
        algorithmL = kCCPRFHmacAlgSHA1;
    }
    if([algorithm.lowercaseString isEqualToString:@"sha256"]){
        algorithmL = kCCPRFHmacAlgSHA256;
    }
    if([algorithm.lowercaseString isEqualToString:@"sha512"]){
        algorithmL = kCCPRFHmacAlgSHA512;
    }
    // Key Derivation using PBKDF2 algorithm.
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
        return @"";
    }

    return [self toHex:hashKeyData];
}

+ (NSData *) AESCBC: (NSString *)operation data: (NSData *)data key: (NSString *)key iv: (NSString *)iv algorithm: (NSString *)algorithm {
    //convert hex string to hex data
    NSData *keyData = [self fromHex:key];
    NSData *ivData = [self fromHex:iv];
    //    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    size_t numBytes = 0;
    
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

    NSMutableData * buffer = [[NSMutableData alloc] initWithLength:[data length] + kCCBlockSizeAES128];

    CCCryptorStatus cryptStatus = CCCrypt(
                                          [operation isEqualToString:@"encrypt"] ? kCCEncrypt : kCCDecrypt,
                                          kCCAlgorithmAES,
                                          kCCOptionPKCS7Padding,
                                          keyData.bytes, keyLength,
                                          ivData.length ? ivData.bytes : nil,
                                          data.bytes, data.length,
                                          buffer.mutableBytes,  buffer.length,
                                          &numBytes);

    if (cryptStatus == kCCSuccess) {
        [buffer setLength:numBytes];
        return buffer;
    }
    NSLog(@"AES error, %d", cryptStatus);
    return nil;
}

+ (NSData *) AESCTR: (NSString *)operation data: (NSData *)data key: (NSString *)key iv: (NSString *)iv algorithm: (NSString *)algorithm {
    //convert hex string to hex data
    NSData *keyData = [self fromHex:key];
    NSData *ivData = [self fromHex:iv];
    //    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    size_t numBytes = 0;
    
    NSArray *aesAlgorithms = @[@"aes-128-ctr", @"aes-192-ctr", @"aes-256-ctr"];
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

    NSMutableData * buffer = [[NSMutableData alloc] initWithLength:[data length] + kCCBlockSizeAES128];
    
    CCCryptorRef cryptor = NULL;
    
    CCCryptorStatus cryptStatus = CCCryptorCreateWithMode(
                    [operation isEqualToString:@"encrypt"] ? kCCEncrypt : kCCDecrypt,
                    kCCModeCTR,
                    kCCAlgorithmAES,
                    ccPKCS7Padding,
                    ivData.length ? ivData.bytes : nil,
                    keyData.bytes,
                    keyLength,
                    NULL,
                    0,
                    0,
                    kCCModeOptionCTR_BE,
                    &cryptor);

    if (cryptStatus == kCCSuccess) {
            //Update Cryptor
            CCCryptorStatus update = CCCryptorUpdate(cryptor,
                    data.bytes,
                    data.length,
                    buffer.mutableBytes,
                    buffer.length,
                    &numBytes);
            if (update == kCCSuccess)
            {
             //Cut Data Out with nedded length
                buffer.length = numBytes;

             //Final Cryptor
             CCCryptorStatus final = CCCryptorFinal(cryptor, //CCCryptorRef cryptorRef,
                                                    buffer.mutableBytes, //void *dataOut,
                                                    buffer.length, // size_t dataOutAvailable,
                                                    &numBytes); // size_t *dataOutMoved)

             if (final == kCCSuccess)
             {
              //Release Cryptor
              //CCCryptorStatus release =
              CCCryptorRelease(cryptor); //CCCryptorRef cryptorRef
             }
             return buffer;
        }
    }
    NSLog(@"AES error, %d", cryptStatus);
    return nil;
}

+ (NSString *) encrypt: (NSString *)clearText key: (NSString *)key iv: (NSString *)iv algorithm: (NSString *)algorithm {
    if ([algorithm containsString:@"ctr"]) {
        NSData *result = [self AESCTR:@"encrypt" data:[clearText dataUsingEncoding:NSUTF8StringEncoding] key:key iv:iv algorithm:algorithm];
        return [self toHex:result];
    }
    else{
        NSData *result = [self AESCBC:@"encrypt" data:[clearText dataUsingEncoding:NSUTF8StringEncoding] key:key iv:iv algorithm:algorithm];
        return [result base64EncodedStringWithOptions:0];
    }
}

+ (NSString *) decrypt: (NSString *)cipherText key: (NSString *)key iv: (NSString *)iv algorithm: (NSString *)algorithm {
    if ([algorithm containsString:@"ctr"]) {
        NSData *result = [self AESCTR:@"decrypt" data:[self fromHex:cipherText] key:key iv:iv algorithm:algorithm];
        return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
    }
    else{
        NSData *result = [self AESCBC:@"decrypt" data:[[NSData alloc] initWithBase64EncodedString:cipherText options:0] key:key iv:iv algorithm:algorithm];
        return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
    }
}

+ (NSString *) hmac256: (NSString *)input key: (NSString *)key {
    NSData *keyData = [self fromHex:key];
    NSData* inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    void* buffer = malloc(CC_SHA256_DIGEST_LENGTH);
    CCHmac(kCCHmacAlgSHA256, [keyData bytes], [keyData length], [inputData bytes], [inputData length], buffer);
    NSData *nsdata = [NSData dataWithBytesNoCopy:buffer length:CC_SHA256_DIGEST_LENGTH freeWhenDone:YES];
    return [self toHex:nsdata];
}

+ (NSString *) hmac512: (NSString *)input key: (NSString *)key {
    NSData *keyData = [self fromHex:key];
    NSData* inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    void* buffer = malloc(CC_SHA512_DIGEST_LENGTH);
    CCHmac(kCCHmacAlgSHA512, [keyData bytes], [keyData length], [inputData bytes], [inputData length], buffer);
    NSData *nsdata = [NSData dataWithBytesNoCopy:buffer length:CC_SHA512_DIGEST_LENGTH freeWhenDone:YES];
    return [self toHex:nsdata];
}

+ (NSString *) sha1: (NSString *)input {
    NSData* inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *result = [[NSMutableData alloc] initWithLength:CC_SHA1_DIGEST_LENGTH];
    CC_SHA1([inputData bytes], (CC_LONG)[inputData length], result.mutableBytes);
    return [self toHex:result];
}

+ (NSString *) sha256: (NSString *)input {
    NSData* inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char* buffer = malloc(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256([inputData bytes], (CC_LONG)[inputData length], buffer);
    NSData *result = [NSData dataWithBytesNoCopy:buffer length:CC_SHA256_DIGEST_LENGTH freeWhenDone:YES];
    return [self toHex:result];
}

+ (NSString *) sha512: (NSString *)input {
    NSData* inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char* buffer = malloc(CC_SHA512_DIGEST_LENGTH);
    CC_SHA512([inputData bytes], (CC_LONG)[inputData length], buffer);
    NSData *result = [NSData dataWithBytesNoCopy:buffer length:CC_SHA512_DIGEST_LENGTH freeWhenDone:YES];
    return [self toHex:result];
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

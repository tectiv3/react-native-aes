//
//  AesCrypt.h
//
//  Created by tectiv3 on 10/02/17.
//  Copyright © 2017 tectiv3. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface AesCrypt : NSObject
+ (NSString *) encrypt: (NSString *)clearText  key: (NSString *)key iv: (NSString *)iv algorithm: (NSString *)algorithm;
+ (NSString *) decrypt: (NSString *)cipherText key: (NSString *)key iv: (NSString *)iv algorithm: (NSString *)algorithm;
+ (NSString *) pbkdf2:(NSString *)password salt: (NSString *)salt cost: (NSInteger)cost length: (NSInteger)length algorithm:(NSString *)algorithm;
+ (NSString *) hmac256: (NSString *)input key: (NSString *)key;
+ (NSString *) hmac512: (NSString *)input key: (NSString *)key;
+ (NSString *) sha1: (NSString *)input;
+ (NSString *) sha256: (NSString *)input;
+ (NSString *) sha512: (NSString *)input;
+ (NSString *) toHex: (NSData *)nsdata;
+ (NSString *) randomUuid;
+ (NSString *) randomKey: (NSInteger)length;
@end

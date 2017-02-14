//
//  AesCrypt.h
//
//  Created by tectiv3 on 10/02/17.
//  Copyright © 2017 tectiv3. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface AesCrypt : NSObject
+ (NSString *) encrypt: (NSString *)clearText  key: (NSString *)key;
+ (NSString *) decrypt: (NSString *)cipherText key: (NSString *)key;
+ (NSString *) generateKey: (NSString *)password;
+ (NSString *) hmac: (NSString *)input key: (NSString *)key;
+ (NSString *) sha256: (NSString *)input;
@end

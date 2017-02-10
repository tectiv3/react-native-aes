//
//  AesCrypt.h
//  crypt
//
//  Created by Fenrir on 10/02/17.
//  Copyright © 2017 Fenrir. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface AesCrypt : NSObject
+ (NSString *) encrypt: (NSString *)clearText  key: (NSString *)key;
+ (NSString *) decrypt: (NSString *)cipherText key: (NSString *)key;
@end

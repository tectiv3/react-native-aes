#import <React/RCTBridgeModule.h>

#ifdef RCT_NEW_ARCH_ENABLED
#import <RNAesSpec/RNAesSpec.h>
#endif

#ifdef RCT_NEW_ARCH_ENABLED
@interface Aes : NSObject <NativeAesSpec>
#else
@interface Aes : NSObject <RCTBridgeModule>
#endif

@end

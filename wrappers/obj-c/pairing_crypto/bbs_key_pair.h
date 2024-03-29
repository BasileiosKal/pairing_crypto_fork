#ifndef bbs_key_pair_h
#define bbs_key_pair_h

/** @brief BBS key pair */
@interface PCLBbsKeyPair : NSObject

/** @brief secret key */
@property(strong, atomic, readwrite) NSData *_Nullable secretKey;

/** @brief public key */
@property(strong, atomic, readwrite) NSData *_Nullable publicKey;

/**
 * @brief Generates a new BBS BLS 12-381 key pair by using an IKM and optionally supplied key-info
 */
- (nullable instancetype)initWithIkm:(NSData *_Nullable)ikm
                             keyInfo:(NSData *_Nullable)keyInfo
                           withError:(NSError *_Nullable *_Nullable)errorPtr;

- (void)generateKeyPair:(NSData *_Nullable)ikm
                keyInfo:(NSData *_Nullable)keyInfo
              withError:(NSError *_Nullable *_Nullable)errorPtr;

@end

#endif /* bbs_key_pair_h */

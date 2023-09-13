package com.tectiv3.aes;

import android.widget.Toast;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import java.util.UUID;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.InvalidKeyException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.Mac;

import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.digests.SHA512Digest;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.util.encoders.Hex;

import android.util.Base64;

import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Callback;

public class RCTAes extends ReactContextBaseJavaModule {

    private static final String CIPHER_CBC_ALGORITHM = "AES/CBC/PKCS7Padding";
    private static final String CIPHER_CTR_ALGORITHM = "AES/CTR/PKCS5Padding";
    public static final String HMAC_SHA_256 = "HmacSHA256";
    public static final String HMAC_SHA_512 = "HmacSHA512";
    private static final String KEY_ALGORITHM = "AES";

    public RCTAes(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "RCTAes";
    }

    @ReactMethod
    public void encrypt(String data, String key, String iv, String algorithm, Promise promise) {
        try {
            String result = encrypt(data, key, iv, algorithm.toLowerCase().contains("cbc")?CIPHER_CBC_ALGORITHM:CIPHER_CTR_ALGORITHM);
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void decrypt(String data, String pwd, String iv, String algorithm, Promise promise) {
        try {
            String strs = decrypt(data, pwd, iv, algorithm.toLowerCase().contains("cbc")?CIPHER_CBC_ALGORITHM:CIPHER_CTR_ALGORITHM);
            promise.resolve(strs);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    public String pbkdf2Sync(String pwd, String salt, Integer cost, Integer length, String algorithm) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException {
        return pbkdf2(pwd, salt, cost, length, algorithm);
    }

    @ReactMethod
    public void pbkdf2(String pwd, String salt, Integer cost, Integer length, String algorithm, Promise promise) {
        try {
            String strs = pbkdf2(pwd, salt, cost, length, algorithm);
            promise.resolve(strs);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void hmac256(String data, String pwd, Promise promise) {
        try {
            String strs = hmacX(data, pwd, HMAC_SHA_256);
            promise.resolve(strs);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void hmac512(String data, String pwd, Promise promise) {
        try {
            String strs = hmacX(data, pwd, HMAC_SHA_512);
            promise.resolve(strs);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void sha256(String data, Promise promise) {
        try {
            String result = shaX(data, "SHA-256");
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void sha1(String data, Promise promise) {
        try {
            String result = shaX(data, "SHA-1");
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void sha512(String data, Promise promise) {
        try {
            String result = shaX(data, "SHA-512");
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void randomUuid(Promise promise) {
        try {
            String result = UUID.randomUUID().toString();
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void randomKey(Integer length, Promise promise) {
        try {
            byte[] key = new byte[length];
            SecureRandom rand = new SecureRandom();
            rand.nextBytes(key);
            String keyHex = bytesToHex(key);
            promise.resolve(keyHex);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    private String shaX(String data, String algorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        md.update(data.getBytes());
        byte[] digest = md.digest();
        return bytesToHex(digest);
    }

    public static String bytesToHex(byte[] bytes) {
        final char[] hexArray = "0123456789abcdef".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
    private static String pbkdf2(String pwd, String salt, Integer cost, Integer length, String algorithm)
    throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException
    {
        Digest algorithmDigest = new SHA512Digest();
        if (algorithm.equalsIgnoreCase("sha1")){
            algorithmDigest = new SHA1Digest();
        }
        if (algorithm.equalsIgnoreCase("sha256")){
            algorithmDigest = new SHA256Digest();
        }
        if (algorithm.equalsIgnoreCase("sha512")){
            algorithmDigest = new SHA512Digest();
        }
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(algorithmDigest);
        gen.init(pwd.getBytes("UTF_8"), salt.getBytes("UTF_8"), cost);
        byte[] key = ((KeyParameter) gen.generateDerivedParameters(length)).getKey();
        return bytesToHex(key);
    }

    private static String hmacX(String text, String key, String algorithm)
    throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException
    {
        byte[] contentData = text.getBytes("UTF_8");
        byte[] akHexData = Hex.decode(key);
        Mac sha_HMAC = Mac.getInstance(algorithm);
        SecretKey secret_key = new SecretKeySpec(akHexData, algorithm);
        sha_HMAC.init(secret_key);
        return bytesToHex(sha_HMAC.doFinal(contentData));
    }

    final static IvParameterSpec emptyIvSpec = new IvParameterSpec(new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});

    private static String encrypt(String text, String hexKey, String hexIv, String algorithm) throws Exception {
        if (text == null || text.length() == 0) {
            return null;
        }

        byte[] key = Hex.decode(hexKey);
        SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, hexIv == null ? emptyIvSpec : new IvParameterSpec(Hex.decode(hexIv)));
        byte[] encrypted = cipher.doFinal(text.getBytes("UTF-8"));
        return Base64.encodeToString(encrypted, Base64.NO_WRAP);
    }

    private static String decrypt(String ciphertext, String hexKey, String hexIv, String algorithm) throws Exception {
        if(ciphertext == null || ciphertext.length() == 0) {
            return null;
        }

        byte[] key = Hex.decode(hexKey);
        SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, hexIv == null ? emptyIvSpec : new IvParameterSpec(Hex.decode(hexIv)));
        byte[] decrypted = cipher.doFinal(Base64.decode(ciphertext, Base64.NO_WRAP));
        return new String(decrypted, "UTF-8");
    }

}

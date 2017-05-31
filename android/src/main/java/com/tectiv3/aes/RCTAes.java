package com.tectiv3.aes;

import android.widget.Toast;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import android.util.Base64;

import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Callback;

public class RCTAes extends ReactContextBaseJavaModule {

    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS7Padding";
    private static final String KEY_ALGORITHM = "AES";
    private static final String SECRET_KEY_ALGORITHM = "PBEWithSHA256And256BitAES-CBC-BC";

    public RCTAes(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "RCTAes";
    }

    @ReactMethod
    public void encrypt(String data, String keyBase64, String ivBase64, Callback success, Callback error) {
        try {
            String result = encrypt(data, keyBase64, ivBase64);
            success.invoke(result);
        } catch (Exception e) {
            error.invoke(e.getMessage());
        }
    }

    @ReactMethod
    public void decrypt(String data, String pwd, String iv, Callback success, Callback error) {
        try {
            String strs = decrypt(data, pwd, iv);
            success.invoke(strs);
        } catch (Exception e) {
            error.invoke(e.getMessage());
        }
    }

    @ReactMethod
    public void pbkdf2(String pwd, String salt, Callback success, Callback error) {
        try {
            String strs = pbkdf2(pwd, salt);
            success.invoke(strs);
        } catch (Exception e) {
            error.invoke(e.getMessage());
        }
    }

    @ReactMethod
    public void hmac256(String data, String pwd, Callback success, Callback error) {
        try {
            String strs = hmac256(data, pwd);
            success.invoke(strs);
        } catch (Exception e) {
            error.invoke(e.getMessage());
        }
    }

    @ReactMethod
    public void sha256(String data, Callback success, Callback error) {
        try {
            String result = shaX(data, "SHA-256");
            success.invoke(result);
        } catch (Exception e) {
            error.invoke(e.getMessage());
        }
    }

    @ReactMethod
    public void sha1(String data, Callback success, Callback error) {
        try {
            String result = shaX(data, "SHA-1");
            success.invoke(result);
        } catch (Exception e) {
            error.invoke(e.getMessage());
        }
    }

    @ReactMethod
    public void sha512(String data, Callback success, Callback error) {
        try {
            String result = shaX(data, "SHA-512");
            success.invoke(result);
        } catch (Exception e) {
            error.invoke(e.getMessage());
        }
    }

    private String shaX(String data, String algorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        md.update(data.getBytes());
        byte[] digest = md.digest();

        return Base64.encodeToString(digest, Base64.DEFAULT);
    }

    private static String pbkdf2(String pwd, String salt) {
        //placeholder for PBKDF2
        return pwd;
    }

    private static String hmac256(String text, String key) {
        //placeholder for hmac256
        return text;
    }

    private static String encrypt(String text, String keyBase64, String ivBase64) throws Exception {
        if (text == null || text.length() == 0) {
            return null;
        }

        byte[] ivBytes = Base64.decode(ivBase64, Base64.DEFAULT);
        if (ivBytes.length != 16) {
            throw new RuntimeException("iv must be 16 bytes length, but it is " + ivBytes.length);
        }

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        SecretKey secretKey = getSecretKey(keyBase64);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        SecureRandom sr = new SecureRandom();
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv, sr);
        byte[] encrypted = cipher.doFinal(text.getBytes("UTF-8"));
        return Base64.encodeToString(encrypted, Base64.DEFAULT);
    }

    private static String decrypt(String code, String keyBase64, String ivBase64) throws Exception {
        if(code == null || code.length() == 0) {
            return null;
        }

        byte[] ivBytes = Base64.decode(ivBase64, Base64.DEFAULT);
        if (ivBytes.length != 16) {
            throw new RuntimeException("iv must be 16 bytes length, but it is " + ivBytes.length);
        }

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        SecretKey secretKey = getSecretKey(keyBase64);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        byte[] decrypted = cipher.doFinal(Base64.decode(code, Base64.DEFAULT));
        return new String(decrypted, "UTF-8");
    }

    private static SecretKey getSecretKey(String keyBase64) throws Exception {
        return new SecretKeySpec(Base64.decode(keyBase64, Base64.DEFAULT), KEY_ALGORITHM);
    }
}


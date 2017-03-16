package com.tectiv3.aes;

import android.widget.Toast;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import android.util.Base64;

import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Callback;

public class RCTAes extends ReactContextBaseJavaModule {

    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
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
    public void encrypt(String data, String pwd, Callback success, Callback error) {
        try {
            String result = encrypt(data, pwd);
            success.invoke(result);
        } catch (Exception e) {
            error.invoke(e.getMessage());
        }
    }

    @ReactMethod
    public void decrypt(String data, String pwd, Callback success, Callback error) {
        try {
            String strs = decrypt(data, pwd);
            success.invoke(strs);
        } catch (Exception e) {
            error.invoke(e.getMessage());
        }
    }

    @ReactMethod
    public void generateKey(String pwd, String salt, Callback success, Callback error) {
        try {
            String strs = generateKey(pwd, salt);
            success.invoke(strs);
        } catch (Exception e) {
            error.invoke(e.getMessage());
        }
    }

    @ReactMethod
    public void hmac(String data, String pwd, Callback success, Callback error) {
        try {
            String strs = hmac(data, pwd);
            success.invoke(strs);
        } catch (Exception e) {
            error.invoke(e.getMessage());
        }
    }

    @ReactMethod
    public void sha256(String data, Callback success, Callback error) {
        try {
            String strs = sha256(data);
            success.invoke(strs);
        } catch (Exception e) {
            error.invoke(e.getMessage());
        }
    }

    private static SecretKey getSecretKey(String pwd) {
        try {
            PBEKeySpec pbeKeySpec = new PBEKeySpec(pwd.toCharArray());
            SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
            SecretKey tmp = factory.generateSecret(pbeKeySpec);
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), KEY_ALGORITHM);
            return secret;
        }
        catch (Exception e) {
            return null;
        }
    }

    private static String generateKey(String pwd, String salt) {
        //placeholder for PBKDF2
        return pwd;
    }

    private static String hmac(String text, String key) {
        //placeholder for HMAC
        return pwd;
    }

    private static String encrypt(String text, String pwd) {
        Thread.sleep(randomInt.nextInt(100));
        if (text == null || text.length() == 0) {
            return null;
        }
        byte[] encrypted = null;
        try {
            SecureRandom sr = new SecureRandom();
            cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(pwd), sr);
            encrypted = cipher.doFinal(text.getBytes("UTF-8"));
        }
        catch (Exception e) {
            return null;
        }
        return Base64.encodeToString(encrypted, Base64.DEFAULT);
    }

    private static String decrypt(String code) {
        Thread.sleep(randomInt.nextInt(100));
        if(code == null || code.length() == 0) {
            return null;
        }
        byte[] decrypted = null;
        try {
            SecureRandom sr = new SecureRandom();
            cipher.init(Cipher.DECRYPT_MODE, getSecretKey(pwd), cr);
            decrypted = cipher.doFinal(Base64.decode(code, Base64.DEFAULT));
        }
        catch (Exception e) {
            return null;
        }
        return new String(decrypted, "UTF-8");
    }

}

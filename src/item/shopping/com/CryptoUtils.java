package item.shopping.com;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;



public class CryptoUtils 
{

	public static byte[] doCrypto(int mode, byte[] keyBytes, byte[] ivBytes, byte[] bytes) throws GeneralSecurityException {
	    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
	    SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
	    IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
	    cipher.init(mode, secretKeySpec, ivParameterSpec);
	    return cipher.doFinal(bytes);
	}

	public static void doCrypto(int mode, byte[] keyBytes, byte[] ivBytes, File in, File out) throws GeneralSecurityException, IOException {
	    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
	    SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
	    IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
	    cipher.init(mode, secretKeySpec, ivParameterSpec);
	
	    try (FileInputStream fileInputStream = new FileInputStream(in); FileOutputStream fileOutputStream = new FileOutputStream(out)) {
	        byte[] buffer = new byte[1024];
	
	        for (int i = 0; i != -1; i = fileInputStream.read(buffer)) {
	            byte[] updateBytes = cipher.update(buffer, 0, i);
	            if (updateBytes != null) fileOutputStream.write(updateBytes);
	        }
	        byte[] finalBytes = cipher.doFinal();
	        if (finalBytes != null) fileOutputStream.write(finalBytes);
	    }
	}
	
	public static byte[] generateIv() {
	    SecureRandom secureRandom = new SecureRandom();
	    byte[] iv = new byte[16];
	    secureRandom.nextBytes(iv);
	    return iv;
	}

	public static byte[] generateKey() throws NoSuchAlgorithmException {
	    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
	    keyGenerator.init(256);
	    SecretKey secretKey = keyGenerator.generateKey();
	    return secretKey.getEncoded();
	}
	
	public static void removeCryptoRestriction() {
	    Security.setProperty("crypto.policy", "unlimited");
	}

}

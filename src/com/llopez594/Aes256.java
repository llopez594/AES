package com.llopez594;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class Aes256 {

    static String plainText = "This is a plain text which need to be encrypted by Java AES 256 Algorithm in CBC Mode";
    static SecretKey key;
    static byte[] IV; //IV is initial vector

    public static void main(String[] argv)  throws Exception
    {


        System.out.println("Original  : "+plainText);

        byte[] cipherText = encrypt(plainText.getBytes(),key, IV);
        System.out.println("Encrypted : "+ Base64.getEncoder().encodeToString(cipherText));

        String decryptedText = decrypt(cipherText,key, IV);
        System.out.println("DeCrypted : "+decryptedText);

    }

    private void init() {
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        keyGenerator.init(256);

        // Generate Key
        SecretKey key = keyGenerator.generateKey();

        // Generating IV.
        byte[] IV = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(IV);
    }

    public static byte[] encrypt (byte[] plaintext,SecretKey key,byte[] IV ) throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] cipherText = cipher.doFinal(plaintext);

        return cipherText;
    }

    public static String decrypt (byte[] cipherText, SecretKey key,byte[] IV) throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decryptedText = cipher.doFinal(cipherText);

        return new String(decryptedText);
    }

}

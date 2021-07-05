package com.llopez594;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class AES128 {
    static String plainText = "This is a plain text which need to be encrypted by Java AES 128 Algorithm";

    private static String charset = "ISO-8859-1";
    private static byte[] encryptionKey = {9, 115, 51, 86, 105, 4, -31, -23, -68, 88, 17, 20, 3, -105, 119, -53};
    private static Cipher cipher;
    private static Cipher decipher;
    private static SecretKeySpec secretKeySpec;

    public static void main(String[] argv)  throws Exception
    {
        init();
        System.out.println("Original  : "+plainText);

        String textEcrypted = encrypt(plainText, secretKeySpec);
        System.out.println("Encrypted : "+ textEcrypted);

        String decryptedText = decrypt(textEcrypted, secretKeySpec);
        System.out.println("DeCrypted : "+decryptedText);
    }

    public static void init() {
        try {
            cipher = Cipher.getInstance("AES");
            decipher = Cipher.getInstance("AES");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }

        secretKeySpec = new SecretKeySpec(encryptionKey,"AES");
    }

    public static String encrypt(String string, SecretKey key) {
        byte[] stringByte = string.getBytes();
        byte[] encryptedByte = new byte[stringByte.length];

        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            encryptedByte = cipher.doFinal(stringByte);
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        String returnString = null;

        try {
            returnString = new String(encryptedByte, charset);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return returnString;
    }

    public static String decrypt(String string, SecretKey key) throws UnsupportedEncodingException {
        byte[] encryptedByte = string.getBytes(charset);
        String descryptedString = null;
        byte[] decryption;

        try {
            decipher.init(Cipher.DECRYPT_MODE, key);
            decryption = decipher.doFinal(encryptedByte);
            descryptedString = new String(decryption);
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        return descryptedString;
    }
}

package cat.uvic.teknos.m09.cryptoutils;

import cat.uvic.teknos.m09.cryptoutils.dto.EncryptedMessage;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Properties;

public class SymmetricEncryption {
    public static Properties props;
    private static Cipher cipher;

    static{
        props = new Properties();
        //takes file properties from current classpath
        try{
            props.load(ClassLoader.getSystemClassLoader().getResourceAsStream("/cryptoutils.properties"));
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        }catch(IOException | NullPointerException error){
            setDefaultProperties();
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static EncryptedMessage encryptMessage(byte[]message, String password) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        var key = getPrivateKeyFromPass(password);
        String salt = props.getProperty("symmetric.salt");

        var iv = new IvParameterSpec(salt.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE,key,iv);

        var cipherText = cipher.doFinal(message);
//        var encoder = Base64.getEncoder();
//        var cipherTextBase64 = encoder.encodeToString(cipherText);
        EncryptedMessage result = new EncryptedMessage(cipherText,salt.getBytes());
        return result;
    }

    public static byte[] decryptedMessage(EncryptedMessage encr, String password) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Key key = getPrivateKeyFromPass(password);
        var iv = new IvParameterSpec(encr.getSalt());
        cipher.init(Cipher.DECRYPT_MODE,key,iv);
        var result = cipher.doFinal(encr.getMessage());

        return result;
//        var decripterText = new String(decripterTextBytes);
    }

    private static Key getPrivateKeyFromPass(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {

        String salt = props.getProperty("symmetric.salt");
        String algorithm = props.getProperty("symmetric.algorithm");
        int iterations = (Integer)props.get("symmetric");

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(),salt.getBytes(),iterations,256);
        SecretKey pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(pbeKeySpec);
        return new SecretKeySpec(pbeKey.getEncoded(), algorithm);
    }

    public static void setDefaultProperties() {
        try {
            props.load(Hash.class.getResourceAsStream("/cryptoutils.properties"));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}

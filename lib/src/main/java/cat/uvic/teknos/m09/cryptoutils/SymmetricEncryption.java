package cat.uvic.teknos.m09.cryptoutils;

import cat.uvic.teknos.m09.cryptoutils.dto.EncryptedMessage;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Properties;

public class SymmetricEncryption {
    public static Properties props;
    private static Cipher cipher;

    static{
        props = new Properties();
        //takes file properties from current classpath
        try{
            props.load(ClassLoader.getSystemClassLoader().getResourceAsStream("/cryptoutils.properties"));
        }catch(IOException | NullPointerException error){
            setDefaultProperties();
        }
    }

    public static EncryptedMessage encryptMessage(byte[]message, String password) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        var key = getPrivateKeyFromPass(password);
        var secureRandom = new SecureRandom();
        var bytes = new byte[16];
        secureRandom.nextBytes(bytes);
        var iv = new IvParameterSpec(bytes);
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE,key,iv);

        var cipherText = cipher.doFinal(message);

        EncryptedMessage result = new EncryptedMessage(cipherText,bytes);
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
        int iterations = Integer.parseInt(props.getProperty("symmetric.iterations"));

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

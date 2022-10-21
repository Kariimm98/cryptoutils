package cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils;

import cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils.dto.EncryptedMessage;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Properties;

public class SymmetricEncryption extends PropertiesImp {
    public static Properties props;
    private static Cipher cipher;

    private static String SALT ="symmetric.salt";
    private static String ALGORITHM ="symmetric.algorithm";
    private static String ITERATIONS ="symmetric.iterations";



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
    }

    private static Key getPrivateKeyFromPass(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {

        String salt = props.getProperty(SALT);
        String algorithm = props.getProperty(ALGORITHM);
        int iterations = Integer.parseInt(props.getProperty(ITERATIONS));

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(),salt.getBytes(),iterations,256);
        SecretKey pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(pbeKeySpec);
        return new SecretKeySpec(pbeKey.getEncoded(), algorithm);
    }
}

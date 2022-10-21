package cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils;

import cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils.Exceptions.DecryptErrorException;
import cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils.dto.EncryptedMessage;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class AssymmetricEncryption extends PropertiesImp {

    private static String ALGORITHM = "assymmetric.algorithm";

    public EncryptedMessage encryptMessage(byte[] message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        EncryptedMessage result = new EncryptedMessage();
        String algorithm = props.getProperty(ALGORITHM);
        var keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        var keyPair = keyPairGenerator.generateKeyPair();

        var cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE,keyPair.getPrivate());
        byte[] encryptedText = cipher.doFinal(message);

        result.setPublicKey(keyPair.getPublic());
        result.setMessage(encryptedText);

        return result;
    }

    public byte[] decryptMessage(EncryptedMessage message) throws DecryptErrorException {

        try{
            String algorithm = props.getProperty(ALGORITHM);
            var cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE,(PublicKey)message.getPublicKey());
            byte[] decryptedText = cipher.doFinal(message.getMessage());
            return decryptedText;
        }catch(Exception e){
            throw new DecryptErrorException("Couldn't decrypt message");
        }
    }
}

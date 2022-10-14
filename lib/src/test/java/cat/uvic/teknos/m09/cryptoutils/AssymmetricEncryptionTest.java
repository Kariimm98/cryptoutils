package cat.uvic.teknos.m09.cryptoutils;

import cat.uvic.teknos.m09.cryptoutils.Exceptions.DecryptErrorException;
import cat.uvic.teknos.m09.cryptoutils.dto.EncryptedMessage;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import static org.junit.jupiter.api.Assertions.*;

class AssymmetricEncryptionTest {

    @Test
    public void encryptDecryptOk() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, DecryptErrorException {
        AssymmetricEncryption encryption = new AssymmetricEncryption();

        String request = "Hola que tal";
        EncryptedMessage response = encryption.encryptMessage(request.getBytes());

        byte[] result = encryption.decryptMessage(response);

        String res = new String(result);

        assertTrue(request.equals(res));
    }
    @Test
    public void encryptDecryptKo() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, DecryptErrorException {
        AssymmetricEncryption encryption = new AssymmetricEncryption();

        String request = "Hola que tal";
        EncryptedMessage response = encryption.encryptMessage(request.getBytes());

        var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        var keyPair = keyPairGenerator.generateKeyPair();
        response.setPublicKey(keyPair.getPublic());

        assertThrows(DecryptErrorException.class,()->encryption.decryptMessage(response));
    }


}
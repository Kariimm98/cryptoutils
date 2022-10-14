package cat.uvic.teknos.m09.cryptoutils;

import cat.uvic.teknos.m09.cryptoutils.Exceptions.DecryptErrorException;
import cat.uvic.teknos.m09.cryptoutils.dto.EncryptedMessage;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import static org.junit.jupiter.api.Assertions.*;

class SymmetricEncryptionTest {

    @Test
    void encryptDecryptMessageSuccess() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException, DecryptErrorException {

        String request = "Hola que tal";
        EncryptedMessage mess = SymmetricEncryption.encryptMessage(request.getBytes(),"Patata");
        byte[] result = SymmetricEncryption.decryptedMessage(mess,"Patata");
        assertTrue(new String(result).equals(request));
    }

    @Test
    void encryptDecryptFailed() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {

        String request = "Hola que tal";
        EncryptedMessage mess = SymmetricEncryption.encryptMessage(request.getBytes(),"Patata");
        byte[] result = SymmetricEncryption.decryptedMessage(mess,"Patata2");
        assertFalse(new String(result).equals(request));
    }

}
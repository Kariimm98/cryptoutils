package cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils;

import cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils.Exceptions.DecryptErrorException;
import cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils.Exceptions.MissingPropertiesException;
import cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils.dto.EncryptedMessage;
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
    void encryptDecryptMessageSuccess() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException, DecryptErrorException, MissingPropertiesException {
        CryptoUtils cr = new CryptoUtils();
        String request = "Hola que tal";
        EncryptedMessage mess = cr.encrypt(request.getBytes(),"Patata");
        byte[] result = cr.decrypt(mess,"Patata");
        assertTrue(new String(result).equals(request));
    }

    @Test
    void encryptDecryptFailed() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException, MissingPropertiesException {
        CryptoUtils cr = new CryptoUtils();
        String request = "Hola que tal";
        EncryptedMessage mess = cr.encrypt(request.getBytes(),"Patata");
        assertThrows(BadPaddingException.class,()->cr.decrypt(mess,"Patata2"));

    }

}
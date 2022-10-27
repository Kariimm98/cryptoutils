package cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils;

import cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils.Exceptions.MissingPropertiesException;
import org.junit.jupiter.api.Test;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

public class SignatureTest {
    @Test
    void verifiedOK() throws UnrecoverableKeyException, MissingPropertiesException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, URISyntaxException {

        CryptoUtils cr = new CryptoUtils();
        String message = "hola que tal";
        CryptoUtils cu = new CryptoUtils();
        var stream = getClass().getClassLoader().getResourceAsStream("certificate.cer");
        var hash = cu.hash(message.getBytes());
        var signed = cr.sign(hash.getHash());

        assertTrue(cr.verify(hash.getHash(),signed,stream.readAllBytes()));
    }

    @Test
    void verifiedKO() throws MissingPropertiesException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException, CertificateException, KeyStoreException, SignatureException, InvalidKeyException {
        CryptoUtils cr = new CryptoUtils();
        String message = "hola que tal";

        var stream = new FileInputStream("certificate.cer");
        CryptoUtils cu = new CryptoUtils();
        var hash = cu.hash(message.getBytes());
        var signed = new byte[100];

        new Random().nextBytes(signed);
        assertFalse(cr.verify(hash.getHash(),signed,stream.readAllBytes()));
    }
}

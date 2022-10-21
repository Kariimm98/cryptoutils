package cat.uvic.teknos.m09.cryptoutils;

import cat.uvic.teknos.m09.cryptoutils.Exceptions.MissingPropertiesException;
import org.junit.jupiter.api.Test;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

public class SignatureTest {
    @Test
    void verifiedOK() throws UnrecoverableKeyException, MissingPropertiesException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        Signature signature = new Signature();
        String message = "hola que tal";

        var stream = getClass().getClassLoader().getResourceAsStream("lib/src/test/resource/certificate.cer");
        var hash = new Hash().getHash(message.getBytes());
        var signed = signature.sign(hash);

        assertTrue(signature.verify(hash,signed,stream.readAllBytes()));
    }

    @Test
    void verifiedKO() throws MissingPropertiesException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException, CertificateException, KeyStoreException, SignatureException, InvalidKeyException {
        Signature signature = new Signature();
        String message = "hola que tal";

        var stream = new FileInputStream("/resource/certificate.cer");
        var hash = new Hash().getHash(message.getBytes());
        var signed = new byte[100];

        new Random().nextBytes(signed);
        assertFalse(signature.verify(hash,signed,stream.readAllBytes()));
    }
}

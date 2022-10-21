package cat.uvic.teknos.m09.cryptoutils;

import cat.uvic.teknos.m09.cryptoutils.Exceptions.MissingPropertiesException;
import cat.uvic.teknos.m09.cryptoutils.dto.EncryptedMessage;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Signature extends PropertiesImp{

    private static String KEYSTORE =  "signature.keystore";
    private static String PASSWORD =  "signature.password";
    private static String ALGORITHM = "signature.algorithm";
    private static String ALIAS = "signature.alias";

    public byte[] sign(byte[] message ) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, SignatureException, MissingPropertiesException {
        var pathKeystore = props.getProperty(KEYSTORE);
        var pass = props.getProperty(PASSWORD);
        var alias = props.getProperty(ALIAS);
        var algorithm = props.getProperty(ALGORITHM);

        var keystore = KeyStore.getInstance("PKCS12");
        keystore.load (new FileInputStream(pathKeystore), pass.toCharArray());
        var privateKey = keystore.getKey(alias, pass.toCharArray());

        var signer = java.security.Signature.getInstance(algorithm);

        signer.initSign((PrivateKey) privateKey);
        signer.update(message);

        var signature = signer.sign();

        return signature;
    }

    public boolean verify(byte[]  message, byte[] signature, byte[] cert) throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, SignatureException, InvalidKeyException, MissingPropertiesException {
        var algorithm = props.getProperty(ALGORITHM);

        var signer = java.security.Signature.getInstance(algorithm);
        var certificateFactory = CertificateFactory.getInstance("X.509");
        var certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(cert));

        try {
            ((X509Certificate) certificate).checkValidity();
        } catch( Exception e) {
            System.out.println(e.getMessage());
        }
        var publicKey = certificate.getPublicKey();

        signer.initVerify(publicKey);
        signer.update(message);

        return signer.verify(signature);
    }

}

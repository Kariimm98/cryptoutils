package cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils;

import cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils.Exceptions.MissingPropertiesException;
import cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils.dto.DigestResult;
import cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils.dto.EncryptedMessage;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

/**
 * Class implements methods generate Hash, encrypt and decrypt with Symmetric Encryption, sign and verify with certificate
 * @author Karim el Bouzzaoui del Moral abdelkarim.el@uvic.cat
 */
public class CryptoUtils extends PropertiesImp{

    private static final String HASH_ALGORITHM = "hash.algorithm";
    private static final String HASH_SALT = "hash.salt";
    private static String SYMMETRIC_SALT ="symmetric.salt";
    private static String SYMMETRIC_ALGORITHM ="symmetric.algorithm";
    private static String SYMMETRIC_ITERATIONS ="symmetric.iterations";
    private static String SIGNATURE_KEYSTORE =  "signature.keystore";
    private static String SIGNATURE_PASSWORD =  "signature.password";
    private static String SIGNATURE_ALGORITHM = "signature.algorithm";
    private static String SIGNATURE_ALIAS = "signature.alias";


    public CryptoUtils() {
        super("/cryptoutils.properties");
    }


    /**
     * Generate Hash with algorithm in properties and salt
     * @param message byte[] for generate hash
     * @return
     * @throws MissingPropertiesException if in file cryptoutils.properties not found the properties
     * @throws NoSuchAlgorithmException
     */
    public DigestResult hash(byte[] message) throws MissingPropertiesException, NoSuchAlgorithmException {

        DigestResult result;

        String algorithm = props.getProperty(HASH_ALGORITHM);
        String salt = props.getProperty(HASH_SALT);
        if(algorithm == null|| salt== null){
            throw new MissingPropertiesException();
        }

        var messageDigest = MessageDigest.getInstance(algorithm);

        messageDigest.update(salt.getBytes());
        result = new DigestResult(messageDigest.digest(message),algorithm,salt.getBytes());

        return result;
    }

    private  byte[] getRandomSalt(){
        var secureRandom = new SecureRandom();
        var salt  = new byte[16];
        secureRandom.nextBytes(salt);
        return salt;
    }


    /**
     * Encrpts message with password using salt
     * @param message byte[] to encrypt
     * @param password String for encrypt
     * @return Object encrypted message with byte[] message encrypted, byte[] salt
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws MissingPropertiesException
     */
    public EncryptedMessage encrypt(byte[]message, String password) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, MissingPropertiesException {
        var key = getPrivateKeyFromPass(password);
        var secureRandom = new SecureRandom();
        var bytes = new byte[16];
        secureRandom.nextBytes(bytes);
        var iv = new IvParameterSpec(bytes);
        Cipher cipher;
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE,key,iv);

        var cipherText = cipher.doFinal(message);

        EncryptedMessage result = new EncryptedMessage(cipherText,bytes);
        return result;
    }
    /**
     * Encrpts message with password without salt
     * @param message byte[] to encrypt
     * @param password String for encrypt
     * @return Object encrypted message with byte[] message encrypted, byte[] salt
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws MissingPropertiesException
     */
    public byte[] encryptNoSalt(byte[]message, String password) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, MissingPropertiesException {
        var key = getPrivateKeyFromPass(password);
        Cipher cipher;
        cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE,key);
        var cipherText = cipher.doFinal(message);
        return cipherText;
    }

    private Key getPrivateKeyFromPass(String password) throws NoSuchAlgorithmException, InvalidKeySpecException, MissingPropertiesException {

        String salt = props.getProperty(SYMMETRIC_SALT);
        String algorithm = props.getProperty(SYMMETRIC_ALGORITHM);
        int iterations = Integer.parseInt(props.getProperty(SYMMETRIC_ITERATIONS));

        if(salt ==null || algorithm == null || iterations ==0)
            throw new MissingPropertiesException("Symmetric Encryption");


        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(),salt.getBytes(),iterations,256);
        SecretKey pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(pbeKeySpec);
        return new SecretKeySpec(pbeKey.getEncoded(), algorithm);
    }

    /**
     * Decrypt message using password
     * @param encr Object with byte[] encrypted message, byte[] salt for decrypt
     * @param password String for decrypt message
     * @return byte[] message decrypted
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchPaddingException
     * @throws MissingPropertiesException
     */
    public byte[] decrypt(EncryptedMessage encr, String password) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, MissingPropertiesException {
        Cipher cipher;
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        Key key = getPrivateKeyFromPass(password);
        var iv = new IvParameterSpec(encr.getSalt());
        cipher.init(Cipher.DECRYPT_MODE,key,iv);
        var result = cipher.doFinal(encr.getMessage());

        return result;
    }
    /**
     * Decrypt message using password without salt
     * @param encr Object with byte[] encrypted message, byte[] salt for decrypt
     * @param password String for decrypt message
     * @return byte[] message decrypted
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchPaddingException
     * @throws MissingPropertiesException
     */
    public byte[] decrypt(byte[] encr, String password) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, MissingPropertiesException {
        Cipher cipher;
        cipher = Cipher.getInstance("AES");
        Key key = getPrivateKeyFromPass(password);
        cipher.init(Cipher.DECRYPT_MODE,key);
        var result = cipher.doFinal(encr);

        return result;
    }


    /**
     * Sign the message with key in keystore assigned from properties
     * @param message byte[] message for sign
     * @return signature of message
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws MissingPropertiesException
     */
    public byte[] sign(byte[] message ) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, SignatureException, MissingPropertiesException {
        var pathKeystore = props.getProperty(SIGNATURE_KEYSTORE);
        var pass = props.getProperty(SIGNATURE_PASSWORD);
        var alias = props.getProperty(SIGNATURE_ALIAS);
        var algorithm = props.getProperty(SIGNATURE_ALGORITHM);

        var keystore = KeyStore.getInstance("PKCS12");

        keystore.load (new FileInputStream(getClass().getClassLoader().getResource(pathKeystore).getPath()), pass.toCharArray());
        var privateKey = keystore.getKey(alias, pass.toCharArray());

        var signer = java.security.Signature.getInstance(algorithm);

        signer.initSign((PrivateKey) privateKey);
        signer.update(message);

        var signature = signer.sign();

        return signature;
    }


    /**
     * Check if signature is correct with certificat
     * @param message  byte[] message
     * @param signature byte[] signature to check if is correct signed
     * @param cert byte[] certificate for check if the singature is correct
     * @return boolean if message is signed correctly or not
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws FileNotFoundException
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws MissingPropertiesException
     */
    public boolean verify(byte[]  message, byte[] signature, byte[] cert) throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, SignatureException, InvalidKeyException, MissingPropertiesException {
        var algorithm = props.getProperty(SIGNATURE_ALGORITHM);

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

package cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils;

import cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils.Exceptions.MissingPropertiesException;
import cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils.dto.DigestResult;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class CryptoUtils extends PropertiesImp{

    private static final String HASH_ALGORITHM = "hash.algorithm";
    private static final String HASH_SALT = "hash.salt";


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



    public  byte[] getRandomSalt(){
        var secureRandom = new SecureRandom();
        var salt  = new byte[16];
        secureRandom.nextBytes(salt);
        return salt;
    }
}

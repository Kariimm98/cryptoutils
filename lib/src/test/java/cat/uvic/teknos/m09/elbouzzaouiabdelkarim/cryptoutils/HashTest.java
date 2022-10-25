/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils;

import cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils.Exceptions.MissingPropertiesException;
import cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils.dto.DigestResult;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import java.security.NoSuchAlgorithmException;


import static org.junit.jupiter.api.Assertions.*;

class HashTest {

    @Test void DigestResultOk() throws NoSuchAlgorithmException {

        byte[] message = "hola".getBytes();
        byte[] message2 = "hola".getBytes();

        CryptoUtils cu = new CryptoUtils();
        var result = Assertions.assertDoesNotThrow(() ->  cu.hash(message));
        var result2 = Assertions.assertDoesNotThrow(() ->  cu.hash(message2));

        assertTrue(java.util.Arrays.equals(result.getHash(),result2.getHash()));

    }

    //when in file properties missing property algorithm throw the exception.
    @Test void throwsMissingProperties(){
        byte[] message = "hola".getBytes();

        CryptoUtils cu = new CryptoUtils();
        String alg = cu.props.getProperty("hash.algorithm");
        cu.props.remove("hash.algorithm");
        assertThrows(MissingPropertiesException.class,()->cu.hash(message));

        cu.props.setProperty("hash.algorithm",alg);

    }

    @Test void DigestResultNotSame(){
        byte[] message = "hola".getBytes();
        byte[] message2 = "hola2".getBytes();

        CryptoUtils cu = new CryptoUtils();
        var result = Assertions.assertDoesNotThrow(() ->  cu.hash(message));
        var result2 = Assertions.assertDoesNotThrow(() ->  cu.hash(message2));

        assertNotEquals(result,result2);
    }
}

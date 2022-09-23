/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package cat.uvic.teknos.m09.cryptoutils;

import cat.uvic.teknos.m09.cryptoutils.Exceptions.MissingPropertiesException;
import cat.uvic.teknos.m09.cryptoutils.Hash;
import cat.uvic.teknos.m09.cryptoutils.dto.DigestResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.*;

class HashTest {

    private static Hash Hash;

    @BeforeAll
    static void beforeAll() {
        Hash = assertDoesNotThrow(()-> new Hash());
    }

    @Test void sameMessageSameResult() throws NoSuchAlgorithmException {

        byte[] message = "hola".getBytes();
        byte[] message2 = "hola".getBytes();


        String result = assertDoesNotThrow(() ->  Hash.getHashAsString(message));
        String result2 = assertDoesNotThrow(() ->  Hash.getHashAsString(message2));

        assertEquals(result,result2);

    }

    //when in file properties missing property algorithm throw the exception.
    @Test void throwsMissingProperties(){
        byte[] message = "hola".getBytes();

        String alg = Hash.props.getProperty("algorithm");
        Hash.props.remove("algorithm");

        assertThrows(MissingPropertiesException.class,()->Hash.getHash(message));

        Hash.props.setProperty("algorithm",alg);

    }

    @Test void notSameHash(){
        byte[] message = "hola".getBytes();
        byte[] message2 = "hola2".getBytes();

        String result = assertDoesNotThrow(() ->  Hash.getHashAsString(message));
        String result2 = assertDoesNotThrow(() ->  Hash.getHashAsString(message2));

        assertNotEquals(result,result2);
    }

    //returns a Hashmap with salt uses in digest and Hash as byte[]
    @Test void getHashWithRandomSalt(){
        byte[] message = "hola".getBytes();

        DigestResult result = assertDoesNotThrow(() ->  Hash.getHashWithRandomSalt(message));

        assertTrue(()->result.getSalt()!=null);
        assertDoesNotThrow(()->result.getHash()!=null);

    }

    //returns a Hashmap with salt uses in digest and Hash as String
    @Test void getHashWithRandomSaltAsString(){
        byte[] message = "hola".getBytes();

        DigestResult result = assertDoesNotThrow(() ->  Hash.getHashWithRandomSaltAsString(message));

        assertTrue(()->result.getSalt()!=null);
        assertDoesNotThrow(()->result.getHash()!=null);

    }
}
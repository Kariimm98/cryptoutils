package cat.uvic.teknos.m09.cryptoutils.dto;

import java.security.Key;

public class EncryptedMessage<T> {

    byte[] message;
    byte[] salt;

    Key publicKey;

    public EncryptedMessage( byte[] mess, byte[] salt){
        this.message = mess;
        this.salt = salt;
    }

    public EncryptedMessage(){

    }

    public byte[] getMessage() {
        return message;
    }

    public void setMessage(byte[] message) {
        this.message = message;
    }

    public byte[] getSalt() {
        return salt;
    }

    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    public Key getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(Key publicKey) {
        this.publicKey = publicKey;
    }
}

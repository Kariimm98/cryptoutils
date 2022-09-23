package cat.uvic.teknos.m09.cryptoutils.dto;

public class EncryptedMessage<T> {

    byte[] message;
    byte[] salt;

    public EncryptedMessage( byte[] mess, byte[] salt){
        this.message = mess;
        this.salt = salt;
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
}

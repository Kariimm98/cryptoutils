package cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils.dto;

public class DigestResult {

    byte[] hash;
    String algorithm;
    byte[] salt;

    public DigestResult(byte[] hash,String algorithm, byte[] salt){
        this.hash = hash;
        this.algorithm = algorithm;
        this.salt =  salt;

    }

    public byte[] getHash() {
        return hash;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public byte[] getSalt() {
        return salt;
    }
}

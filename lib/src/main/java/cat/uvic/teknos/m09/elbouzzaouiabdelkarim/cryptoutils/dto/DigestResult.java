package cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils.dto;

public class DigestResult<T> {

    T hash;
    String algorithm;
    T salt;

    public DigestResult(T hash,String algorithm, T salt){
        this.hash = hash;
        this.algorithm = algorithm;
        this.salt =  salt;

    }

    public T getHash() {
        return hash;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public T getSalt() {
        return salt;
    }
}

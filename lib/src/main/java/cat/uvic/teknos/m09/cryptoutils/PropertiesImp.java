package cat.uvic.teknos.m09.cryptoutils;

import java.io.IOException;
import java.util.Properties;

public class PropertiesImp {
    public static Properties props;
    static{
        props = new Properties();
        //takes file properties from current classpath
        try{
            props.load(ClassLoader.getSystemClassLoader().getResourceAsStream("/cryptoutils.properties"));
        }catch(IOException | NullPointerException error){
            setDefaultProperties();
        }
    }

    public static void setDefaultProperties() {
        try {
            props.load(Hash.class.getResourceAsStream("/cryptoutils.properties"));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}

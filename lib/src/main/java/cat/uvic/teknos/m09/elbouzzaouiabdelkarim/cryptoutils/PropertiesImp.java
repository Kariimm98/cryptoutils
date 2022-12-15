package cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils;

import java.io.IOException;
import java.util.Properties;

public class PropertiesImp {

    public String propertiesPath;
    public Properties props;

    public PropertiesImp(String properties) {
        this.propertiesPath = properties;

        props = new Properties();
        //takes file properties from current classpath
        try{
            props.load(ClassLoader.getSystemClassLoader().getResourceAsStream(propertiesPath));
        }catch(IOException | NullPointerException error){
            setDefaultProperties();
        }
    }
    public void setDefaultProperties() {
        try {
            props.load(PropertiesImp.class.getResourceAsStream(propertiesPath));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


}

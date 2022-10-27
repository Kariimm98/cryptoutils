package cat.uvic.teknos.m09.elbouzzaouiabdelkarim.cryptoutils.Exceptions;

public class MissingPropertiesException extends Exception{
    public MissingPropertiesException(){
        super("Faltan Campos en el Fichero de configuracion");
    }
    public MissingPropertiesException(String ...args){
        super("Faltan Campos en el Fichero de configuracion: "+ args[0]);
    }
}

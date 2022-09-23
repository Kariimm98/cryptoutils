package cat.uvic.teknos.m09.cryptoutils.Exceptions;

public class MissingPropertiesException extends Exception{
    public MissingPropertiesException(){
        super("Faltan Campos en el Fichero de configuracion");
    }
}

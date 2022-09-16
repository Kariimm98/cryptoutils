package cat.uvic.teknos.m09.Exceptions;

public class MissingPropertiesException extends Exception{
    public MissingPropertiesException(){
        super("Faltan Campos en el Fichero de configuracion");
    }
}

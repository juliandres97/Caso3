package cliente;

import javax.xml.bind.DatatypeConverter;

public class Transformacion {
    public static final String SEPARADOR2 = ";";

    public static String codificar(byte[] b) {
        String ret = "";
        int i = 0;
        while (i < b.length) {
            String g;
            ret = String.valueOf(ret) + ((g = Integer.toHexString(b[i] & 255)).length() == 1 ? "0" : "") + g;
            ++i;
        }
        return ret;
    }

    public static String toHexString(byte[] array) {
        return DatatypeConverter.printHexBinary(array);
    }

    public static byte[] toByteArray(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }

    public static byte[] decodificar(String ss) {
        byte[] ret = new byte[ss.length() / 2];
        int i = 0;
        while (i < ret.length) {
            ret[i] = (byte)Integer.parseInt(ss.substring(i * 2, (i + 1) * 2), 16);
            ++i;
        }
        return ret;
    }
}


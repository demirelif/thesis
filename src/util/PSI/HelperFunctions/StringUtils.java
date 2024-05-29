package util.PSI.HelperFunctions;

public class StringUtils {
    public static int getLastChar(String str) {
        if ( str == null || str.isEmpty() ){
            throw new IllegalArgumentException("String is null or empty");
        } else {
            return str.charAt(str.length()-1);
        }
    }
}

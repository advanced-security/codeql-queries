import java.util.Base64;

class MyApp {
    public static String KEY = "VGVzdFBhc3N3b3Jk";
    public static byte[] KEY2 = new byte[] { 'V', 'G', 'V', 'z', 'd', 'F', 'B', 'h', 'c', '3', 'N', '3', 'b', '3', 'J',
            'k' };

    public String getDecoderString() {
        byte[] decodedBytes = Base64.getDecoder().decode(MyApp.KEY);

        String decodedString = new String(decodedBytes);
        return decodedString;
    }

    public String getDecoderBytes() {
        byte[] decodedBytes = Base64.getDecoder().decode(MyApp.KEY2);

        String decodedString = new String(decodedBytes);
        return decodedString;
    }

    public String getDecoderConvertString() {
        String key = MyApp.KEY2.toString();
        byte[] decodedBytes = Base64.getDecoder().decode(key);

        String decodedString = new String(decodedBytes);
        return decodedString;
    }

    public String getDecoderConvertBytes() {
        byte[] key = MyApp.KEY.getBytes();
        byte[] decodedBytes = Base64.getDecoder().decode(key);

        String decodedString = new String(decodedBytes);
        return decodedString;
    }

}
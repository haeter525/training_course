package dynamic_analysis.analysis_1;

/**
 * DecodeStr
 */
public class DecodeStr {
    private static short[] arr = {9652, 898, 4013, 4015, 4030, 4021, 4004, 4005, 4030, 4003, 4012, 4021, 4007, 4025, 4013, 2651, 2573, 2642, 2651, 2573, -24286, -29649, -29664, -29654, -29636, -29663, -29657, -29654, -29600, -29638, -29657, -29638, -29662, -29653, -23840, -23825, -23835, -23821, -23826, -23832, -23835, -23889, -23819, -23836, -23815, -23819, -31551, -31579, -31564, -31564, -31551, -28084, -28099, -28128, -28099, -28123, -28116, -28084, -26205, -26158, -26173, -26146, -26158, -26205, -23474, -23475, -23483, -23506, -23476, -23475, -23466, -23477, -23484, -23506, -30564, -30586};

    private static String decodeStr(int i, int i2, int i3) {
        char[] cArr = new char[i2 - i];
        for (int i4 = 0; i4 < i2 - i; i4++) {
            cArr[i4] = (char) (arr[i + i4] ^ i3);
        }
        return new String(cArr);
    }

    public static void main(String[] args) {
        String decodedStr = decodeStr(20, 21, -24255);
        System.out.println(decodedStr);
    }
}
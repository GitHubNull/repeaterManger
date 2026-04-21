package oxff.top.db.pool;

import java.util.HashMap;
import java.util.Map;

/**
 * HTTP 枚举映射类
 * 将 Protocol/Method 字符串与数据库整数存储互转
 */
public class HttpEnum {

    // ---- Protocol 枚举 ----
    private static final Map<String, Integer> PROTOCOL_TO_INT = new HashMap<>();
    private static final Map<Integer, String> INT_TO_PROTOCOL = new HashMap<>();

    static {
        PROTOCOL_TO_INT.put("http", 0);
        PROTOCOL_TO_INT.put("https", 1);

        INT_TO_PROTOCOL.put(0, "http");
        INT_TO_PROTOCOL.put(1, "https");
    }

    // ---- Method 枚举 ----
    private static final Map<String, Integer> METHOD_TO_INT = new HashMap<>();
    private static final Map<Integer, String> INT_TO_METHOD = new HashMap<>();

    static {
        METHOD_TO_INT.put("GET", 0);
        METHOD_TO_INT.put("POST", 1);
        METHOD_TO_INT.put("PUT", 2);
        METHOD_TO_INT.put("DELETE", 3);
        METHOD_TO_INT.put("PATCH", 4);
        METHOD_TO_INT.put("HEAD", 5);
        METHOD_TO_INT.put("OPTIONS", 6);
        METHOD_TO_INT.put("TRACE", 7);
        METHOD_TO_INT.put("CONNECT", 8);

        INT_TO_METHOD.put(0, "GET");
        INT_TO_METHOD.put(1, "POST");
        INT_TO_METHOD.put(2, "PUT");
        INT_TO_METHOD.put(3, "DELETE");
        INT_TO_METHOD.put(4, "PATCH");
        INT_TO_METHOD.put(5, "HEAD");
        INT_TO_METHOD.put(6, "OPTIONS");
        INT_TO_METHOD.put(7, "TRACE");
        INT_TO_METHOD.put(8, "CONNECT");
        INT_TO_METHOD.put(9, "OTHER");
    }

    /** OTHER 方法的整数值 */
    public static final int METHOD_OTHER = 9;

    /**
     * 将协议字符串转换为整数
     *
     * @param protocol "http" 或 "https"
     * @return 整数值，未知协议返回 0 (http)
     */
    public static int protocolToInt(String protocol) {
        if (protocol == null) {
            return 0;
        }
        Integer value = PROTOCOL_TO_INT.get(protocol.toLowerCase());
        return value != null ? value : 0;
    }

    /**
     * 将整数转换为协议字符串
     *
     * @param value 整数值
     * @return "http" 或 "https"，未知值返回 "http"
     */
    public static String intToProtocol(int value) {
        String protocol = INT_TO_PROTOCOL.get(value);
        return protocol != null ? protocol : "http";
    }

    /**
     * 将 HTTP 方法字符串转换为整数
     *
     * @param method HTTP 方法（GET, POST, ...）
     * @return 整数值，未知方法返回 9 (OTHER)
     */
    public static int methodToInt(String method) {
        if (method == null) {
            return METHOD_OTHER;
        }
        Integer value = METHOD_TO_INT.get(method.toUpperCase());
        return value != null ? value : METHOD_OTHER;
    }

    /**
     * 将整数转换为 HTTP 方法字符串
     *
     * @param value 整数值
     * @return HTTP 方法字符串，未知值返回 "OTHER"
     */
    public static String intToMethod(int value) {
        String method = INT_TO_METHOD.get(value);
        return method != null ? method : "OTHER";
    }

    /**
     * 判断方法是否为 OTHER
     */
    public static boolean isOtherMethod(int value) {
        return value == METHOD_OTHER;
    }
}

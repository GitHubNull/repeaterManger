package oxff.top.model;

import java.util.Date;

/**
 * 请求响应记录类 - 保存HTTP请求和响应的完整信息
 */
public class RequestResponseRecord {
    private final byte[] request;           // 请求原始数据
    private final byte[] response;          // 响应原始数据
    private final Date timestamp;           // 请求时间戳
    private final String method;            // HTTP方法
    private final String url;               // 请求URL
    private final int statusCode;           // HTTP状态码
    private final int responseLength;       // 响应长度
    private final long responseTime;        // 响应时间(毫秒)
    private String comment;                 // 记录注释
    private String color;                   // 记录颜色(用于UI显示)

    /**
     * 创建请求响应记录
     * 
     * @param request 请求原始数据
     * @param response 响应原始数据
     * @param timestamp 请求时间戳
     * @param method HTTP方法
     * @param url 请求URL
     * @param statusCode HTTP状态码
     * @param responseLength 响应长度
     * @param responseTime 响应时间(毫秒)
     */
    public RequestResponseRecord(byte[] request, byte[] response, Date timestamp,
                                 String method, String url, int statusCode,
                                 int responseLength, long responseTime) {
        this.request = request;
        this.response = response;
        this.timestamp = timestamp;
        this.method = method;
        this.url = url;
        this.statusCode = statusCode;
        this.responseLength = responseLength;
        this.responseTime = responseTime;
        this.comment = "";
        this.color = null;
    }

    public byte[] getRequest() {
        return request;
    }

    public byte[] getResponse() {
        return response;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public String getMethod() {
        return method;
    }

    public String getUrl() {
        return url;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public int getResponseLength() {
        return responseLength;
    }

    public long getResponseTime() {
        return responseTime;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public String getColor() {
        return color;
    }

    public void setColor(String color) {
        this.color = color;
    }

    @Override
    public String toString() {
        return String.format("%s %s → HTTP %d (%d 字节, %d ms)", 
            method, url, statusCode, responseLength, responseTime);
    }
} 
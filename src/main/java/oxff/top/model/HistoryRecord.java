package oxff.top.model;

/**
 * 历史记录类
 */
public class HistoryRecord {
    private final int id;
    private final int requestId;
    private final String method;
    private final String url;
    private final int statusCode;
    private final int responseLength;
    private final long timestamp;
    private final byte[] requestData;
    private final byte[] responseData;
    
    public HistoryRecord(int id, int requestId, String method, String url, int statusCode,
                        int responseLength, long timestamp, byte[] requestData, byte[] responseData) {
        this.id = id;
        this.requestId = requestId;
        this.method = method;
        this.url = url;
        this.statusCode = statusCode;
        this.responseLength = responseLength;
        this.timestamp = timestamp;
        this.requestData = requestData;
        this.responseData = responseData;
    }
    
    public int getId() {
        return id;
    }
    
    public int getRequestId() {
        return requestId;
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
    
    public long getTimestamp() {
        return timestamp;
    }
    
    public byte[] getRequestData() {
        return requestData;
    }
    
    public byte[] getResponseData() {
        return responseData;
    }
} 
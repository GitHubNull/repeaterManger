package oxff.top.model;

/**
 * 请求记录类
 */
public class RequestRecord {
    private final int id;
    private final String protocol;
    private final String domain;
    private final String path;
    private final String query;
    private final String method;
    private final byte[] requestData;
    
    public RequestRecord(int id, String protocol, String domain, String path, String query, String method, byte[] requestData) {
        this.id = id;
        this.protocol = protocol;
        this.domain = domain;
        this.path = path;
        this.query = query;
        this.method = method;
        this.requestData = requestData;
    }
    
    public int getId() {
        return id;
    }
    
    public String getProtocol() {
        return protocol;
    }
    
    public String getDomain() {
        return domain;
    }
    
    public String getPath() {
        return path;
    }
    
    public String getQuery() {
        return query;
    }
    
    public String getMethod() {
        return method;
    }
    
    public byte[] getRequestData() {
        return requestData;
    }
    
    /**
     * 获取完整URL
     */
    public String getUrl() {
        StringBuilder url = new StringBuilder();
        url.append(protocol).append("://").append(domain).append(path);
        if (query != null && !query.isEmpty()) {
            url.append("?").append(query);
        }
        return url.toString();
    }
} 
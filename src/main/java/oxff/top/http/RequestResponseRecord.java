package oxff.top.http;

import java.awt.Color;
import java.util.Date;
import java.net.URL;
import java.net.MalformedURLException;

/**
 * 请求响应记录类 - 用于存储HTTP交互记录
 */
public class RequestResponseRecord {
    private int id;                    // 数据库ID
    private int requestId;             // 所属请求ID
    private String protocol;           // 协议 (http/https)
    private String domain;             // 域名
    private String path;               // 路径
    private String queryParameters;    // 查询参数
    private String method;             // 请求方法
    private int statusCode;            // 响应状态码
    private int responseLength;        // 响应长度
    private int responseTime;          // 响应时间(ms)
    private Date timestamp;            // 时间戳
    private String comment;            // 备注
    private Color color;               // 标记颜色
    private byte[] requestData;        // 原始请求数据
    private byte[] responseData;       // 原始响应数据
    
    /**
     * 默认构造函数
     */
    public RequestResponseRecord() {
        this.timestamp = new Date();
        this.comment = "";
    }
    
    /**
     * 基础构造函数
     */
    public RequestResponseRecord(int requestId, String protocol, String domain, String path, 
                             String query, String method) {
        this();
        this.requestId = requestId;
        this.protocol = protocol;
        this.domain = domain;
        this.path = path;
        this.queryParameters = query;
        this.method = method;
    }
    
    /**
     * 完整构造函数
     */
    public RequestResponseRecord(int requestId, String protocol, String domain, String path, 
                             String query, String method, int statusCode, 
                             int responseLength, int responseTime, 
                             byte[] requestData, byte[] responseData) {
        this(requestId, protocol, domain, path, query, method);
        this.statusCode = statusCode;
        this.responseLength = responseLength;
        this.responseTime = responseTime;
        this.requestData = requestData;
        this.responseData = responseData;
    }
    
    /**
     * 完整构造函数 - 用于历史记录
     */
    public RequestResponseRecord(int id, int requestId, String method, String url, int statusCode,
                               int responseLength, long timestamp, byte[] requestData, byte[] responseData) {
        this();
        this.id = id;
        this.requestId = requestId;
        this.method = method;
        
        // 解析URL
        try {
            URL parsedUrl = new URL(url);
            this.protocol = parsedUrl.getProtocol();
            this.domain = parsedUrl.getHost();
            this.path = parsedUrl.getPath();
            this.queryParameters = parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "";
        } catch (MalformedURLException e) {
            // 如果URL解析失败，使用简单的字符串处理
            this.protocol = url.startsWith("https://") ? "https" : "http";
            String remaining = url.substring(protocol.length() + 3);
            
            int pathStart = remaining.indexOf('/');
            if (pathStart > 0) {
                this.domain = remaining.substring(0, pathStart);
                remaining = remaining.substring(pathStart);
            } else {
                this.domain = remaining;
                remaining = "/";
            }
            
            int queryStart = remaining.indexOf('?');
            if (queryStart > 0) {
                this.path = remaining.substring(0, queryStart);
                this.queryParameters = remaining.substring(queryStart + 1);
            } else {
                this.path = remaining;
                this.queryParameters = "";
            }
        }
        
        this.statusCode = statusCode;
        this.responseLength = responseLength;
        this.responseTime = 0; // 默认设置为0
        this.timestamp = new Date(timestamp);
        this.requestData = requestData;
        this.responseData = responseData;
    }
    
    /**
     * 将URL解析为各个组件
     * 
     * @param url 原始URL
     */
    @SuppressWarnings("unused")
    private void parseUrl(String url) {
        try {
            // 处理没有协议的URL
            String normalizedUrl = url;
            if (!normalizedUrl.startsWith("http://") && !normalizedUrl.startsWith("https://")) {
                normalizedUrl = "http://" + normalizedUrl;
            }
            
            URL parsedUrl = new URL(normalizedUrl);
            
            // 设置协议
            this.protocol = parsedUrl.getProtocol();
            
            // 设置域名
            this.domain = parsedUrl.getHost();
            
            // 设置路径，如果为空则使用"/"
            this.path = parsedUrl.getPath();
            if (this.path == null || this.path.isEmpty()) {
                this.path = "/";
            }
            
            // 设置查询参数
            this.queryParameters = parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "";
            
        } catch (MalformedURLException e) {
            // 如果URL解析失败，尝试简单拆分
            this.protocol = url.startsWith("https://") ? "https" : "http";
            
            String remaining = url;
            
            // 移除协议部分
            if (remaining.startsWith("http://")) {
                remaining = remaining.substring(7);
            } else if (remaining.startsWith("https://")) {
                remaining = remaining.substring(8);
            }
            
            // 提取域名
            int pathStart = remaining.indexOf('/');
            if (pathStart > 0) {
                this.domain = remaining.substring(0, pathStart);
                remaining = remaining.substring(pathStart);
            } else {
                this.domain = remaining;
                remaining = "/";
            }
            
            // 提取路径和查询参数
            int queryStart = remaining.indexOf('?');
            if (queryStart > 0) {
                this.path = remaining.substring(0, queryStart);
                this.queryParameters = remaining.substring(queryStart + 1);
            } else {
                this.path = remaining;
                this.queryParameters = "";
            }
        }
    }
    
    // Getters and Setters
    
    public int getId() {
        return id;
    }
    
    public void setId(int id) {
        this.id = id;
    }
    
    public int getRequestId() {
        return requestId;
    }
    
    public void setRequestId(int requestId) {
        this.requestId = requestId;
    }
    
    public String getProtocol() {
        return protocol;
    }
    
    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }
    
    public String getDomain() {
        return domain;
    }
    
    public void setDomain(String domain) {
        this.domain = domain;
    }
    
    public String getPath() {
        return path;
    }
    
    public void setPath(String path) {
        this.path = path;
    }
    
    public String getQueryParameters() {
        return queryParameters;
    }
    
    public void setQueryParameters(String queryParameters) {
        this.queryParameters = queryParameters;
    }
    
    public String getMethod() {
        return method;
    }
    
    public void setMethod(String method) {
        this.method = method;
    }
    
    public int getStatusCode() {
        return statusCode;
    }
    
    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }
    
    public int getResponseLength() {
        return responseLength;
    }
    
    public void setResponseLength(int responseLength) {
        this.responseLength = responseLength;
    }
    
    public int getResponseTime() {
        return responseTime;
    }
    
    public void setResponseTime(int responseTime) {
        this.responseTime = responseTime;
    }
    
    public Date getTimestamp() {
        return timestamp;
    }
    
    public void setTimestamp(Date timestamp) {
        this.timestamp = timestamp;
    }
    
    public String getComment() {
        return comment;
    }
    
    public void setComment(String comment) {
        this.comment = (comment != null) ? comment : "";
    }
    
    public Color getColor() {
        return color;
    }
    
    public void setColor(Color color) {
        this.color = color;
    }
    
    public byte[] getRequestData() {
        return requestData;
    }
    
    public void setRequestData(byte[] requestData) {
        this.requestData = requestData;
    }
    
    public byte[] getResponseData() {
        return responseData;
    }
    
    public void setResponseData(byte[] responseData) {
        this.responseData = responseData;
    }
    
    /**
     * 获取截断后的备注文本用于表格显示
     */
    public String getTruncatedComment(int maxLength) {
        if (comment == null || comment.trim().isEmpty()) {
            return "";
        }
        
        comment = comment.trim();
        if (comment.length() <= maxLength) {
            return comment;
        }
        
        return comment.substring(0, maxLength) + "...";
    }
    
    /**
     * 获取完整URL
     */
    public String getUrl() {
        StringBuilder url = new StringBuilder();
        url.append(protocol).append("://").append(domain).append(path);
        if (queryParameters != null && !queryParameters.isEmpty()) {
            url.append("?").append(queryParameters);
        }
        return url.toString();
    }
    
    @Override
    public String toString() {
        return String.format("%s %s://%s%s [%d]", 
                method, protocol, domain, path, statusCode);
    }
} 
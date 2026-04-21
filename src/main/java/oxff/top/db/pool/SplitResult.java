package oxff.top.db.pool;

/**
 * HTTP 数据分割结果值对象
 * 将原始 HTTP 字节流分割为头部和主体两部分
 */
public class SplitResult {
    private final byte[] headers;
    private final byte[] body;

    public SplitResult(byte[] headers, byte[] body) {
        this.headers = headers;
        this.body = body;
    }

    /**
     * 获取头部字节数据（包含请求行/状态行 + 所有头部 + 空行 \r\n\r\n）
     */
    public byte[] getHeaders() {
        return headers;
    }

    /**
     * 获取主体字节数据（可能为空数组，不为 null）
     */
    public byte[] getBody() {
        return body;
    }

    /**
     * 判断主体是否为空
     */
    public boolean hasBody() {
        return body != null && body.length > 0;
    }
}

package org.oxff.repeater.db.pool;

/**
 * HTTP 数据分割器
 * 将原始 HTTP 字节流分割为头部块和主体块
 * 使用手动扫描方式，不依赖 Burp API
 */
public class ContentSplitter {

    /**
     * 分割 HTTP 请求数据
     *
     * @param rawRequest 原始请求字节
     * @return 分割结果
     */
    public SplitResult splitRequest(byte[] rawRequest) {
        if (rawRequest == null || rawRequest.length == 0) {
            return new SplitResult(new byte[0], new byte[0]);
        }

        int bodyOffset = findBodyOffsetManual(rawRequest);
        return splitAt(rawRequest, bodyOffset);
    }

    /**
     * 分割 HTTP 响应数据
     *
     * @param rawResponse 原始响应字节
     * @return 分割结果
     */
    public SplitResult splitResponse(byte[] rawResponse) {
        if (rawResponse == null || rawResponse.length == 0) {
            return new SplitResult(new byte[0], new byte[0]);
        }

        int bodyOffset = findBodyOffsetManual(rawResponse);
        return splitAt(rawResponse, bodyOffset);
    }

    /**
     * 手动扫描 \r\n\r\n 定位 body 偏移量
     * body 从 \r\n\r\n 之后开始
     */
    public int findBodyOffsetManual(byte[] data) {
        if (data == null) {
            return 0;
        }
        for (int i = 0; i < data.length - 3; i++) {
            if (data[i] == '\r' && data[i + 1] == '\n'
                    && data[i + 2] == '\r' && data[i + 3] == '\n') {
                return i + 4;
            }
        }
        return data.length;
    }

    /**
     * 在指定偏移量处分割字节数组
     */
    private SplitResult splitAt(byte[] data, int offset) {
        if (offset <= 0) {
            return new SplitResult(new byte[0], data);
        }
        if (offset >= data.length) {
            return new SplitResult(data, new byte[0]);
        }

        byte[] headers = new byte[offset];
        byte[] body = new byte[data.length - offset];
        System.arraycopy(data, 0, headers, 0, offset);
        System.arraycopy(data, offset, body, 0, body.length);

        return new SplitResult(headers, body);
    }
}

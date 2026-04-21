package oxff.top.db.pool;

import burp.BurpExtender;

/**
 * HTTP 数据分割器
 * 将原始 HTTP 字节流分割为头部块和主体块
 */
public class ContentSplitter {

    /**
     * 分割 HTTP 请求数据
     * 优先使用 Burp API 分析器，不可用时回退到手动扫描
     *
     * @param rawRequest 原始请求字节
     * @return 分割结果
     */
    public SplitResult splitRequest(byte[] rawRequest) {
        if (rawRequest == null || rawRequest.length == 0) {
            return new SplitResult(new byte[0], new byte[0]);
        }

        int bodyOffset = findRequestBodyOffset(rawRequest);
        return splitAt(rawRequest, bodyOffset);
    }

    /**
     * 分割 HTTP 响应数据
     * 优先使用 Burp API 分析器，不可用时回退到手动扫描
     *
     * @param rawResponse 原始响应字节
     * @return 分割结果
     */
    public SplitResult splitResponse(byte[] rawResponse) {
        if (rawResponse == null || rawResponse.length == 0) {
            return new SplitResult(new byte[0], new byte[0]);
        }

        int bodyOffset = findResponseBodyOffset(rawResponse);
        return splitAt(rawResponse, bodyOffset);
    }

    /**
     * 使用 Burp API 查找请求 body 偏移量
     */
    private int findRequestBodyOffset(byte[] rawRequest) {
        try {
            if (BurpExtender.helpers != null) {
                return BurpExtender.helpers.analyzeRequest(rawRequest).getBodyOffset();
            }
        } catch (Exception e) {
            // Burp helpers 不可用，回退到手动方式
        }
        return findBodyOffsetManual(rawRequest);
    }

    /**
     * 使用 Burp API 查找响应 body 偏移量
     */
    private int findResponseBodyOffset(byte[] rawResponse) {
        try {
            if (BurpExtender.helpers != null) {
                return BurpExtender.helpers.analyzeResponse(rawResponse).getBodyOffset();
            }
        } catch (Exception e) {
            // Burp helpers 不可用，回退到手动方式
        }
        return findBodyOffsetManual(rawResponse);
    }

    /**
     * 手动扫描 \r\n\r\n 定位 body 偏移量（离线/迁移模式）
     * body 从 \r\n\r\n 之后开始
     */
    public int findBodyOffsetManual(byte[] data) {
        if (data == null) {
            return 0;
        }
        for (int i = 0; i < data.length - 3; i++) {
            if (data[i] == '\r' && data[i + 1] == '\n'
                    && data[i + 2] == '\r' && data[i + 3] == '\n') {
                return i + 4; // body 从 \r\n\r\n 之后开始
            }
        }
        // 没找到空行分隔符，整个数据都是头部
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

package oxff.top.privilege.report;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * 集中式二进制内容分析引擎
 * 格式无关，产出数据结构供各 ReportGenerator 格式化输出
 */
public class BinaryContentRenderer {

    // ========== 分级阈值 ==========

    /** 小文件阈值: 100KB */
    private static final int SMALL_THRESHOLD = 100 * 1024;
    /** 中文件阈值: 5MB */
    private static final int MEDIUM_THRESHOLD = 5 * 1024 * 1024;
    /** hex预览字节数 - 小文件 */
    private static final int HEX_PREVIEW_SMALL = 256;
    /** hex预览字节数 - 中文件 */
    private static final int HEX_PREVIEW_MEDIUM = 512;
    /** hex预览字节数 - 大文件(元数据卡内的简短预览) */
    private static final int HEX_PREVIEW_LARGE = 128;
    /** multipart二进制part的预览字节数 */
    private static final int MULTIPART_BINARY_PREVIEW = 128;

    // ========== 数据结构 ==========

    /** 二进制大小分级 */
    public enum BinarySizeTier {
        SMALL,   // < 100KB
        MEDIUM,  // 100KB - 5MB
        LARGE    // > 5MB
    }

    /** 二进制内容分析结果 */
    public static class BinaryAnalysisResult {
        public final boolean isBinary;
        public final String contentType;
        public final String contentCategory;
        public final long contentLength;
        public final String sha256Hash;
        public final String humanSize;
        public final byte[] previewBytes;
        public final String base64Data;
        public final List<MultipartPartInfo> multipartParts;

        public BinaryAnalysisResult(boolean isBinary, String contentType, String contentCategory,
                                    long contentLength, String sha256Hash, String humanSize,
                                    byte[] previewBytes, String base64Data,
                                    List<MultipartPartInfo> multipartParts) {
            this.isBinary = isBinary;
            this.contentType = contentType;
            this.contentCategory = contentCategory;
            this.contentLength = contentLength;
            this.sha256Hash = sha256Hash;
            this.humanSize = humanSize;
            this.previewBytes = previewBytes;
            this.base64Data = base64Data;
            this.multipartParts = multipartParts;
        }
    }

    /** Multipart 单 part 信息 */
    public static class MultipartPartInfo {
        public final String name;
        public final String fileName;
        public final String partContentType;
        public final boolean isText;
        public final String textContent;
        public final byte[] binaryPreview;
        public final long partSize;

        public MultipartPartInfo(String name, String fileName, String partContentType,
                                 boolean isText, String textContent, byte[] binaryPreview,
                                 long partSize) {
            this.name = name;
            this.fileName = fileName;
            this.partContentType = partContentType;
            this.isText = isText;
            this.textContent = textContent;
            this.binaryPreview = binaryPreview;
            this.partSize = partSize;
        }
    }

    /** 分级渲染内容 */
    public static class TieredRenderContent {
        public final BinarySizeTier tier;
        public final String metadataCardText;
        public final String hexDumpPreview;
        public final String base64Content;
        public final List<MultipartPartInfo> multipartParts;
        public final String contentType;
        public final String contentCategory;
        public final String humanSize;

        public TieredRenderContent(BinarySizeTier tier, String metadataCardText,
                                   String hexDumpPreview, String base64Content,
                                   List<MultipartPartInfo> multipartParts,
                                   String contentType, String contentCategory,
                                   String humanSize) {
            this.tier = tier;
            this.metadataCardText = metadataCardText;
            this.hexDumpPreview = hexDumpPreview;
            this.base64Content = base64Content;
            this.multipartParts = multipartParts;
            this.contentType = contentType;
            this.contentCategory = contentCategory;
            this.humanSize = humanSize;
        }
    }

    // ========== 核心分析方法 ==========

    /**
     * 分析 body 内容
     *
     * @param body              原始 body 字节
     * @param contentTypeHeader Content-Type header 值（可为 null）
     * @return 分析结果
     */
    public BinaryAnalysisResult analyzeBody(byte[] body, String contentTypeHeader) {
        if (body == null || body.length == 0) {
            return new BinaryAnalysisResult(false, "text/plain", "text",
                    0, "", "0 bytes", new byte[0], null, null);
        }

        boolean binary = isBinaryBody(body);
        String contentType = contentTypeHeader != null ? contentTypeHeader : "application/octet-stream";
        String category = classifyContentType(contentType);
        long length = body.length;
        String sha256 = computeSha256Hex(body);
        String humanSize = formatHumanSize(length);

        // 预览字节
        int previewLen = Math.min(body.length, HEX_PREVIEW_MEDIUM);
        byte[] preview = new byte[previewLen];
        System.arraycopy(body, 0, preview, 0, previewLen);

        // base64: 仅小文件
        String base64 = null;
        if (!binary && length < SMALL_THRESHOLD) {
            // 文本内容不需要 base64
            base64 = null;
        } else if (binary && length < SMALL_THRESHOLD) {
            base64 = Base64.getEncoder().encodeToString(body);
        }

        // multipart 解析
        List<MultipartPartInfo> multipartParts = null;
        if (contentType.contains("multipart/form-data")) {
            try {
                multipartParts = parseMultipart(body, contentType);
            } catch (Exception e) {
                // 解析失败，退化为不透明二进制
                multipartParts = null;
            }
        }

        return new BinaryAnalysisResult(binary, contentType, category, length,
                sha256, humanSize, preview, base64, multipartParts);
    }

    /**
     * 按分级规则生成渲染内容
     */
    public TieredRenderContent createTieredContent(BinaryAnalysisResult analysis) {
        if (analysis == null || analysis.contentLength == 0) {
            return new TieredRenderContent(BinarySizeTier.SMALL, "", "", null, null,
                    "text/plain", "text", "0 bytes");
        }

        BinarySizeTier tier;
        if (analysis.contentLength < SMALL_THRESHOLD) {
            tier = BinarySizeTier.SMALL;
        } else if (analysis.contentLength < MEDIUM_THRESHOLD) {
            tier = BinarySizeTier.MEDIUM;
        } else {
            tier = BinarySizeTier.LARGE;
        }

        // 元数据卡
        String metadataCard = buildMetadataCard(analysis, tier);

        // hex dump 预览
        String hexDump = null;
        if (tier == BinarySizeTier.SMALL) {
            hexDump = generateHexDump(analysis.previewBytes, HEX_PREVIEW_SMALL);
        } else if (tier == BinarySizeTier.MEDIUM) {
            hexDump = generateHexDump(analysis.previewBytes, HEX_PREVIEW_MEDIUM);
        }
        // LARGE tier: 无 hex dump

        return new TieredRenderContent(tier, metadataCard, hexDump, analysis.base64Data,
                analysis.multipartParts, analysis.contentType, analysis.contentCategory,
                analysis.humanSize);
    }

    /**
     * 构建纯文本元数据卡
     */
    private String buildMetadataCard(BinaryAnalysisResult analysis, BinarySizeTier tier) {
        StringBuilder sb = new StringBuilder();
        sb.append("Binary Content\n");
        sb.append("Content-Type: ").append(analysis.contentType).append("\n");
        sb.append("Content-Length: ").append(analysis.contentLength).append(" bytes (").append(analysis.humanSize).append(")\n");
        sb.append("SHA-256: ").append(analysis.sha256Hash).append("\n");
        if (analysis.multipartParts != null && !analysis.multipartParts.isEmpty()) {
            sb.append("Multipart Parts: ").append(analysis.multipartParts.size()).append("\n");
        }
        // 大文件显示简短 hex 预览
        if (tier == BinarySizeTier.LARGE && analysis.previewBytes != null && analysis.previewBytes.length > 0) {
            sb.append("Preview (first ").append(HEX_PREVIEW_LARGE).append(" bytes):\n");
            sb.append(generateHexDump(analysis.previewBytes, HEX_PREVIEW_LARGE));
        }
        return sb.toString();
    }

    // ========== Content-Type 提取 ==========

    /**
     * 从 HTTP 响应字节中提取 Content-Type
     */
    public static String extractContentTypeFromResponse(byte[] responseData) {
        if (responseData == null || responseData.length == 0) return "application/octet-stream";
        try {
            HttpResponse response = HttpResponse.httpResponse(ByteArray.byteArray(responseData));
            for (HttpHeader header : response.headers()) {
                if ("Content-Type".equalsIgnoreCase(header.name())) {
                    return header.value();
                }
            }
        } catch (Exception ignored) {
            // Montoya 解析失败，回退到原始扫描
        }
        return fallbackExtractContentType(responseData);
    }

    /**
     * 从 HTTP 请求字节中提取 Content-Type
     */
    public static String extractContentTypeFromRequest(byte[] requestData) {
        if (requestData == null || requestData.length == 0) return "application/octet-stream";
        try {
            HttpRequest request = HttpRequest.httpRequest(ByteArray.byteArray(requestData));
            for (HttpHeader header : request.headers()) {
                if ("Content-Type".equalsIgnoreCase(header.name())) {
                    return header.value();
                }
            }
        } catch (Exception ignored) {
            // Montoya 解析失败，回退到原始扫描
        }
        return fallbackExtractContentType(requestData);
    }

    /**
     * 回退方案: 在原始字节中扫描 Content-Type header
     */
    private static String fallbackExtractContentType(byte[] httpMessage) {
        try {
            // 只扫描 header 部分 (到第一个 \r\n\r\n)
            int headerEnd = findHeaderEnd(httpMessage);
            if (headerEnd < 0) headerEnd = Math.min(httpMessage.length, 8192);
            String headerStr = new String(httpMessage, 0, headerEnd, StandardCharsets.ISO_8859_1);

            for (String line : headerStr.split("\r\n")) {
                if (line.toLowerCase().startsWith("content-type:")) {
                    return line.substring("content-type:".length()).trim();
                }
            }
        } catch (Exception ignored) {
        }
        return "application/octet-stream";
    }

    /**
     * 查找 HTTP header 结束位置 (\r\n\r\n)
     */
    private static int findHeaderEnd(byte[] data) {
        for (int i = 0; i < data.length - 3; i++) {
            if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n') {
                return i;
            }
        }
        return -1;
    }

    // ========== 二进制检测 ==========

    /**
     * 检测是否为二进制 body
     * 采样前 1024 字节，非打印字符占比 >30% 则判定为二进制
     */
    private boolean isBinaryBody(byte[] data) {
        if (data == null || data.length == 0) return false;
        int nonPrintable = 0;
        int checkLen = Math.min(data.length, 1024);
        for (int i = 0; i < checkLen; i++) {
            byte b = data[i];
            if (b < 0x09 || (b > 0x0D && b < 0x20) || b == 0x7F) {
                nonPrintable++;
            }
        }
        return (double) nonPrintable / checkLen > 0.3;
    }

    // ========== Hex Dump 生成 ==========

    /**
     * 生成标准 hex dump (偏移量-hex-ASCII 格式)
     * 输出仅含 ASCII 字符，PDF Latin-1 渲染安全
     *
     * @param data     原始字节
     * @param maxBytes 最大预览字节数
     * @return hex dump 字符串
     */
    public static String generateHexDump(byte[] data, int maxBytes) {
        if (data == null || data.length == 0) return "";
        int len = Math.min(data.length, maxBytes);
        StringBuilder sb = new StringBuilder();
        for (int offset = 0; offset < len; offset += 16) {
            // 偏移量
            sb.append(String.format("%08x  ", offset));

            // hex 部分
            for (int i = 0; i < 16; i++) {
                if (offset + i < len) {
                    sb.append(String.format("%02x ", data[offset + i]));
                } else {
                    sb.append("   ");
                }
                if (i == 7) sb.append(" ");
            }

            // ASCII 部分
            sb.append(" |");
            for (int i = 0; i < 16; i++) {
                if (offset + i < len) {
                    int b = data[offset + i] & 0xFF;
                    sb.append((b >= 0x20 && b < 0x7F) ? (char) b : '.');
                } else {
                    sb.append(' ');
                }
            }
            sb.append("|\n");
        }
        return sb.toString();
    }

    // ========== SHA-256 ==========

    /**
     * 计算 SHA-256 哈希值，返回十六进制字符串
     */
    public static String computeSha256Hex(byte[] data) {
        if (data == null || data.length == 0) return "";
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "error";
        }
    }

    // ========== 人类可读大小 ==========

    /**
     * 格式化字节数为人类可读字符串
     */
    public static String formatHumanSize(long bytes) {
        if (bytes < 1024) return bytes + " bytes";
        if (bytes < 1024 * 1024) return String.format("%.2f KB", bytes / 1024.0);
        if (bytes < 1024L * 1024 * 1024) return String.format("%.2f MB", bytes / (1024.0 * 1024));
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }

    // ========== Multipart 解析 ==========

    /**
     * 解析 multipart/form-data body
     * 宽容解析: 任何失败退化为不透明二进制
     */
    public List<MultipartPartInfo> parseMultipart(byte[] body, String contentTypeHeader) {
        List<MultipartPartInfo> parts = new ArrayList<>();

        // 提取 boundary
        String boundary = extractBoundary(contentTypeHeader);
        if (boundary == null) return null;

        byte[] boundaryBytes = ("--" + boundary).getBytes(StandardCharsets.ISO_8859_1);
        byte[] endBoundaryBytes = ("--" + boundary + "--").getBytes(StandardCharsets.ISO_8859_1);

        // 查找所有 boundary 位置
        List<Integer> boundaryPositions = findAllOccurrences(body, boundaryBytes);
        if (boundaryPositions.size() < 2) return null;

        // 查找结束 boundary 位置，用于截断最后一个 part 的尾部数据
        int endBoundaryPosition = -1;
        List<Integer> endBoundaryPositions = findAllOccurrences(body, endBoundaryBytes);
        if (!endBoundaryPositions.isEmpty()) {
            endBoundaryPosition = endBoundaryPositions.get(endBoundaryPositions.size() - 1);
        }

        // 解析每个 part
        for (int i = 0; i < boundaryPositions.size() - 1; i++) {
            int partStart = boundaryPositions.get(i) + boundaryBytes.length;
            // 跳过 \r\n
            while (partStart < body.length && (body[partStart] == '\r' || body[partStart] == '\n')) {
                partStart++;
            }

            int partEnd = boundaryPositions.get(i + 1);

            // 如果下一个 boundary 是结束 boundary，则 part 内容截止到结束 boundary 之前
            // 并跳过后续 parts（结束 boundary 之后不应再有有效 part）
            if (endBoundaryPosition >= 0 && boundaryPositions.get(i + 1) == endBoundaryPosition) {
                // 去掉前导 \r\n
                while (partEnd > partStart && (body[partEnd - 1] == '\r' || body[partEnd - 1] == '\n')) {
                    partEnd--;
                }

                if (partStart < partEnd) {
                    try {
                        MultipartPartInfo part = parseSinglePart(body, partStart, partEnd);
                        if (part != null) parts.add(part);
                    } catch (Exception e) {
                        // 单 part 解析失败，跳过
                    }
                }
                // 结束 boundary 之后不再解析
                break;
            }

            // 去掉前导 \r\n
            while (partEnd > partStart && (body[partEnd - 1] == '\r' || body[partEnd - 1] == '\n')) {
                partEnd--;
            }

            if (partStart >= partEnd) continue;

            try {
                MultipartPartInfo part = parseSinglePart(body, partStart, partEnd);
                if (part != null) parts.add(part);
            } catch (Exception e) {
                // 单 part 解析失败，跳过
            }
        }

        return parts.isEmpty() ? null : parts;
    }

    /**
     * 从 Content-Type header 提取 boundary 参数
     */
    private String extractBoundary(String contentTypeHeader) {
        if (contentTypeHeader == null) return null;
        String lower = contentTypeHeader.toLowerCase();
        int idx = lower.indexOf("boundary=");
        if (idx < 0) return null;
        int start = idx + "boundary=".length();
        // 去除引号
        if (start < contentTypeHeader.length() && contentTypeHeader.charAt(start) == '"') {
            start++;
            int endQuote = contentTypeHeader.indexOf('"', start);
            if (endQuote < 0) return null;
            return contentTypeHeader.substring(start, endQuote);
        }
        // boundary 到分号或结尾
        int end = contentTypeHeader.indexOf(';', start);
        if (end < 0) end = contentTypeHeader.length();
        return contentTypeHeader.substring(start, end).trim();
    }

    /**
     * 在字节数组中查找所有模式出现位置
     */
    private List<Integer> findAllOccurrences(byte[] data, byte[] pattern) {
        List<Integer> positions = new ArrayList<>();
        for (int i = 0; i <= data.length - pattern.length; i++) {
            boolean match = true;
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) positions.add(i);
        }
        return positions;
    }

    /**
     * 解析单个 multipart part
     */
    private MultipartPartInfo parseSinglePart(byte[] body, int start, int end) {
        // 查找 part 内的 header/body 分隔 \r\n\r\n
        int headerEnd = -1;
        for (int i = start; i < end - 3; i++) {
            if (body[i] == '\r' && body[i + 1] == '\n' && body[i + 2] == '\r' && body[i + 3] == '\n') {
                headerEnd = i;
                break;
            }
        }
        if (headerEnd < 0) return null;

        String partHeaders = new String(body, start, headerEnd - start, StandardCharsets.ISO_8859_1);
        int bodyStart = headerEnd + 4;
        int bodyEnd = end;

        // 提取 part 的 Content-Disposition 和 Content-Type
        String name = null;
        String fileName = null;
        String partContentType = "text/plain";

        for (String line : partHeaders.split("\r\n")) {
            String lower = line.toLowerCase();
            if (lower.startsWith("content-disposition:")) {
                name = extractParam(line, "name");
                fileName = extractParam(line, "filename");
            } else if (lower.startsWith("content-type:")) {
                partContentType = line.substring("content-type:".length()).trim();
            }
        }

        int partSize = bodyEnd - bodyStart;
        byte[] partBody = new byte[partSize];
        System.arraycopy(body, bodyStart, partBody, 0, partSize);

        boolean isText = !isBinaryBody(partBody);

        if (isText) {
            String textContent = new String(partBody, StandardCharsets.UTF_8);
            // 限制文本长度
            if (textContent.length() > 50000) {
                textContent = textContent.substring(0, 50000) + "\n... [Truncated — total " + partSize + " bytes]";
            }
            return new MultipartPartInfo(name, fileName, partContentType, true,
                    textContent, null, partSize);
        } else {
            byte[] preview = new byte[Math.min(partSize, MULTIPART_BINARY_PREVIEW)];
            System.arraycopy(partBody, 0, preview, 0, preview.length);
            return new MultipartPartInfo(name, fileName, partContentType, false,
                    null, preview, partSize);
        }
    }

    /**
     * 从 header 行中提取参数值 (如 name="value")
     */
    private String extractParam(String headerLine, String paramName) {
        String search = paramName + "=";
        int idx = headerLine.toLowerCase().indexOf(search.toLowerCase());
        if (idx < 0) return null;
        int start = idx + search.length();
        if (start >= headerLine.length()) return null;

        // 去引号
        if (headerLine.charAt(start) == '"') {
            start++;
            int endQuote = headerLine.indexOf('"', start);
            if (endQuote < 0) return null;
            return headerLine.substring(start, endQuote);
        }
        // 无引号，到分号或结尾
        int end = headerLine.indexOf(';', start);
        if (end < 0) end = headerLine.length();
        return headerLine.substring(start, end).trim();
    }

    // ========== Content-Type 分类 ==========

    /**
     * 将 MIME 类型映射到内容类别
     */
    public static String classifyContentType(String contentType) {
        if (contentType == null) return "binary";
        String lower = contentType.toLowerCase().split(";")[0].trim();

        if (lower.startsWith("image/")) return "image";
        if (lower.startsWith("audio/")) return "audio";
        if (lower.startsWith("video/")) return "video";
        if (lower.contains("multipart/")) return "multipart";
        if (lower.startsWith("text/") || lower.contains("json") || lower.contains("xml")
                || lower.contains("javascript") || lower.contains("yaml")) return "text";
        if (lower.contains("pdf") || lower.contains("msword") || lower.contains("officedocument")
                || lower.contains("spreadsheet") || lower.contains("presentation")) return "document";
        if (lower.contains("zip") || lower.contains("tar") || lower.contains("gzip")
                || lower.contains("rar") || lower.contains("7z") || lower.contains("x-xz")) return "archive";

        return "binary";
    }
}

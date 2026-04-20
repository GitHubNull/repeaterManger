package oxff.top.io;

import burp.BurpExtender;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import oxff.top.db.DatabaseManager;
import oxff.top.db.HistoryDAO;
import oxff.top.db.RequestDAO;
import oxff.top.http.RequestResponseRecord;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Color;
import java.awt.Component;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Postman Collection v2.1.0 导入器
 */
public class PostmanImporter {
    @SuppressWarnings("unused")
    private final DatabaseManager dbManager;
    private final RequestDAO requestDAO;
    private final HistoryDAO historyDAO;
    private final AtomicBoolean isImporting = new AtomicBoolean(false);

    public PostmanImporter() {
        this.dbManager = DatabaseManager.getInstance();
        this.requestDAO = new RequestDAO();
        this.historyDAO = new HistoryDAO();
    }

    /**
     * 从Postman Collection文件导入（UI入口）
     */
    public boolean importFromFile(Component parent) {
        if (isImporting.get()) {
            JOptionPane.showMessageDialog(parent,
                "另一个导入操作正在进行中，请稍后再试。", "导入繁忙", JOptionPane.WARNING_MESSAGE);
            return false;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("从Postman Collection导入");
        fileChooser.setFileFilter(new FileNameExtensionFilter("Postman Collection (*.json)", "json"));
        fileChooser.setAcceptAllFileFilterUsed(false);

        int result = fileChooser.showOpenDialog(parent);
        if (result != JFileChooser.APPROVE_OPTION) {
            return false;
        }

        File selectedFile = fileChooser.getSelectedFile();
        if (!selectedFile.exists() || !selectedFile.isFile()) {
            JOptionPane.showMessageDialog(parent, "所选文件不存在", "导入错误", JOptionPane.ERROR_MESSAGE);
            return false;
        }

        // 验证格式
        FormatDetector.ImportFormat format = FormatDetector.detectFormat(selectedFile);
        if (format != FormatDetector.ImportFormat.POSTMAN_V21) {
            JOptionPane.showMessageDialog(parent,
                "选择的文件不是有效的Postman Collection格式。", "格式错误", JOptionPane.ERROR_MESSAGE);
            return false;
        }

        int mergeOrReplace = JOptionPane.showOptionDialog(parent,
            "选择导入模式：\n- 合并：将导入数据添加到现有数据\n- 替换：清空现有数据后导入",
            "选择导入模式", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE,
            null, new String[]{"合并", "替换", "取消"}, "合并");

        if (mergeOrReplace == 2 || mergeOrReplace == JOptionPane.CLOSED_OPTION) {
            return false;
        }

        final boolean isReplace = (mergeOrReplace == 1);

        isImporting.set(true);
        CompletableFuture.runAsync(() -> {
            try {
                doImport(selectedFile, isReplace);
                JOptionPane.showMessageDialog(parent, "Postman Collection导入成功", "导入成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                BurpExtender.printError("[!] 导入Postman Collection失败: " + e.getMessage());
                JOptionPane.showMessageDialog(parent,
                    "导入失败: " + e.getMessage(), "导入错误", JOptionPane.ERROR_MESSAGE);
            } finally {
                isImporting.set(false);
            }
        });

        return true;
    }

    /**
     * 执行导入
     */
    private void doImport(File jsonFile, boolean replace) throws IOException, SQLException {
        if (replace) {
            requestDAO.clearAllRequests();
            historyDAO.clearAllHistory();
            BurpExtender.printOutput("[+] 已清空现有数据，准备导入Postman Collection");
        }

        try (FileInputStream fis = new FileInputStream(jsonFile);
             InputStreamReader reader = new InputStreamReader(fis, StandardCharsets.UTF_8)) {

            JsonObject collection = JsonParser.parseReader(reader).getAsJsonObject();
            JsonArray items = collection.getAsJsonArray("item");

            List<JsonObject> flatItems = flattenItems(items, "");
            BurpExtender.printOutput("[*] 发现 " + flatItems.size() + " 个Postman item");

            int requestCount = 0;
            int historyCount = 0;

            for (JsonObject item : flatItems) {
                if (!item.has("request")) {
                    continue;
                }

                JsonObject requestObj = item.getAsJsonObject("request");
                JsonArray responses = item.has("response") ? item.getAsJsonArray("response") : new JsonArray();

                // 解析URL
                UrlComponents url = parsePostmanUrl(requestObj.get("url"));
                String method = getString(requestObj, "method", "GET");

                // 解析headers
                List<PostmanHeader> headers = parseHeaders(requestObj);

                // 解析body
                BodyResult bodyResult = parseBody(requestObj);
                byte[] bodyBytes = bodyResult.bodyBytes;

                // 合并headers（如果body解析更新了Content-Type）
                if (bodyResult.contentType != null) {
                    headers = setOrUpdateHeader(headers, "Content-Type", bodyResult.contentType);
                }

                // 重建raw HTTP请求
                byte[] rawRequest = reconstructRawRequest(method, url, headers, bodyBytes);

                // 提取comment和color
                DescriptionParse desc = parseDescription(getString(requestObj, "description", ""));
                String itemName = getString(item, "name", "");
                String comment = desc.comment != null && !desc.comment.isEmpty() ? desc.comment : itemName;

                if (responses.size() > 0) {
                    // 有response → 导入为history
                    for (JsonElement respElem : responses) {
                        JsonObject respObj = respElem.getAsJsonObject();
                        RequestResponseRecord record = new RequestResponseRecord();
                        record.setRequestId(-1);
                        record.setMethod(method);
                        record.setProtocol(url.protocol);
                        record.setDomain(url.domain);
                        record.setPath(url.path);
                        record.setQueryParameters(url.query);
                        record.setStatusCode(getInt(respObj, "code", 0));

                        byte[] rawResponse = reconstructRawResponse(respObj);
                        record.setResponseData(rawResponse);
                        record.setResponseLength(rawResponse != null ? rawResponse.length : 0);
                        record.setResponseTime(parseResponseTime(respObj));
                        record.setRequestData(rawRequest);
                        record.setComment(comment);
                        if (desc.color != null && !desc.color.isEmpty()) {
                            try {
                                record.setColor(Color.decode(desc.color));
                            } catch (Exception e) {
                                // 忽略
                            }
                        }

                        historyDAO.saveHistory(record);
                        historyCount++;
                    }
                } else {
                    // 无response → 导入为request
                    int newId = requestDAO.saveRequest(url.protocol, url.domain, url.path, url.query, method, rawRequest);
                    if (newId > 0) {
                        if (comment != null && !comment.isEmpty()) {
                            requestDAO.updateRequestComment(newId, comment);
                        }
                        if (desc.color != null && !desc.color.isEmpty()) {
                            try {
                                requestDAO.updateRequestColor(newId, Color.decode(desc.color));
                            } catch (Exception e) {
                                // 忽略
                            }
                        }
                        requestCount++;
                    }
                }
            }

            BurpExtender.printOutput("[+] Postman Collection导入完成: " + requestCount + " 条请求, " + historyCount + " 条历史记录");
        }
    }

    /**
     * 扁平化Postman item数组（处理嵌套文件夹）
     */
    private List<JsonObject> flattenItems(JsonArray items, String parentPrefix) {
        List<JsonObject> result = new ArrayList<>();
        if (items == null) return result;

        for (JsonElement elem : items) {
            if (!elem.isJsonObject()) continue;
            JsonObject item = elem.getAsJsonObject();

            if (item.has("item") && item.get("item").isJsonArray()) {
                // 这是一个文件夹
                String folderName = getString(item, "name", "Folder");
                String newPrefix = parentPrefix.isEmpty() ? folderName : parentPrefix + " / " + folderName;
                result.addAll(flattenItems(item.getAsJsonArray("item"), newPrefix));
            } else {
                // 这是一个请求
                if (!parentPrefix.isEmpty()) {
                    String originalName = getString(item, "name", "Request");
                    item.addProperty("name", parentPrefix + " / " + originalName);
                }
                result.add(item);
            }
        }
        return result;
    }

    /**
     * 解析Postman URL
     */
    private UrlComponents parsePostmanUrl(JsonElement urlElement) {
        UrlComponents result = new UrlComponents();
        result.protocol = "http";
        result.domain = "localhost";
        result.path = "/";
        result.query = "";

        if (urlElement == null || urlElement.isJsonNull()) {
            return result;
        }

        if (urlElement.isJsonPrimitive()) {
            return parseUrlString(urlElement.getAsString());
        }

        if (urlElement.isJsonObject()) {
            JsonObject urlObj = urlElement.getAsJsonObject();

            // 优先使用raw
            if (urlObj.has("raw") && !urlObj.get("raw").isJsonNull()) {
                return parseUrlString(urlObj.get("raw").getAsString());
            }

            // 从组件构建
            result.protocol = getString(urlObj, "protocol", "http");

            // host
            if (urlObj.has("host")) {
                JsonElement hostElem = urlObj.get("host");
                if (hostElem.isJsonArray()) {
                    StringBuilder host = new StringBuilder();
                    for (JsonElement e : hostElem.getAsJsonArray()) {
                        if (host.length() > 0) host.append(".");
                        host.append(e.getAsString());
                    }
                    result.domain = host.toString();
                } else {
                    result.domain = hostElem.getAsString();
                }
            }

            // path
            if (urlObj.has("path")) {
                JsonElement pathElem = urlObj.get("path");
                if (pathElem.isJsonArray()) {
                    StringBuilder p = new StringBuilder();
                    for (JsonElement e : pathElem.getAsJsonArray()) {
                        if (p.length() > 0) p.append("/");
                        p.append(e.getAsString());
                    }
                    result.path = "/" + p.toString();
                } else {
                    result.path = pathElem.getAsString();
                    if (!result.path.startsWith("/")) {
                        result.path = "/" + result.path;
                    }
                }
            }

            // query
            if (urlObj.has("query")) {
                JsonElement queryElem = urlObj.get("query");
                if (queryElem.isJsonArray()) {
                    StringBuilder q = new StringBuilder();
                    for (JsonElement e : queryElem.getAsJsonArray()) {
                        JsonObject qObj = e.getAsJsonObject();
                        String key = getString(qObj, "key", "");
                        String value = getString(qObj, "value", "");
                        if (q.length() > 0) q.append("&");
                        q.append(urlEncode(key)).append("=").append(urlEncode(value));
                    }
                    result.query = q.toString();
                } else {
                    result.query = queryElem.getAsString();
                }
            }
        }

        return result;
    }

    private UrlComponents parseUrlString(String urlString) {
        UrlComponents result = new UrlComponents();
        result.protocol = "http";
        result.domain = "localhost";
        result.path = "/";
        result.query = "";

        if (urlString == null || urlString.isEmpty()) {
            return result;
        }

        try {
            URL url = new URL(urlString);
            result.protocol = url.getProtocol();
            result.domain = url.getHost();
            if (url.getPort() != -1) {
                result.domain += ":" + url.getPort();
            }
            result.path = url.getPath();
            if (result.path.isEmpty()) result.path = "/";
            result.query = url.getQuery() != null ? url.getQuery() : "";
        } catch (MalformedURLException e) {
            // 处理部分URL
            if (urlString.startsWith("/")) {
                result.path = urlString;
                int qIndex = urlString.indexOf('?');
                if (qIndex >= 0) {
                    result.path = urlString.substring(0, qIndex);
                    result.query = urlString.substring(qIndex + 1);
                }
            } else {
                result.domain = urlString;
            }
        }

        return result;
    }

    private List<PostmanHeader> parseHeaders(JsonObject requestObj) {
        List<PostmanHeader> headers = new ArrayList<>();
        if (!requestObj.has("header") || requestObj.get("header").isJsonNull()) {
            return headers;
        }

        JsonArray headerArray = requestObj.getAsJsonArray("header");
        for (JsonElement elem : headerArray) {
            JsonObject h = elem.getAsJsonObject();
            boolean disabled = h.has("disabled") && h.get("disabled").getAsBoolean();
            if (disabled) continue;

            String key = getString(h, "key", "");
            String value = getString(h, "value", "");
            if (!key.isEmpty()) {
                headers.add(new PostmanHeader(key, value));
            }
        }
        return headers;
    }

    private BodyResult parseBody(JsonObject requestObj) {
        BodyResult result = new BodyResult();
        if (!requestObj.has("body") || requestObj.get("body").isJsonNull()) {
            return result;
        }

        JsonObject body = requestObj.getAsJsonObject("body");
        String mode = getString(body, "mode", "");

        switch (mode) {
            case "raw":
                result.bodyBytes = getString(body, "raw", "").getBytes(StandardCharsets.UTF_8);
                break;
            case "urlencoded":
                result.bodyBytes = parseUrlEncodedBody(body);
                result.contentType = "application/x-www-form-urlencoded";
                break;
            case "formdata":
                result.bodyBytes = parseFormDataBody(body);
                result.contentType = "multipart/form-data; boundary=" + generateBoundary();
                break;
            case "graphql":
                result.bodyBytes = parseGraphQLBody(body);
                result.contentType = "application/json";
                break;
            case "file":
                result.bodyBytes = new byte[0];
                break;
            default:
                result.bodyBytes = new byte[0];
        }

        return result;
    }

    private byte[] parseUrlEncodedBody(JsonObject body) {
        StringBuilder sb = new StringBuilder();
        if (body.has("urlencoded") && body.get("urlencoded").isJsonArray()) {
            JsonArray params = body.getAsJsonArray("urlencoded");
            for (JsonElement elem : params) {
                JsonObject param = elem.getAsJsonObject();
                boolean disabled = param.has("disabled") && param.get("disabled").getAsBoolean();
                if (disabled) continue;

                String key = getString(param, "key", "");
                String value = getString(param, "value", "");
                if (sb.length() > 0) sb.append("&");
                sb.append(urlEncode(key)).append("=").append(urlEncode(value));
            }
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private String generateBoundary() {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder("----WebKitFormBoundary");
        java.util.Random random = new java.util.Random();
        for (int i = 0; i < 16; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }

    private byte[] parseFormDataBody(JsonObject body) {
        String boundary = generateBoundary();
        StringBuilder sb = new StringBuilder();

        if (body.has("formdata") && body.get("formdata").isJsonArray()) {
            JsonArray params = body.getAsJsonArray("formdata");
            for (JsonElement elem : params) {
                JsonObject param = elem.getAsJsonObject();
                boolean disabled = param.has("disabled") && param.get("disabled").getAsBoolean();
                if (disabled) continue;

                String key = getString(param, "key", "");
                String value = getString(param, "value", "");
                String type = getString(param, "type", "text");

                sb.append("--").append(boundary).append("\r\n");

                if ("file".equals(type)) {
                    String src = getString(param, "src", "");
                    sb.append("Content-Disposition: form-data; name=\"").append(key).append("\"; ");
                    sb.append("filename=\"").append(src).append("\"\r\n");
                    sb.append("Content-Type: application/octet-stream\r\n\r\n");
                    sb.append("\r\n");
                } else {
                    sb.append("Content-Disposition: form-data; name=\"").append(key).append("\"\r\n\r\n");
                    sb.append(value).append("\r\n");
                }
            }
        }
        sb.append("--").append(boundary).append("--\r\n");
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private byte[] parseGraphQLBody(JsonObject body) {
        if (body.has("graphql") && body.get("graphql").isJsonObject()) {
            JsonObject graphql = body.getAsJsonObject("graphql");
            JsonObject payload = new JsonObject();
            if (graphql.has("query")) {
                payload.addProperty("query", graphql.get("query").getAsString());
            }
            if (graphql.has("variables") && !graphql.get("variables").isJsonNull()) {
                String variables = graphql.get("variables").getAsString();
                try {
                    payload.add("variables", JsonParser.parseString(variables));
                } catch (Exception e) {
                    payload.addProperty("variables", variables);
                }
            }
            return payload.toString().getBytes(StandardCharsets.UTF_8);
        }
        return "{}".getBytes(StandardCharsets.UTF_8);
    }

    @SuppressWarnings("unused")
    private byte[] reconstructRawRequest(String method, UrlComponents url, List<PostmanHeader> headers, byte[] bodyBytes) {
        StringBuilder rawRequest = new StringBuilder();

        // Request line
        rawRequest.append(method).append(" ");
        rawRequest.append(url.path);
        if (!url.query.isEmpty()) {
            rawRequest.append("?").append(url.query);
        }
        rawRequest.append(" HTTP/1.1\r\n");

        // Host header
        rawRequest.append("Host: ").append(url.domain).append("\r\n");

        // 其他headers
        boolean hasHost = false;
        for (PostmanHeader header : headers) {
            if (header.key.equalsIgnoreCase("Host")) {
                hasHost = true;
                continue; // 避免重复Host
            }
            rawRequest.append(header.key).append(": ").append(header.value).append("\r\n");
        }

        // Content-Length
        if (bodyBytes != null && bodyBytes.length > 0) {
            rawRequest.append("Content-Length: ").append(bodyBytes.length).append("\r\n");
        }

        rawRequest.append("\r\n");

        byte[] headerBytes = rawRequest.toString().getBytes(StandardCharsets.UTF_8);

        if (bodyBytes != null && bodyBytes.length > 0) {
            byte[] fullRequest = new byte[headerBytes.length + bodyBytes.length];
            System.arraycopy(headerBytes, 0, fullRequest, 0, headerBytes.length);
            System.arraycopy(bodyBytes, 0, fullRequest, headerBytes.length, bodyBytes.length);
            return fullRequest;
        }

        return headerBytes;
    }

    private byte[] reconstructRawResponse(JsonObject responseObj) {
        StringBuilder rawResponse = new StringBuilder();

        int code = getInt(responseObj, "code", 200);
        String status = getString(responseObj, "status", "OK");

        rawResponse.append("HTTP/1.1 ").append(code).append(" ").append(status).append("\r\n");

        // Response headers
        if (responseObj.has("header") && responseObj.get("header").isJsonArray()) {
            JsonArray headers = responseObj.getAsJsonArray("header");
            for (JsonElement elem : headers) {
                JsonObject h = elem.getAsJsonObject();
                String key = getString(h, "key", "");
                String value = getString(h, "value", "");
                if (!key.isEmpty()) {
                    rawResponse.append(key).append(": ").append(value).append("\r\n");
                }
            }
        }

        rawResponse.append("\r\n");

        String body = getString(responseObj, "body", "");
        rawResponse.append(body);

        return rawResponse.toString().getBytes(StandardCharsets.UTF_8);
    }

    private DescriptionParse parseDescription(String description) {
        DescriptionParse result = new DescriptionParse();
        if (description == null || description.isEmpty()) {
            return result;
        }

        // 解析color
        Pattern colorPattern = Pattern.compile("<!--\\s*repeater-color:\\s*(#[0-9A-Fa-f]{6})\\s*-->");
        Matcher matcher = colorPattern.matcher(description);
        if (matcher.find()) {
            result.color = matcher.group(1);
        }

        // 移除color标记后的剩余文本作为comment
        result.comment = description.replaceAll("<!--\\s*repeater-color:\\s*#[0-9A-Fa-f]{6}\\s*-->\\s*\\n?\\n?", "").trim();

        return result;
    }

    private int parseResponseTime(JsonObject responseObj) {
        if (responseObj.has("name")) {
            String name = responseObj.get("name").getAsString();
            Pattern pattern = Pattern.compile("\\((\\d+)ms\\)");
            Matcher matcher = pattern.matcher(name);
            if (matcher.find()) {
                try {
                    return Integer.parseInt(matcher.group(1));
                } catch (NumberFormatException e) {
                    return 0;
                }
            }
        }
        return 0;
    }

    private List<PostmanHeader> setOrUpdateHeader(List<PostmanHeader> headers, String key, String value) {
        List<PostmanHeader> result = new ArrayList<>();
        boolean updated = false;
        for (PostmanHeader h : headers) {
            if (h.key.equalsIgnoreCase(key)) {
                result.add(new PostmanHeader(key, value));
                updated = true;
            } else {
                result.add(h);
            }
        }
        if (!updated) {
            result.add(new PostmanHeader(key, value));
        }
        return result;
    }

    private String getString(JsonObject obj, String key, String defaultValue) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            return obj.get(key).getAsString();
        }
        return defaultValue;
    }

    private int getInt(JsonObject obj, String key, int defaultValue) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            try {
                return obj.get(key).getAsInt();
            } catch (Exception e) {
                return defaultValue;
            }
        }
        return defaultValue;
    }

    private String urlEncode(String s) {
        try {
            return java.net.URLEncoder.encode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    private static class UrlComponents {
        String protocol;
        String domain;
        String path;
        String query;
    }

    private static class PostmanHeader {
        String key;
        String value;

        PostmanHeader(String key, String value) {
            this.key = key;
            this.value = value;
        }
    }

    private static class BodyResult {
        byte[] bodyBytes;
        String contentType;
    }

    private static class DescriptionParse {
        String comment = "";
        String color = "";
    }
}

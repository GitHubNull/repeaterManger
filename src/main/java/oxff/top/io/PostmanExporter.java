package oxff.top.io;

import burp.BurpExtender;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import oxff.top.db.DatabaseManager;
import oxff.top.db.history.HistoryReadDAO;
import oxff.top.db.RequestDAO;
import oxff.top.http.RequestResponseRecord;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Component;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Postman Collection v2.1.0 导出器
 */
public class PostmanExporter {
    private final DatabaseManager dbManager;
    private final RequestDAO requestDAO;
    private final HistoryReadDAO historyReadDAO;

    public PostmanExporter() {
        this.dbManager = DatabaseManager.getInstance();
        this.requestDAO = new RequestDAO();
        this.historyReadDAO = new HistoryReadDAO();
    }

    /**
     * 导出到Postman Collection v2.1.0格式
     */
    public boolean export(Component parent) {
        try {
            BurpExtender.printOutput("[+] 开始Postman Collection v2.1.0导出过程");

            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("导出Postman Collection");
            FileNameExtensionFilter filter = new FileNameExtensionFilter("Postman Collection (*.json)", "json");
            fileChooser.setFileFilter(filter);
            fileChooser.setSelectedFile(new File(
                    oxff.top.config.DatabaseConfig.generateSessionDirectoryName() + ".json"));

            int result = fileChooser.showSaveDialog(parent);
            if (result != JFileChooser.APPROVE_OPTION) {
                return false;
            }

            File outputFile = fileChooser.getSelectedFile();
            if (!outputFile.getName().toLowerCase().endsWith(".json")) {
                outputFile = new File(outputFile.getAbsolutePath() + ".json");
            }

            if (outputFile.exists()) {
                int overwrite = JOptionPane.showConfirmDialog(
                    parent, "文件已存在，是否覆盖？", "确认覆盖", JOptionPane.YES_NO_OPTION);
                if (overwrite != JOptionPane.YES_OPTION) {
                    return false;
                }
            }

            exportToPostman(outputFile, parent);
            return true;

        } catch (Exception e) {
            BurpExtender.printError("[!] 导出Postman Collection失败: " + e.getMessage());
            JOptionPane.showMessageDialog(parent,
                "导出失败: " + e.getMessage(), "导出错误", JOptionPane.ERROR_MESSAGE);
            return false;
        }
    }

    private void exportToPostman(File outputFile, Component parent) throws IOException {
        dbManager.checkDatabaseStatus();

        List<Map<String, Object>> requests = requestDAO.getAllRequests();
        List<RequestResponseRecord> history = historyReadDAO.getAllHistory();

        BurpExtender.printOutput("[*] 从数据库获取到 " + requests.size() + " 条请求记录和 " +
                              history.size() + " 条历史记录");

        // 构建Postman Collection
        JsonObject collection = new JsonObject();

        // info对象
        JsonObject info = new JsonObject();
        info.addProperty("_postman_id", UUID.randomUUID().toString());
        info.addProperty("name", "Enhanced Repeater Export - " + new Date().toString());
        info.addProperty("description", "Exported from Enhanced Repeater Manager");
        info.addProperty("schema", "https://schema.getpostman.com/json/collection/v2.1.0/collection.json");
        collection.add("info", info);

        // item数组
        JsonArray items = new JsonArray();

        // 导出请求
        for (Map<String, Object> request : requests) {
            items.add(exportRequestToPostmanItem(request));
        }

        // 导出历史记录（带response）
        for (RequestResponseRecord record : history) {
            items.add(exportHistoryToPostmanItem(record));
        }

        collection.add("item", items);

        // 写入文件
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try (FileWriter writer = new FileWriter(outputFile)) {
            writer.write(gson.toJson(collection));
        }

        int totalItems = requests.size() + history.size();
        BurpExtender.printOutput("[+] Postman Collection导出成功: " + outputFile.getAbsolutePath() +
                              "，包含 " + totalItems + " 个item");

        JOptionPane.showMessageDialog(parent,
            "Postman Collection导出成功！\n已导出 " + totalItems + " 个请求/历史记录。",
            "导出成功", JOptionPane.INFORMATION_MESSAGE);
    }

    private JsonObject exportRequestToPostmanItem(Map<String, Object> request) {
        JsonObject item = new JsonObject();

        String method = (String) request.getOrDefault("method", "GET");
        String protocol = (String) request.getOrDefault("protocol", "http");
        String domain = (String) request.getOrDefault("domain", "localhost");
        String path = (String) request.getOrDefault("path", "/");
        String query = (String) request.getOrDefault("query", "");
        String comment = (String) request.getOrDefault("comment", "");
        Object colorObj = request.get("color");
        String color = colorObj != null ? colorObj.toString() : "";
        byte[] requestData = (byte[]) request.get("request_data");

        // 设置name
        String name = comment != null && !comment.trim().isEmpty() ? comment.trim()
            : method + " " + domain + (path != null && !path.equals("/") ? path : "");
        item.addProperty("name", name.length() > 100 ? name.substring(0, 100) + "..." : name);

        // 解析raw request
        ParsedHttpMessage parsed = parseRawRequest(requestData);

        // 如果raw request中有完整URL，优先使用
        if (parsed.requestTarget != null && (parsed.requestTarget.startsWith("http://") || parsed.requestTarget.startsWith("https://"))) {
            try {
                URL fullUrl = new URL(parsed.requestTarget);
                protocol = fullUrl.getProtocol();
                domain = fullUrl.getHost();
                path = fullUrl.getPath();
                if (path.isEmpty()) path = "/";
                query = fullUrl.getQuery() != null ? fullUrl.getQuery() : "";
            } catch (Exception e) {
                // 忽略解析错误，使用数据库中的值
            }
        }

        // request对象
        JsonObject requestObj = new JsonObject();
        requestObj.addProperty("method", parsed.method != null ? parsed.method : method);
        requestObj.add("header", parsed.headers);
        requestObj.add("url", buildUrlObject(protocol, domain, path, query));

        // description（嵌入color信息）
        StringBuilder desc = new StringBuilder();
        if (color != null && !color.isEmpty() && color.startsWith("java.awt.Color")) {
            // 提取hex颜色
            try {
                java.awt.Color c = (java.awt.Color) colorObj;
                String hex = String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
                desc.append("<!-- repeater-color: ").append(hex).append(" -->\n\n");
            } catch (Exception e) {
                // 忽略
            }
        } else if (color != null && !color.isEmpty()) {
            desc.append("<!-- repeater-color: ").append(color).append(" -->\n\n");
        }
        if (comment != null && !comment.isEmpty()) {
            desc.append(comment);
        }
        if (desc.length() > 0) {
            requestObj.addProperty("description", desc.toString());
        }

        // body
        if (parsed.body != null && !parsed.body.isEmpty()) {
            requestObj.add("body", buildBodyObject(parsed.body, parsed.contentType));
        }

        item.add("request", requestObj);
        item.add("response", new JsonArray());

        return item;
    }

    private JsonObject exportHistoryToPostmanItem(RequestResponseRecord record) {
        JsonObject item = new JsonObject();

        String method = record.getMethod() != null ? record.getMethod() : "GET";
        String protocol = record.getProtocol() != null ? record.getProtocol() : "http";
        String domain = record.getDomain() != null ? record.getDomain() : "localhost";
        String path = record.getPath() != null ? record.getPath() : "/";
        String query = record.getQueryParameters() != null ? record.getQueryParameters() : "";
        String comment = record.getComment() != null ? record.getComment() : "";

        String name = comment != null && !comment.trim().isEmpty() ? comment.trim()
            : method + " " + domain + (path != null && !path.equals("/") ? path : "");
        item.addProperty("name", name.length() > 100 ? name.substring(0, 100) + "..." : name);

        // 解析raw request
        ParsedHttpMessage parsedReq = parseRawRequest(record.getRequestData());

        // request对象
        JsonObject requestObj = new JsonObject();
        requestObj.addProperty("method", parsedReq.method != null ? parsedReq.method : method);
        requestObj.add("header", parsedReq.headers);
        requestObj.add("url", buildUrlObject(protocol, domain, path, query));

        // description
        StringBuilder desc = new StringBuilder();
        if (record.getColor() != null) {
            String hex = String.format("#%02x%02x%02x", record.getColor().getRed(), record.getColor().getGreen(), record.getColor().getBlue());
            desc.append("<!-- repeater-color: ").append(hex).append(" -->\n\n");
        }
        if (comment != null && !comment.isEmpty()) {
            desc.append(comment);
        }
        if (desc.length() > 0) {
            requestObj.addProperty("description", desc.toString());
        }

        if (parsedReq.body != null && !parsedReq.body.isEmpty()) {
            requestObj.add("body", buildBodyObject(parsedReq.body, parsedReq.contentType));
        }

        item.add("request", requestObj);

        // response数组
        JsonArray responses = new JsonArray();
        if (record.getResponseData() != null && record.getResponseData().length > 0) {
            responses.add(exportResponseToPostman(record));
        }
        item.add("response", responses);

        return item;
    }

    private JsonObject exportResponseToPostman(RequestResponseRecord record) {
        JsonObject response = new JsonObject();

        String statusText = getStatusText(record.getStatusCode());
        String responseName = record.getStatusCode() + " " + statusText;
        if (record.getResponseTime() > 0) {
            responseName += " (" + record.getResponseTime() + "ms)";
        }
        response.addProperty("name", responseName);

        // 解析raw response
        ParsedHttpMessage parsedResp = parseRawResponse(record.getResponseData());

        response.addProperty("status", parsedResp.statusText != null ? parsedResp.statusText : statusText);
        response.addProperty("code", record.getStatusCode());
        response.add("header", parsedResp.headers);
        response.addProperty("body", parsedResp.body != null ? parsedResp.body : "");

        // originalRequest
        JsonObject originalRequest = new JsonObject();
        originalRequest.addProperty("method", record.getMethod());
        originalRequest.add("header", new JsonArray());
        originalRequest.add("url", buildUrlObject(record.getProtocol(), record.getDomain(), record.getPath(), record.getQueryParameters()));
        response.add("originalRequest", originalRequest);

        return response;
    }

    private JsonObject buildUrlObject(String protocol, String domain, String path, String query) {
        JsonObject url = new JsonObject();

        StringBuilder raw = new StringBuilder();
        raw.append(protocol).append("://").append(domain);
        String normalizedPath = (path != null && !path.isEmpty()) ? path : "/";
        raw.append(normalizedPath);

        // host数组
        JsonArray host = new JsonArray();
        if (domain != null) {
            for (String part : domain.split("\\.")) {
                host.add(part);
            }
        }

        // path数组
        JsonArray pathArray = new JsonArray();
        String pathWithoutLeadingSlash = normalizedPath.startsWith("/") ? normalizedPath.substring(1) : normalizedPath;
        if (!pathWithoutLeadingSlash.isEmpty()) {
            for (String part : pathWithoutLeadingSlash.split("/")) {
                if (!part.isEmpty()) {
                    pathArray.add(part);
                }
            }
        }

        // query数组
        JsonArray queryArray = new JsonArray();
        if (query != null && !query.isEmpty()) {
            raw.append("?").append(query);
            for (String param : query.split("&")) {
                if (param.isEmpty()) continue;
                String[] kv = param.split("=", 2);
                JsonObject q = new JsonObject();
                q.addProperty("key", urlDecode(kv[0]));
                q.addProperty("value", kv.length > 1 ? urlDecode(kv[1]) : "");
                queryArray.add(q);
            }
        }

        url.addProperty("raw", raw.toString());
        url.addProperty("protocol", protocol);
        url.add("host", host);
        url.add("path", pathArray);
        if (queryArray.size() > 0) {
            url.add("query", queryArray);
        }

        return url;
    }

    private JsonObject buildBodyObject(String body, String contentType) {
        JsonObject bodyObj = new JsonObject();

        if (body == null || body.isEmpty()) {
            return bodyObj;
        }

        String lowerCT = contentType != null ? contentType.toLowerCase() : "";

        if (lowerCT.contains("application/x-www-form-urlencoded")) {
            bodyObj.addProperty("mode", "urlencoded");
            JsonArray urlencoded = new JsonArray();
            for (String param : body.split("&")) {
                if (param.isEmpty()) continue;
                String[] kv = param.split("=", 2);
                JsonObject p = new JsonObject();
                p.addProperty("key", urlDecode(kv[0]));
                p.addProperty("value", kv.length > 1 ? urlDecode(kv[1]) : "");
                p.addProperty("type", "text");
                urlencoded.add(p);
            }
            bodyObj.add("urlencoded", urlencoded);
        } else if (lowerCT.contains("multipart/form-data")) {
            bodyObj.addProperty("mode", "raw");
            bodyObj.addProperty("raw", body);
            JsonObject options = new JsonObject();
            JsonObject raw = new JsonObject();
            raw.addProperty("language", "text");
            options.add("raw", raw);
            bodyObj.add("options", options);
        } else if (lowerCT.contains("application/graphql") ||
                  (body.trim().startsWith("{\"query\"") || body.trim().startsWith("{\"operationName\""))) {
            bodyObj.addProperty("mode", "graphql");
            try {
                com.google.gson.JsonObject graphqlBody = com.google.gson.JsonParser.parseString(body).getAsJsonObject();
                JsonObject graphql = new JsonObject();
                if (graphqlBody.has("query")) {
                    graphql.addProperty("query", graphqlBody.get("query").getAsString());
                }
                if (graphqlBody.has("variables")) {
                    graphql.addProperty("variables", graphqlBody.get("variables").toString());
                }
                bodyObj.add("graphql", graphql);
            } catch (Exception e) {
                bodyObj.addProperty("mode", "raw");
                bodyObj.addProperty("raw", body);
            }
        } else {
            bodyObj.addProperty("mode", "raw");
            bodyObj.addProperty("raw", body);
            JsonObject options = new JsonObject();
            JsonObject raw = new JsonObject();
            if (lowerCT.contains("json")) {
                raw.addProperty("language", "json");
            } else if (lowerCT.contains("xml")) {
                raw.addProperty("language", "xml");
            } else if (lowerCT.contains("html")) {
                raw.addProperty("language", "html");
            } else {
                raw.addProperty("language", "text");
            }
            options.add("raw", raw);
            bodyObj.add("options", options);
        }

        return bodyObj;
    }

    private ParsedHttpMessage parseRawRequest(byte[] data) {
        ParsedHttpMessage result = new ParsedHttpMessage();
        if (data == null || data.length == 0) {
            return result;
        }

        String text;
        try {
            text = new String(data, StandardCharsets.UTF_8);
        } catch (Exception e) {
            text = new String(data, StandardCharsets.ISO_8859_1);
        }

        String[] parts = splitAtFirstDoubleCRLF(text);
        if (parts.length == 0) {
            return result;
        }

        String headerSection = parts[0];
        result.body = parts.length > 1 ? parts[1] : "";

        String[] lines = headerSection.split("\r\n");
        if (lines.length == 0) {
            return result;
        }

        // 解析请求行
        String[] firstLineParts = lines[0].split(" ", 3);
        if (firstLineParts.length >= 2) {
            result.method = firstLineParts[0];
            result.requestTarget = firstLineParts[1];
        }

        // 解析headers
        result.headers = new JsonArray();
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (line.isEmpty()) continue;
            int colonIndex = line.indexOf(':');
            if (colonIndex > 0) {
                JsonObject header = new JsonObject();
                String key = line.substring(0, colonIndex).trim();
                String value = line.substring(colonIndex + 1).trim();
                header.addProperty("key", key);
                header.addProperty("value", value);
                header.addProperty("type", "text");
                result.headers.add(header);

                if (key.equalsIgnoreCase("Content-Type")) {
                    result.contentType = value;
                }
            }
        }

        return result;
    }

    private ParsedHttpMessage parseRawResponse(byte[] data) {
        ParsedHttpMessage result = new ParsedHttpMessage();
        if (data == null || data.length == 0) {
            return result;
        }

        String text;
        try {
            text = new String(data, StandardCharsets.UTF_8);
        } catch (Exception e) {
            text = new String(data, StandardCharsets.ISO_8859_1);
        }

        String[] parts = splitAtFirstDoubleCRLF(text);
        if (parts.length == 0) {
            return result;
        }

        String headerSection = parts[0];
        result.body = parts.length > 1 ? parts[1] : "";

        String[] lines = headerSection.split("\r\n");
        if (lines.length == 0) {
            return result;
        }

        // 解析状态行: HTTP/1.1 200 OK
        String[] statusParts = lines[0].split(" ", 3);
        if (statusParts.length >= 2) {
            try {
                result.statusCode = Integer.parseInt(statusParts[1]);
            } catch (NumberFormatException e) {
                result.statusCode = 0;
            }
            result.statusText = statusParts.length > 2 ? statusParts[2] : "";
        }

        // 解析headers
        result.headers = new JsonArray();
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (line.isEmpty()) continue;
            int colonIndex = line.indexOf(':');
            if (colonIndex > 0) {
                JsonObject header = new JsonObject();
                header.addProperty("key", line.substring(0, colonIndex).trim());
                header.addProperty("value", line.substring(colonIndex + 1).trim());
                result.headers.add(header);
            }
        }

        return result;
    }

    private String[] splitAtFirstDoubleCRLF(String text) {
        int index = text.indexOf("\r\n\r\n");
        if (index >= 0) {
            return new String[]{text.substring(0, index), text.substring(index + 4)};
        }
        // 尝试只用\n\n
        index = text.indexOf("\n\n");
        if (index >= 0) {
            return new String[]{text.substring(0, index), text.substring(index + 2)};
        }
        return new String[]{text};
    }

    private String urlDecode(String s) {
        try {
            return java.net.URLDecoder.decode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    private String getStatusText(int code) {
        switch (code) {
            case 200: return "OK";
            case 201: return "Created";
            case 204: return "No Content";
            case 301: return "Moved Permanently";
            case 302: return "Found";
            case 304: return "Not Modified";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 500: return "Internal Server Error";
            case 502: return "Bad Gateway";
            case 503: return "Service Unavailable";
            default: return "";
        }
    }

    private static class ParsedHttpMessage {
        String method;
        String requestTarget;
        JsonArray headers;
        String body;
        String contentType;
        @SuppressWarnings("unused")
        int statusCode;
        String statusText;
    }
}

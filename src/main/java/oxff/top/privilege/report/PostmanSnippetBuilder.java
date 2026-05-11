package oxff.top.privilege.report;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import oxff.top.http.RequestResponseRecord;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Postman Collection JSON 片段构建器
 * 生成可独立导入 Postman 的请求/响应 JSON 片段
 */
public class PostmanSnippetBuilder {

    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");

    private PostmanSnippetBuilder() {
    }

    /**
     * 从请求记录构建 Postman Collection JSON 片段
     */
    public static String build(RequestResponseRecord record) {
        if (record == null) {
            return "{}";
        }

        try {
            JsonObject item = new JsonObject();

            // Name
            String name = record.getMethod() + " " + record.getPath();
            if (record.getUserSessionName() != null && !record.getUserSessionName().isEmpty()) {
                name += " [" + record.getUserSessionName() + "]";
            }
            item.addProperty("name", name);

            // Request
            JsonObject request = new JsonObject();
            request.addProperty("method", record.getMethod());

            // URL
            JsonObject urlObj = buildUrlObject(record);
            request.add("url", urlObj);

            // Headers
            JsonArray headerArray = new JsonArray();
            byte[] requestData = record.getRequestData();
            if (requestData != null && requestData.length > 0) {
                try {
                    HttpRequest httpRequest = HttpRequest.httpRequest(ByteArray.byteArray(requestData));
                    List<HttpHeader> headers = httpRequest.headers();
                    if (headers != null) {
                        for (HttpHeader header : headers) {
                            JsonObject h = new JsonObject();
                            h.addProperty("key", header.name());
                            h.addProperty("value", header.value());
                            h.addProperty("type", "text");
                            headerArray.add(h);
                        }
                    }

                    // Body
                    byte[] body = httpRequest.body() != null ? httpRequest.body().getBytes() : null;
                    if (body != null && body.length > 0) {
                        JsonObject bodyObj = new JsonObject();
                        bodyObj.addProperty("mode", "raw");
                        bodyObj.addProperty("raw", BinaryContentRenderer.decodeBody(body,
                                BinaryContentRenderer.extractContentTypeFromRequest(requestData)));
                        request.add("body", bodyObj);
                    }
                } catch (Exception ignored) {
                }
            }
            request.add("header", headerArray);

            // Description with metadata
            StringBuilder desc = new StringBuilder();
            desc.append("**Privilege Test Finding**\n\n");
            if (record.getUserSessionName() != null) {
                desc.append("- Session: ").append(record.getUserSessionName()).append("\n");
            }
            if (record.getJudgment() != null) {
                desc.append("- Judgment: ").append(record.getJudgment()).append("\n");
            }
            desc.append("- Similarity: ").append(String.format("%.2f", record.getSimilarity())).append("\n");
            desc.append("- Timestamp: ").append(DATE_FORMAT.format(record.getTimestamp())).append("\n");
            request.addProperty("description", desc.toString());

            item.add("request", request);

            // Response (if available)
            byte[] responseData = record.getResponseData();
            if (responseData != null && responseData.length > 0) {
                JsonArray responseArray = new JsonArray();
                JsonObject response = new JsonObject();
                response.addProperty("name", "Response (" + record.getStatusCode() + ")");
                response.addProperty("status", getStatusText(record.getStatusCode()));
                response.addProperty("code", record.getStatusCode());
                response.addProperty("body", BinaryContentRenderer.decodeBody(responseData,
                        BinaryContentRenderer.extractContentTypeFromResponse(responseData)));
                responseArray.add(response);
                item.add("response", responseArray);
            }

            return item.toString();
        } catch (Exception e) {
            return "{}";
        }
    }

    /**
     * 构建 Postman Collection 完整结构（可独立导入）
     */
    public static String buildCollection(List<RequestResponseRecord> records) {
        JsonObject collection = new JsonObject();

        // Info
        JsonObject info = new JsonObject();
        info.addProperty("_postman_id", UUID.randomUUID().toString());
        info.addProperty("name", "Privilege Test - " + new SimpleDateFormat("yyyy-MM-dd HH:mm").format(new Date()));
        info.addProperty("schema", "https://schema.getpostman.com/json/collection/v2.1.0/collection.json");
        collection.add("info", info);

        // Items
        JsonArray items = new JsonArray();
        for (RequestResponseRecord record : records) {
            try {
                JsonObject item = new JsonObject();
                String name = record.getMethod() + " " + record.getPath();
                if (record.getUserSessionName() != null && !record.getUserSessionName().isEmpty()) {
                    name += " [" + record.getUserSessionName() + "]";
                }
                item.addProperty("name", name);

                JsonObject request = new JsonObject();
                request.addProperty("method", record.getMethod());
                request.add("url", buildUrlObject(record));
                items.add(item);
            } catch (Exception ignored) {
            }
        }
        collection.add("item", items);

        return collection.toString();
    }

    private static JsonObject buildUrlObject(RequestResponseRecord record) {
        JsonObject urlObj = new JsonObject();
        urlObj.addProperty("raw", record.getUrl());
        urlObj.addProperty("protocol", record.getProtocol());
        JsonArray hostArray = new JsonArray();
        hostArray.add(record.getDomain());
        urlObj.add("host", hostArray);

        String path = record.getPath() != null ? record.getPath() : "/";
        urlObj.addProperty("path", path);

        // Query params
        JsonArray queryArray = new JsonArray();
        if (record.getQueryParameters() != null && !record.getQueryParameters().isEmpty()) {
            String[] pairs = record.getQueryParameters().split("&");
            for (String pair : pairs) {
                String[] kv = pair.split("=", 2);
                JsonObject q = new JsonObject();
                q.addProperty("key", kv[0]);
                q.addProperty("value", kv.length > 1 ? kv[1] : "");
                queryArray.add(q);
            }
        }
        urlObj.add("query", queryArray);

        return urlObj;
    }

    private static String getStatusText(int statusCode) {
        if (statusCode >= 200 && statusCode < 300) return "OK";
        if (statusCode >= 300 && statusCode < 400) return "Redirect";
        if (statusCode >= 400 && statusCode < 500) return "Client Error";
        if (statusCode >= 500) return "Server Error";
        return "Unknown";
    }
}

package oxff.top.http;

import burp.BurpExtender;
import burp.IHttpService;
import burp.IRequestInfo;
import oxff.top.api.ApiExtractionEngine;
import oxff.top.api.ApiExtractionRule;
import oxff.top.api.ApiRuleManager;

import java.util.ArrayList;
import java.util.List;

/**
 * HTTP请求辅助工具类
 * 提供URL提取、IHttpService重建、API值计算等静态方法
 */
public class HttpRequestHelper {

    /**
     * 从请求中安全地提取URL信息
     *
     * @param requestBytes 请求字节数组
     * @param requestInfo 已分析的请求信息
     * @param httpService 当前的HTTP服务信息（可为null）
     * @return 提取的URL，如果提取失败则返回简化URL或默认值
     */
    public static String extractUrlFromRequest(byte[] requestBytes, IRequestInfo requestInfo, IHttpService httpService) {
        try {
            // 尝试使用标准方式获取URL
            return requestInfo.getUrl().toString();
        } catch (Exception e) {
            // 如果标准方式失败，从请求头中提取
            try {
                List<String> headers = requestInfo.getHeaders();
                String firstLine = headers.get(0); // 例如："GET /path HTTP/1.1"

                // 从Host头中提取主机名
                String host = "";
                for (String header : headers) {
                    if (header.toLowerCase().startsWith("host:")) {
                        host = header.substring(5).trim();
                        break;
                    }
                }

                // 构建URL
                String[] parts = firstLine.split("\\s+");
                if (parts.length >= 2) {
                    String path = parts[1];
                    if (!host.isEmpty()) {
                        // 综合判断是否为HTTPS
                        boolean isHttps = false;
                        // 1. 请求行URL包含https://（绝对URL形式）
                        if (path.startsWith("https://")) {
                            isHttps = true;
                        }
                        // 2. Host头包含443端口
                        if (host.contains(":443")) {
                            isHttps = true;
                        }
                        // 3. 如果有httpService，使用其协议信息
                        if (httpService != null &&
                            "https".equalsIgnoreCase(httpService.getProtocol())) {
                            isHttps = true;
                        }

                        String url = (isHttps ? "https://" : "http://") + host + path;
                        // 修复可能的双重协议前缀
                        while (url.startsWith("http://http://") || url.startsWith("https://https://") ||
                               url.startsWith("http://https://") || url.startsWith("https://http://")) {
                            url = url.replace("http://", "").replace("https://", "");
                            url = (isHttps ? "https://" : "http://") + url;
                        }
                        return url;
                    } else {
                        return path; // 如果找不到Host，至少显示路径
                    }
                }

                return "未知URL (从路径获取失败)";
            } catch (Exception ex) {
                BurpExtender.printError("[!] 提取URL失败: " + ex.getMessage());
                return "未知URL";
            }
        }
    }

    /**
     * 从请求数据中重建IHttpService
     * 解决从已保存请求重新发送时HTTPS协议丢失的问题
     *
     * @param requestId 请求ID
     * @param requestData 请求数据
     * @return 重建的IHttpService对象
     */
    public static IHttpService rebuildHttpService(int requestId, byte[] requestData) {
        try {
            String protocol = "http";
            String host = "";
            int port = 80;

            // 从请求数据中提取host和port
            IRequestInfo tempInfo = BurpExtender.helpers.analyzeRequest(requestData);
            List<String> headers = tempInfo.getHeaders();

            // 提取host
            for (String header : headers) {
                if (header.toLowerCase().startsWith("host:")) {
                    String hostValue = header.substring(5).trim();
                    String[] hostParts = hostValue.split(":");
                    host = hostParts[0];
                    if (hostParts.length > 1) {
                        try {
                            port = Integer.parseInt(hostParts[1]);
                        } catch (NumberFormatException e) {
                            // 忽略
                        }
                    }
                    break;
                }
            }

            // 从数据库中获取保存的协议信息（按ID单条查询，避免全表扫描）
            try {
                oxff.top.db.RequestDAO requestDAO = new oxff.top.db.RequestDAO();
                java.util.Map<String, Object> request = requestDAO.getRequest(requestId);
                if (request != null) {
                    protocol = (String) request.get("protocol");
                    String dbDomain = (String) request.get("domain");
                    if (dbDomain != null && !dbDomain.isEmpty()) {
                        host = dbDomain;
                    }
                }
            } catch (Exception e) {
                BurpExtender.printOutput("[*] 从数据库获取协议信息失败，使用请求数据推断: " + e.getMessage());
            }

            // 综合判断HTTPS：优先数据库协议，再结合请求头判断
            boolean isSecure = protocol.equalsIgnoreCase("https");

            // 额外检查请求头中的HTTPS指示
            if (!isSecure) {
                String firstLine = headers.get(0);
                if (firstLine.contains("https://")) {
                    isSecure = true;
                }
                for (String header : headers) {
                    if (header.toLowerCase().startsWith("host:") && header.contains(":443")) {
                        isSecure = true;
                        break;
                    }
                }
            }

            // 根据协议设置默认端口
            if (isSecure && port == 80) {
                port = 443;
            } else if (!isSecure && port == 443) {
                port = 80;
            }

            if (host.isEmpty()) {
                host = "unknown";
            }

            return BurpExtender.helpers.buildHttpService(host, port, isSecure);
        } catch (Exception e) {
            BurpExtender.printError("[!] 重建IHttpService失败: " + e.getMessage());
            // 返回一个默认的HTTP服务
            return BurpExtender.helpers.buildHttpService("unknown", 80, false);
        }
    }

    /**
     * 从请求数据中计算API值
     * 使用当前配置的提取规则，无规则时返回 path 作为默认值
     */
    public static String computeApiFromRequest(String path, String query, byte[] requestBytes) {
        try {
            IRequestInfo reqInfo = BurpExtender.helpers.analyzeRequest(requestBytes);
            List<String> headerList = new ArrayList<>(reqInfo.getHeaders());
            String contentType = null;
            for (String header : headerList) {
                if (header.toLowerCase().startsWith("content-type:")) {
                    contentType = header.substring("content-type:".length()).trim();
                    break;
                }
            }
            int bodyOffset = reqInfo.getBodyOffset();
            byte[] body = null;
            if (bodyOffset < requestBytes.length) {
                body = java.util.Arrays.copyOfRange(requestBytes, bodyOffset, requestBytes.length);
                if (body.length == 0) body = null;
            }
            List<ApiExtractionRule> activeRules = ApiRuleManager.getInstance().getActiveRules();
            return ApiExtractionEngine.extractApi(
                    path, (query == null || query.isEmpty()) ? null : query,
                    headerList, body, contentType, activeRules);
        } catch (Exception e) {
            BurpExtender.printOutput("[*] 计算API值失败，使用路径作为默认值: " + e.getMessage());
            return path != null ? path : "/";
        }
    }
}

package oxff.top.http;

import burp.BurpExtender;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import oxff.top.api.ApiExtractionEngine;
import oxff.top.api.ApiExtractionRule;
import oxff.top.api.ApiRuleManager;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * HTTP请求辅助工具类
 * 提供URL提取、HttpService重建、API值计算等静态方法
 */
public class HttpRequestHelper {

    /**
     * 从请求中安全地提取URL信息
     *
     * @param requestBytes 请求字节数组
     * @param httpRequest 已解析的HttpRequest对象
     * @param httpService 当前的HTTP服务信息（可为null）
     * @return 提取的URL，如果提取失败则返回简化URL或默认值
     */
    public static String extractUrlFromRequest(byte[] requestBytes, HttpRequest httpRequest, HttpService httpService) {
        try {
            // 尝试使用标准方式获取URL
            return httpRequest.url();
        } catch (Exception e) {
            // 如果标准方式失败，从请求头中提取
            try {
                List<String> headers = convertHeadersToStringList(httpRequest.headers());
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
                        if (httpService != null && httpService.secure()) {
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
     * 从请求数据中重建HttpService
     * 解决从已保存请求重新发送时HTTPS协议丢失的问题
     *
     * @param requestId 请求ID
     * @param requestData 请求数据
     * @return 重建的HttpService对象
     */
    public static HttpService rebuildHttpService(int requestId, byte[] requestData) {
        try {
            String protocol = "http";
            String host = "";
            int port = 80;

            // 从请求数据中提取host和port
            HttpRequest tempRequest = HttpRequest.httpRequest(ByteArray.byteArray(requestData));
            List<String> headers = convertHeadersToStringList(tempRequest.headers());

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
            // 端口优先级：Host头非标准端口 > 数据库domain端口 > 协议默认端口
            // Host头来自实际请求，最可靠；数据库domain可能过时
            boolean hasNonStandardPortFromHost = (port != 80 && port != 443);
            try {
                oxff.top.db.RequestDAO requestDAO = new oxff.top.db.RequestDAO();
                java.util.Map<String, Object> request = requestDAO.getRequest(requestId);
                if (request != null) {
                    String dbProtocol = (String) request.get("protocol");
                    if (dbProtocol != null && !dbProtocol.isEmpty()) {
                        protocol = dbProtocol;
                    }
                    String dbDomain = (String) request.get("domain");
                    if (dbDomain != null && !dbDomain.isEmpty()) {
                        host = dbDomain;
                        if (dbDomain.contains(":")) {
                            String[] domainParts = dbDomain.split(":");
                            host = domainParts[0];
                            // 仅当Host头未提取到非标准端口时，才使用数据库的端口
                            // 避免数据库中过时的端口覆盖Host头中的最新端口
                            if (!hasNonStandardPortFromHost) {
                                try {
                                    port = Integer.parseInt(domainParts[1]);
                                } catch (NumberFormatException e) {
                                    // 忽略，保持从Host头提取的端口
                                }
                            }
                        }
                        // 如果数据库domain不含端口，保持从Host头提取的端口不变
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

            // 根据协议设置默认端口（仅在未从Host头提取到非标准端口时才使用默认值）
            if (isSecure && port == 80) {
                port = 443;
            } else if (!isSecure && port == 443) {
                port = 80;
            }
            // 如果从Host头提取到了非标准端口（如9527），不要覆盖

            if (host.isEmpty()) {
                host = "unknown";
            }

            return HttpService.httpService(host, port, isSecure);
        } catch (Exception e) {
            BurpExtender.printError("[!] 重建HttpService失败: " + e.getMessage());
            // 返回一个默认的HTTP服务
            return HttpService.httpService("unknown", 80, false);
        }
    }

    /**
     * 从请求数据中计算API值
     * 使用当前配置的提取规则，无规则时返回 path 作为默认值
     */
    public static String computeApiFromRequest(String path, String query, byte[] requestBytes) {
        try {
            HttpRequest reqInfo = HttpRequest.httpRequest(ByteArray.byteArray(requestBytes));
            List<String> headerList = convertHeadersToStringList(reqInfo.headers());
            String contentType = null;
            for (String header : headerList) {
                if (header.toLowerCase().startsWith("content-type:")) {
                    contentType = header.substring("content-type:".length()).trim();
                    break;
                }
            }
            int bodyOffset = reqInfo.bodyOffset();
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

    /**
     * 将Montoya API的HttpHeader列表转换为字符串列表
     * 注意：Montoya SDK 的 headers() 返回的是纯 HTTP 头部，不包含请求行
     * 若需要请求行信息，应使用 method()、path()、httpVersion() 等方法单独获取
     */
    /**
     * 解析域名字符串（含非标准端口）
     * <p>
     * 优先从HttpService获取端口（httpRequest.url()可能不含显式端口，getPort()返回-1），
     * 否则用URL默认端口兜底。仅当端口为非标准端口时追加到域名。
     * <p>
     * 解决两个问题：
     * 1. java.net.URL.getPort() 在URL不含显式端口时返回-1，导致域名丢失端口信息
     * 2. 对IP地址，Montoya API的httpRequest.url()可能含显式端口，行为与域名场景不一致
     *
     * @param parsedUrl   已解析的URL对象
     * @param httpService HTTP服务信息，可为null
     * @return 域名字符串，非标准端口时包含端口号
     */
    public static String resolveDomainWithPort(URL parsedUrl, HttpService httpService) {
        String host = parsedUrl.getHost();
        int effectivePort;
        if (httpService != null) {
            effectivePort = httpService.port();
            // 防御性处理：某些HttpService的host()可能返回"host:port"格式（如IP地址场景）
            // 用parsedUrl.getHost()作为权威host来源，不依赖httpService.host()
        } else {
            effectivePort = parsedUrl.getPort();
            if (effectivePort == -1) {
                // URL不含显式端口时，根据协议推断默认端口
                effectivePort = parsedUrl.getDefaultPort();
            }
        }
        int defaultPort = parsedUrl.getDefaultPort();
        if (effectivePort != -1 && effectivePort != defaultPort) {
            host = host + ":" + effectivePort;
        }
        return host;
    }

    /**
     * 从HttpService解析域名字符串（含非标准端口）
     * 适用于没有URL对象、只有HttpService的场景（如AutoTestEngine）
     *
     * @param httpService HTTP服务信息，可为null
     * @return 域名字符串，非标准端口时包含端口号；httpService为null时返回"unknown"
     */
    public static String resolveDomainFromService(HttpService httpService) {
        if (httpService == null) return "unknown";
        String host = stripPortFromHost(httpService.host());
        int port = httpService.port();
        int defaultPort = httpService.secure() ? 443 : 80;
        if (port != -1 && port != defaultPort) {
            host = host + ":" + port;
        }
        return host;
    }

    /**
     * 从可能包含端口的host字符串中提取纯主机名
     * 防御性处理：某些场景下httpService.host()可能返回"host:port"格式
     *
     * @param host 可能包含端口的主机名字符串
     * @return 不含端口的主机名
     */
    public static String stripPortFromHost(String host) {
        if (host == null || host.isEmpty()) return host;
        // IPv6地址格式: [::1] 或 [::1]:port
        if (host.startsWith("[")) {
            int bracketEnd = host.indexOf(']');
            if (bracketEnd > 0) {
                return host.substring(1, bracketEnd);
            }
            return host;
        }
        // IPv4或域名: host 或 host:port
        int lastColon = host.lastIndexOf(":");
        if (lastColon > 0) {
            String afterColon = host.substring(lastColon + 1);
            try {
                Integer.parseInt(afterColon);
                return host.substring(0, lastColon);
            } catch (NumberFormatException e) {
                // 冒号后不是数字，不是端口格式，保持原样
            }
        }
        return host;
    }

    private static List<String> convertHeadersToStringList(List<burp.api.montoya.http.message.HttpHeader> rawHeaders) {
        List<String> result = new ArrayList<>();
        for (burp.api.montoya.http.message.HttpHeader header : rawHeaders) {
            String name = header.name();
            String value = header.value();
            if (name != null && value != null) {
                result.add(name + ": " + value);
            } else if (name != null) {
                result.add(name);
            }
        }
        return result;
    }
}

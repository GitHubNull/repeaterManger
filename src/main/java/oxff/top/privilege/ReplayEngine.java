package oxff.top.privilege;

import burp.BurpExtender;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import oxff.top.http.HttpRequestHelper;
import oxff.top.http.RequestManager;
import oxff.top.http.RequestResponseRecord;
import oxff.top.privilege.model.JudgmentResult;
import oxff.top.privilege.model.TokenLocation;
import oxff.top.privilege.model.UserSession;

import javax.swing.SwingUtilities;
import java.awt.Color;
import java.net.URL;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 重放引擎（单例）
 * 核心职责：接收原始请求，遍历已启用的用户会话，替换令牌后发送，收集结果
 *
 * 结果通过回调通知UI，在请求管理Tab的HistoryPanel中展示
 */
public class ReplayEngine {

    private static ReplayEngine instance;

    private final ExecutorService executor;

    /** 当前批次已处理的API集合（用于去重，线程安全） */
    private final Set<String> processedApis = ConcurrentHashMap.newKeySet();

    private ReplayEngine() {
        this.executor = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "PrivilegeTest-Replay");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * 获取单例实例
     */
    public static synchronized ReplayEngine getInstance() {
        if (instance == null) {
            instance = new ReplayEngine();
        }
        return instance;
    }

    /**
     * 重放回调接口
     */
    public interface ReplayCallback {
        /**
         * 某个用户会话的重放完成
         *
         * @param record  历史记录（含用户会话信息和判决结果）
         * @param isFirst 是否为第一个用户（基准用户）
         */
        void onReplayComplete(RequestResponseRecord record, boolean isFirst);

        /**
         * 所有用户会话重放完成
         */
        void onAllComplete();
    }

    /**
     * 对原始请求执行权限测试重放
     *
     * @param originalRequest 原始请求字节数组
     * @param httpService     HTTP服务信息
     * @param requestId       请求ID
     * @param requestManager  请求管理器
     * @param callback        回调
     * @return true 如果请求因去重被跳过（未执行重放），false 如果正常执行了重放
     */
    public boolean replay(byte[] originalRequest, HttpService httpService, int requestId,
                       RequestManager requestManager, ReplayCallback callback) {
        SessionManager sessionManager = SessionManager.getInstance();
        List<UserSession> enabledSessions = sessionManager.getEnabledSessions();

        if (enabledSessions.isEmpty()) {
            BurpExtender.printOutput("[*] 无已启用的用户会话，跳过权限测试重放");
            return false;
        }

        // API去重检查：从请求字节数组中解析path和query，确保API键有意义
        String api;
        try {
            HttpRequest reqInfo;
            if (httpService != null) {
                reqInfo = HttpRequest.httpRequest(httpService, ByteArray.byteArray(originalRequest));
            } else {
                reqInfo = HttpRequest.httpRequest(ByteArray.byteArray(originalRequest));
            }
            java.net.URL parsedUrl = new java.net.URL(reqInfo.url());
            String reqPath = parsedUrl.getPath() != null ? parsedUrl.getPath() : "/";
            String reqQuery = parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "";
            api = HttpRequestHelper.computeApiFromRequest(reqPath, reqQuery, originalRequest);
        } catch (Exception e) {
            // 解析失败时使用整个请求URL作为fallback
            BurpExtender.printOutput("[*] ReplayEngine: 解析请求URL失败，使用fallback计算API键: " + e.getMessage());
            api = HttpRequestHelper.computeApiFromRequest("/", "", originalRequest);
        }
        if (sessionManager.isDedupEnabled() && isApiProcessed(api)) {
            BurpExtender.printOutput("[*] 权限测试重放：API已处理过，跳过去重: " + api);
            return true; // 返回true表示被去重跳过，调用方需据此跳过CountDownLatch等待
        }
        if (sessionManager.isDedupEnabled()) {
            addProcessedApi(api);
        }

        List<TokenLocation> locations = sessionManager.getTokenLocations();

        executor.submit(() -> {
            BurpExtender.printOutput("[*] 开始权限测试重放: " + enabledSessions.size() + "个用户会话");

            // 存储基准用户的响应，用于后续比较
            byte[] baselineResponse = null;
            int baselineStatusCode = -1;

            for (int i = 0; i < enabledSessions.size(); i++) {
                UserSession session = enabledSessions.get(i);
                boolean isFirst = (i == 0);

                try {
                    // 替换令牌
                    byte[] modifiedRequest = TokenReplacementEngine.replaceTokens(
                            originalRequest, locations, session);

                    // 同步发送请求（在后台线程中）
                    ReplayResultHolder holder = sendSync(modifiedRequest, httpService, requestManager);

                    // 判断判决结果
                    String judgment = JudgmentResult.PENDING.name();
                    double similarity = -1;
                    Color judgmentColor = null;
                    String judgmentNote = "";

                    if (holder.response != null && holder.response.length > 0) {
                        if (isFirst) {
                            // 基准用户：保存纯响应体作为比较基准（仅响应体，不含响应头）
                            baselineResponse = extractResponseBody(holder.response);
                            baselineStatusCode = holder.statusCode;
                            judgment = JudgmentResult.NOT_ESCALATED.name(); // 基准用户默认标记为安全
                            judgmentColor = null; // 基准用户不特殊着色
                        } else {
                            // 非基准用户：使用 JudgmentEngine 判决
                            String responseHeaders = extractResponseHeaders(holder.response);
                            byte[] responseBodyOnly = extractResponseBody(holder.response);
                            double threshold = sessionManager.getSimilarityThreshold();

                            JudgmentEngine.JudgmentOutcome outcome = JudgmentEngine.judge(
                                    holder.statusCode, responseHeaders, responseBodyOnly,
                                    baselineResponse, baselineStatusCode, threshold, holder.durationMs);

                            judgment = outcome.result.name();
                            similarity = outcome.similarity;
                            judgmentColor = outcome.color;
                            judgmentNote = outcome.note;
                        }
                    } else {
                        judgment = JudgmentResult.ERROR.name();
                    }

                    // 创建历史记录
                    RequestResponseRecord record = new RequestResponseRecord();
                    record.setRequestId(requestId);
                    // 解析HTTP元数据（方法、协议、域名、路径、查询参数）
                    populateRecordFromRequest(record, modifiedRequest, httpService);
                    record.setStatusCode(holder.statusCode);
                    record.setResponseLength(holder.response != null ? holder.response.length : 0);
                    record.setResponseTime((int) holder.durationMs);
                    record.setRequestData(modifiedRequest);
                    record.setResponseData(holder.response != null ? holder.response : new byte[0]);
                    record.setTimestamp(new java.util.Date());
                    record.setUserSessionName(session.getName());
                    record.setJudgment(judgment);
                    record.setSimilarity(similarity);
                    record.setColor(judgmentColor);

                    if (holder.errorMessage != null) {
                        record.setComment("请求失败: " + holder.errorMessage);
                    } else if (judgmentNote != null && !judgmentNote.isEmpty()) {
                        record.setComment(judgmentNote);
                    }

                    // 通知UI（在EDT上）
                    final RequestResponseRecord finalRecord = record;
                    final boolean finalIsFirst = isFirst;
                    SwingUtilities.invokeLater(() -> {
                        if (callback != null) {
                            callback.onReplayComplete(finalRecord, finalIsFirst);
                        }
                    });

                } catch (Exception e) {
                    BurpExtender.printError("[!] 权限测试重放异常 (user=" + session.getName() + "): " + e.getMessage());

                    // 创建错误记录
                    RequestResponseRecord errorRecord = new RequestResponseRecord();
                    errorRecord.setRequestId(requestId);
                    // 解析HTTP元数据（方法、协议、域名、路径、查询参数）
                    populateRecordFromRequest(errorRecord, originalRequest, httpService);
                    errorRecord.setStatusCode(0);
                    errorRecord.setResponseTime(0);
                    errorRecord.setRequestData(originalRequest);
                    errorRecord.setResponseData(new byte[0]);
                    errorRecord.setTimestamp(new java.util.Date());
                    errorRecord.setUserSessionName(session.getName());
                    errorRecord.setJudgment(JudgmentResult.ERROR.name());
                    errorRecord.setSimilarity(-1);
                    errorRecord.setComment("重放异常: " + e.getMessage());

                    SwingUtilities.invokeLater(() -> {
                        if (callback != null) {
                            callback.onReplayComplete(errorRecord, isFirst);
                        }
                    });
                }
            }

            // 全部完成
            SwingUtilities.invokeLater(() -> {
                if (callback != null) {
                    callback.onAllComplete();
                }
            });

            BurpExtender.printOutput("[+] 权限测试重放完成: " + enabledSessions.size() + "个用户会话");
        });

        return false; // 正常执行了重放（异步），未被去重跳过
    }

    /**
     * 同步发送HTTP请求（在后台线程中调用）
     */
    private ReplayResultHolder sendSync(byte[] requestBytes, HttpService httpService,
                                         RequestManager requestManager) {
        ReplayResultHolder holder = new ReplayResultHolder();
        Object lock = new Object();
        boolean[] done = {false};

        requestManager.makeHttpRequestAsync(requestBytes, 30, -1, httpService,
                new RequestManager.RequestCallback() {
                    @Override
                    public void onSuccess(byte[] response, long requestTimeMs, long responseTimeMs, long durationMs) {
                        holder.response = response;
                        holder.durationMs = durationMs;
                        if (response != null && response.length > 0) {
                            try {
                                burp.api.montoya.http.message.responses.HttpResponse resp =
                                        burp.api.montoya.http.message.responses.HttpResponse.httpResponse(
                                                burp.api.montoya.core.ByteArray.byteArray(response));
                                holder.statusCode = resp.statusCode();
                            } catch (Exception e) {
                                holder.statusCode = -1;
                            }
                        }
                        synchronized (lock) {
                            done[0] = true;
                            lock.notifyAll();
                        }
                    }

                    @Override
                    public void onFailure(String errorMessage, long requestTimeMs, long responseTimeMs, long durationMs) {
                        holder.errorMessage = errorMessage;
                        holder.durationMs = durationMs;
                        synchronized (lock) {
                            done[0] = true;
                            lock.notifyAll();
                        }
                    }
                });

        // 等待响应（最多60秒）
        synchronized (lock) {
            long startTime = System.currentTimeMillis();
            while (!done[0] && (System.currentTimeMillis() - startTime) < 60000) {
                try {
                    lock.wait(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }

        return holder;
    }

    /**
     * 清除去重记录（新批次开始时调用）
     */
    public void clearProcessedApis() {
        processedApis.clear();
    }

    /**
     * 添加已处理的API（用于去重）
     */
    public void addProcessedApi(String api) {
        processedApis.add(api);
    }

    /**
     * 检查API是否已处理
     */
    public boolean isApiProcessed(String api) {
        return processedApis.contains(api);
    }

    /**
     * 从请求字节和HttpService中提取HTTP元数据，填充到记录中
     */
    private void populateRecordFromRequest(RequestResponseRecord record, byte[] requestBytes, HttpService httpService) {
        try {
            HttpRequest requestInfo = HttpRequest.httpRequest(httpService, ByteArray.byteArray(requestBytes));
            String method = requestInfo.method();
            URL parsedUrl = new URL(requestInfo.url());

            String protocol = parsedUrl.getProtocol();
            String domain = parsedUrl.getHost();
            int port = parsedUrl.getPort();
            if (port != -1 && port != parsedUrl.getDefaultPort()) {
                domain = domain + ":" + port;
            }
            String path = parsedUrl.getPath();
            String query = parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "";

            record.setMethod(method);
            record.setProtocol(protocol);
            record.setDomain(domain);
            record.setPath(path);
            record.setQueryParameters(query);
        } catch (Exception e) {
            BurpExtender.printOutput("[*] ReplayEngine: 解析请求URL失败，使用fallback: " + e.getMessage());
            record.setMethod("UNKNOWN");
            record.setProtocol(httpService.secure() ? "https" : "http");
            record.setDomain(httpService.host());
            record.setPath("/");
            record.setQueryParameters("");
        }
    }

    /**
     * 从响应字节数组中提取响应头字符串
     */
    private String extractResponseHeaders(byte[] responseBytes) {
        if (responseBytes == null || responseBytes.length == 0) return "";
        try {
            String responseStr = new String(responseBytes, java.nio.charset.StandardCharsets.UTF_8);
            int bodySeparator = responseStr.indexOf("\r\n\r\n");
            if (bodySeparator > 0) {
                return responseStr.substring(0, bodySeparator);
            }
            bodySeparator = responseStr.indexOf("\n\n");
            if (bodySeparator > 0) {
                return responseStr.substring(0, bodySeparator);
            }
            return responseStr;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 从响应字节数组中提取纯响应体（不含响应头）
     * 相似度计算应仅基于响应体内容，排除响应头的影响
     */
    private byte[] extractResponseBody(byte[] responseBytes) {
        if (responseBytes == null || responseBytes.length == 0) return new byte[0];
        try {
            String responseStr = new String(responseBytes, java.nio.charset.StandardCharsets.UTF_8);
            int bodySeparator = responseStr.indexOf("\r\n\r\n");
            if (bodySeparator > 0) {
                int bodyStart = bodySeparator + 4;
                if (bodyStart < responseBytes.length) {
                    return java.util.Arrays.copyOfRange(responseBytes, bodyStart, responseBytes.length);
                }
                return new byte[0];
            }
            bodySeparator = responseStr.indexOf("\n\n");
            if (bodySeparator > 0) {
                int bodyStart = bodySeparator + 2;
                if (bodyStart < responseBytes.length) {
                    return java.util.Arrays.copyOfRange(responseBytes, bodyStart, responseBytes.length);
                }
                return new byte[0];
            }
            // 无法分离头和体时，返回完整内容作为fallback
            return responseBytes;
        } catch (Exception e) {
            return responseBytes;
        }
    }

    /**
     * 重放结果持有者
     */
    private static class ReplayResultHolder {
        byte[] response;
        int statusCode = -1;
        long durationMs;
        String errorMessage;
    }
}

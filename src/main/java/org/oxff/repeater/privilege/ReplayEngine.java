package org.oxff.repeater.privilege;

import org.oxff.repeater.logging.LogManager;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.oxff.repeater.http.HttpRequestHelper;
import org.oxff.repeater.http.RequestManager;
import org.oxff.repeater.http.RequestResponseRecord;
import org.oxff.repeater.privilege.model.JudgmentResult;
import org.oxff.repeater.privilege.model.TokenLocation;
import org.oxff.repeater.privilege.model.UserSession;

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

    // useHttp2 已改为方法参数传递，避免单例实例字段在并发 replay() 调用时被覆盖

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
                       RequestManager requestManager, boolean useHttp2, ReplayCallback callback) {
        SessionManager sessionManager = SessionManager.getInstance();
        List<UserSession> enabledSessions = sessionManager.getEnabledSessions();

        if (enabledSessions.isEmpty()) {
            LogManager.getInstance().printOutput("[*] 无已启用的用户会话，跳过权限测试重放");
            return false;
        }

        // API去重检查：使用 DedupConfigManager 按优先级链式计算去重键，失败时自动回退PATH
        DedupConfigManager dedupConfigManager = DedupConfigManager.getInstance();
        String api = dedupConfigManager.computeDedupKey(originalRequest, httpService);
        if (ApiDedupEngine.checkAndAddKey(processedApis, api)) {
            LogManager.getInstance().printOutput("[*] 权限测试重放：API已处理过，跳过去重: " + api);
            return true; // 返回true表示被去重跳过，调用方需据此跳过CountDownLatch等待
        }

        final boolean finalUseHttp2 = useHttp2;
        executor.submit(() -> {
            LogManager.getInstance().printOutput("[*] 开始权限测试重放: " + enabledSessions.size() + "个用户会话");

            // 存储基准用户的响应，用于后续比较
            byte[] baselineResponse = null;
            int baselineStatusCode = -1;
            boolean baselineValid = false;

            for (int i = 0; i < enabledSessions.size(); i++) {
                UserSession session = enabledSessions.get(i);
                boolean isFirst = (i == 0);

                // 根据会话关联的方案过滤令牌位置
                List<TokenLocation> locations = sessionManager.getTokenLocationsByScheme(session.getSchemeId());

                // 重放延迟：使用全局配置
                int replayDelay = sessionManager.getReplayDelay();
                if (replayDelay > 0 && i > 0) {
                    try {
                        Thread.sleep(replayDelay);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }

                // 请求超时：使用全局配置
                int timeoutSeconds = sessionManager.getRequestTimeout();

                // 重试参数：使用全局配置
                int retryCount = sessionManager.getRetryCount();
                int retryDelay = sessionManager.getRetryDelay();

                // 非基准用户：如果基准请求失败，跳过比对判决，标记为ERROR
                if (!isFirst && !baselineValid) {
                    RequestResponseRecord skipRecord = new RequestResponseRecord();
                    skipRecord.setRequestId(requestId);
                    populateRecordFromRequest(skipRecord, originalRequest, httpService);
                    skipRecord.setStatusCode(0);
                    skipRecord.setResponseTime(0);
                    skipRecord.setRequestData(originalRequest);
                    skipRecord.setResponseData(new byte[0]);
                    skipRecord.setTimestamp(new java.util.Date());
                    skipRecord.setUserSessionName(session.getName());
                    skipRecord.setJudgment(JudgmentResult.ERROR.name());
                    skipRecord.setSimilarity(-1);
                    skipRecord.setComment("基准请求失败，无法进行对比判决");

                    SwingUtilities.invokeLater(() -> {
                        if (callback != null) {
                            callback.onReplayComplete(skipRecord, false);
                        }
                    });
                    continue;
                }

                try {
                    // 替换令牌（使用方案过滤后的令牌位置）
                    byte[] modifiedRequest = TokenReplacementEngine.replaceTokens(
                            originalRequest, locations, session);

                    // 带重试的同步发送请求（在后台线程中）
                    // finalUseHttp2 通过参数传递，避免单例实例字段在并发 replay() 调用时被覆盖
                    ReplayResultHolder holder = sendSyncWithRetry(
                            modifiedRequest, httpService, requestManager, finalUseHttp2,
                            timeoutSeconds, retryCount, retryDelay);

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
                            baselineValid = true;
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
                        if (isFirst) {
                            LogManager.getInstance().printError("[!] 基准用户请求失败，后续会话将跳过判决");
                        }
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
                    LogManager.getInstance().printError("[!] 权限测试重放异常 (user=" + session.getName() + "): " + e.getMessage());

                    // 基准用户异常时标记baselineValid为false
                    if (isFirst) {
                        LogManager.getInstance().printError("[!] 基准用户请求异常，后续会话将跳过判决");
                    }

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

            LogManager.getInstance().printOutput("[+] 权限测试重放完成: " + enabledSessions.size() + "个用户会话");
        });

        return false; // 正常执行了重放（异步），未被去重跳过
    }

    /**
     * 带重试的同步发送HTTP请求（在后台线程中调用）
     *
     * @param requestBytes   请求字节数组
     * @param httpService    HTTP服务信息
     * @param requestManager 请求管理器
     * @param useHttp2       是否使用HTTP/2协议（参数传递，避免实例字段竞态）
     * @param timeoutSeconds 请求超时时间（秒）
     * @param retryCount     失败重试次数
     * @param retryDelayMs   重试间隔（毫秒）
     */
    private ReplayResultHolder sendSyncWithRetry(byte[] requestBytes, HttpService httpService,
                                                  RequestManager requestManager, boolean useHttp2,
                                                  int timeoutSeconds, int retryCount, int retryDelayMs) {
        ReplayResultHolder holder = sendSyncOnce(requestBytes, httpService, requestManager, useHttp2, timeoutSeconds);

        // 重试逻辑：仅在请求失败且有重试次数时执行
        int attempts = 0;
        while (holder.errorMessage != null && attempts < retryCount) {
            attempts++;
            LogManager.getInstance().printOutput(String.format("[*] 重放重试 (%d/%d), 等待 %dms...",
                    attempts, retryCount, retryDelayMs));
            try {
                Thread.sleep(retryDelayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            holder = sendSyncOnce(requestBytes, httpService, requestManager, useHttp2, timeoutSeconds);
        }

        return holder;
    }

    /**
     * 单次同步发送HTTP请求（在后台线程中调用）
     *
     * @param requestBytes   请求字节数组
     * @param httpService    HTTP服务信息
     * @param requestManager 请求管理器
     * @param useHttp2       是否使用HTTP/2协议
     * @param timeoutSeconds 请求超时时间（秒）
     */
    private ReplayResultHolder sendSyncOnce(byte[] requestBytes, HttpService httpService,
                                             RequestManager requestManager, boolean useHttp2,
                                             int timeoutSeconds) {
        ReplayResultHolder holder = new ReplayResultHolder();
        Object lock = new Object();
        boolean[] done = {false};

        requestManager.makeHttpRequestAsync(requestBytes, timeoutSeconds, -1, httpService, useHttp2,
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

        // 等待响应（超时时间基于请求超时的2倍，最少60秒）
        long waitTimeoutMs = Math.max(60000, timeoutSeconds * 2000L);
        synchronized (lock) {
            long startTime = System.currentTimeMillis();
            while (!done[0] && (System.currentTimeMillis() - startTime) < waitTimeoutMs) {
                try {
                    lock.wait(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            // BUG修复：超时后设置 errorMessage，使 sendSyncWithRetry 的重试逻辑能被触发
            // 原代码超时后 holder.errorMessage 为 null，导致重试条件 holder.errorMessage != null 永远为 false
            if (!done[0] && holder.errorMessage == null) {
                holder.errorMessage = String.format("请求超时（等待 %dms 未收到响应）", waitTimeoutMs);
                holder.durationMs = waitTimeoutMs;
                LogManager.getInstance().printError(String.format("[!] 重放请求超时：等待 %dms 未收到响应", waitTimeoutMs));
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
     * 从请求字节和HttpService中提取HTTP元数据，填充到记录中
     */
    private void populateRecordFromRequest(RequestResponseRecord record, byte[] requestBytes, HttpService httpService) {
        try {
            HttpRequest requestInfo = HttpRequest.httpRequest(httpService, ByteArray.byteArray(requestBytes));
            String method = requestInfo.method();
            URL parsedUrl = new URL(requestInfo.url());

            String protocol = parsedUrl.getProtocol();
            String domain = HttpRequestHelper.resolveDomainWithPort(parsedUrl, httpService);
            String path = parsedUrl.getPath();
            String query = parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "";

            record.setMethod(method);
            record.setProtocol(protocol);
            record.setDomain(domain);
            record.setPath(path);
            record.setQueryParameters(query);
        } catch (Exception e) {
            LogManager.getInstance().printOutput("[*] ReplayEngine: 解析请求URL失败，使用fallback: " + e.getMessage());
            record.setMethod("UNKNOWN");
            record.setProtocol(httpService.secure() ? "https" : "http");
            record.setDomain(HttpRequestHelper.resolveDomainFromService(httpService));
            record.setPath("/");
            record.setQueryParameters("");
        }
    }

    /**
     * 从响应字节数组中提取响应头字符串
     * 使用字节级查找分隔符，避免 UTF-8 多字节字符导致字符索引与字节偏移错位（BUG-007）
     */
    private String extractResponseHeaders(byte[] responseBytes) {
        if (responseBytes == null || responseBytes.length == 0) return "";
        try {
            int separatorPos = findHeaderBodySeparator(responseBytes);
            if (separatorPos < 0) {
                // 未找到分隔符，返回全部内容
                return new String(responseBytes, java.nio.charset.StandardCharsets.UTF_8);
            }
            return new String(responseBytes, 0, separatorPos, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 字节级查找 header/body 分隔符
     * @return 分隔符起始位置的字节偏移，未找到返回 -1
     */
    private static int findHeaderBodySeparator(byte[] data) {
        // 优先查找 \r\n\r\n
        for (int i = 0; i < data.length - 3; i++) {
            if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n') {
                return i;
            }
        }
        // 回退查找 \n\n
        for (int i = 0; i < data.length - 1; i++) {
            if (data[i] == '\n' && data[i + 1] == '\n') {
                return i;
            }
        }
        return -1;
    }

    /**
     * 从响应字节数组中提取纯响应体（不含响应头）
     * 相似度计算应仅基于响应体内容，排除响应头的影响
     * 使用字节级查找分隔符，避免 UTF-8 多字节字符导致字符索引与字节偏移错位（BUG-007）
     */
    private byte[] extractResponseBody(byte[] responseBytes) {
        if (responseBytes == null || responseBytes.length == 0) return new byte[0];
        try {
            int separatorPos = findHeaderBodySeparator(responseBytes);
            if (separatorPos < 0) {
                // 无法分离头和体时，返回完整内容作为fallback
                return responseBytes;
            }
            // 计算分隔符长度（\r\n\r\n=4 或 \n\n=2）
            int separatorLen = (responseBytes[separatorPos] == '\r') ? 4 : 2;
            int bodyStart = separatorPos + separatorLen;
            if (bodyStart < responseBytes.length) {
                return java.util.Arrays.copyOfRange(responseBytes, bodyStart, responseBytes.length);
            }
            return new byte[0];
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

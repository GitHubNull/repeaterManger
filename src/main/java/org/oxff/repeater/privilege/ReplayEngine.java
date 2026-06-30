package org.oxff.repeater.privilege;

import org.oxff.repeater.logging.LogManager;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.oxff.repeater.http.HttpMessageParser;
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
                    SyncHttpSender.Result holder = sendSyncWithRetry(
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
                            baselineResponse = HttpMessageParser.extractResponseBody(holder.response);
                            baselineStatusCode = holder.statusCode;
                            baselineValid = true;
                            judgment = JudgmentResult.NOT_ESCALATED.name(); // 基准用户默认标记为安全
                            judgmentColor = null; // 基准用户不特殊着色
                        } else {
                            // 非基准用户：使用 JudgmentEngine 判决
                            String responseHeaders = HttpMessageParser.extractResponseHeaders(holder.response);
                            byte[] responseBodyOnly = HttpMessageParser.extractResponseBody(holder.response);
                            double threshold = sessionManager.getSimilarityThreshold();

                            // === 判决前诊断日志 ===
                            // 空 body WARNING — 始终输出(不受调试开关影响)
                            if (baselineResponse == null || baselineResponse.length == 0) {
                                LogManager.getInstance().printError(String.format(
                                        "[!] 基准响应体为空(requestId未知,用户=%s),相似度计算不可靠", session.getName()));
                            }
                            if (responseBodyOnly == null || responseBodyOnly.length == 0) {
                                LogManager.getInstance().printError(String.format(
                                        "[!] 当前响应体为空(用户=%s),相似度计算不可靠", session.getName()));
                            }
                            // 调试日志
                            LogManager.getInstance().judgmentDebug(String.format(
                                    "[判决] 判决前数据: baselineBodyLen=%d, currentBodyLen=%d, baselineStatusCode=%d, currentStatusCode=%d, threshold=%.2f",
                                    baselineResponse != null ? baselineResponse.length : -1,
                                    responseBodyOnly != null ? responseBodyOnly.length : -1,
                                    baselineStatusCode, holder.statusCode, threshold));
                            LogManager.getInstance().judgmentDebug(String.format(
                                    "[判决] 基准响应体前200字: %s",
                                    truncateForLog(baselineResponse, 200)));
                            LogManager.getInstance().judgmentDebug(String.format(
                                    "[判决] 当前响应体前200字: %s",
                                    truncateForLog(responseBodyOnly, 200)));

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

                    // 基准用户：保存纯响应体到独立字段，用于报告生成时的数据分离
                    if (isFirst) {
                        record.setBaselineResponseData(baselineResponse);
                    }

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
     * 带重试的同步发送HTTP请求（委托给 SyncHttpSender）
     */
    private SyncHttpSender.Result sendSyncWithRetry(byte[] requestBytes, HttpService httpService,
                                                  RequestManager requestManager, boolean useHttp2,
                                                  int timeoutSeconds, int retryCount, int retryDelayMs) {
        return SyncHttpSender.sendWithRetry(requestBytes, httpService, requestManager,
                useHttp2, timeoutSeconds, retryCount, retryDelayMs, "重放");
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
     * 截断字节数组为字符串用于日志（UTF-8解码，截断到 maxLen 字符）
     */
    private static String truncateForLog(byte[] data, int maxLen) {
        if (data == null || data.length == 0) return "(空)";
        try {
            String s = new String(data, java.nio.charset.StandardCharsets.UTF_8);
            return s.length() > maxLen ? s.substring(0, maxLen) + "...(截断)" : s;
        } catch (Exception e) {
            return "(解码失败)";
        }
    }
}

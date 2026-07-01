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
import org.oxff.repeater.privilege.model.FieldDefinition;
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
 * 核心职责：接收原始请求，遍历已启用的用户会话，替换字段后发送，收集结果
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
        executor.submit(() -> executeSessionReplay(
                enabledSessions, sessionManager, originalRequest, httpService,
                requestId, finalUseHttp2, requestManager, callback));

        return false; // 正常执行了重放（异步），未被去重跳过
    }

    /**
     * 执行会话重放的核心逻辑（在后台线程中运行）。
     * <p>
     * 对每个已启用的用户会话：加载存储基线、替换认证字段、发送请求、
     * 与基线比对判决、创建历史记录并通知UI。
     *
     * @param enabledSessions 已启用的用户会话列表
     * @param sessionManager  会话管理器
     * @param originalRequest 原始请求字节数组
     * @param httpService     HTTP服务信息
     * @param requestId       请求ID
     * @param useHttp2        是否使用HTTP/2
     * @param requestManager  请求管理器
     * @param callback        重放完成回调
     */
    private void executeSessionReplay(List<UserSession> enabledSessions, SessionManager sessionManager,
                                       byte[] originalRequest, HttpService httpService, int requestId,
                                       boolean useHttp2, RequestManager requestManager, ReplayCallback callback) {
        LogManager.getInstance().printOutput("[*] 开始权限测试重放: " + enabledSessions.size() + "个用户会话");

        // ===== 加载存储的基线响应（来自 benchmark 报文表 requests 表）=====
        byte[] baselineResponse = null;
        int baselineStatusCode = -1;
        boolean baselineValid = false;
        String baselineContentType = null;
        boolean hasStoredBaseline = false;

        try {
            org.oxff.repeater.db.RequestDAO requestDAO = new org.oxff.repeater.db.RequestDAO();
            byte[] storedBaseline = requestDAO.getOriginalResponseData(requestId);
            if (storedBaseline != null && storedBaseline.length > 0) {
                byte[] storedBody = HttpMessageParser.extractResponseBody(storedBaseline);
                int storedStatus = requestDAO.getOriginalResponseStatusCode(requestId);
                if (storedBody != null && storedBody.length > 0 && storedStatus > 0) {
                    baselineResponse = storedBody;
                    baselineStatusCode = storedStatus;
                    String storedHeaders = HttpMessageParser.extractResponseHeaders(storedBaseline);
                    baselineContentType = JudgmentEngine.extractContentType(storedHeaders);
                    baselineValid = true;
                    hasStoredBaseline = true;
                    LogManager.getInstance().printOutput(String.format(
                            "[*] 使用存储基线响应: requestId=%d, status=%d, bodyLen=%d",
                            requestId, baselineStatusCode, baselineResponse.length));
                }
            }
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] 加载存储基线响应失败: " + e.getMessage());
        }

        if (!hasStoredBaseline) {
            LogManager.getInstance().printOutput(
                    "[*] 无存储基线响应，回退兼容模式：首个已启用会话响应作为基准");
        }

        for (int i = 0; i < enabledSessions.size(); i++) {
            UserSession session = enabledSessions.get(i);
            boolean isFirst = (i == 0);
            boolean useAsBaselineFallback = (!hasStoredBaseline && isFirst);

            // 诊断并记录会话字段配置状态
            List<FieldDefinition> locations = sessionManager.getFieldDefinitionsByScheme(session.getSchemeId());
            logSessionFieldDiagnostics(session, locations);

            // 重放延迟
            int replayDelay = sessionManager.getReplayDelay();
            if (replayDelay > 0 && i > 0) {
                try {
                    Thread.sleep(replayDelay);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }

            int timeoutSeconds = sessionManager.getRequestTimeout();
            int retryCount = sessionManager.getRetryCount();
            int retryDelay = sessionManager.getRetryDelay();

            // 基线不可用时跳过对比判决
            if (!useAsBaselineFallback && !baselineValid) {
                RequestResponseRecord skipRecord = createSkipRecord(
                        originalRequest, httpService, requestId, session, "基准请求失败，无法进行对比判决");
                SwingUtilities.invokeLater(() -> {
                    if (callback != null) {
                        callback.onReplayComplete(skipRecord, false);
                    }
                });
                continue;
            }

            try {
                byte[] modifiedRequest = FieldReplacementEngine.replaceFields(
                        originalRequest, locations, session);

                SyncHttpSender.Result holder = sendSyncWithRetry(
                        modifiedRequest, httpService, requestManager, useHttp2,
                        timeoutSeconds, retryCount, retryDelay);

                // 判决结果（由辅助方法计算）
                ReplayJudgment judgment = evaluateJudgment(
                        holder, useAsBaselineFallback, baselineResponse, baselineStatusCode,
                        baselineContentType, baselineValid, session, requestId);

                // 更新基线（兼容模式首个会话）
                if (useAsBaselineFallback && judgment.baselineUpdated) {
                    baselineResponse = judgment.newBaselineResponse;
                    baselineStatusCode = judgment.newBaselineStatusCode;
                    baselineContentType = judgment.newBaselineContentType;
                    baselineValid = true;
                }

                // 创建历史记录
                RequestResponseRecord record = new RequestResponseRecord();
                record.setRequestId(requestId);
                populateRecordFromRequest(record, modifiedRequest, httpService);
                record.setStatusCode(holder.statusCode);
                record.setResponseLength(holder.response != null ? holder.response.length : 0);
                record.setResponseTime((int) holder.durationMs);
                record.setRequestData(modifiedRequest);
                record.setResponseData(holder.response != null ? holder.response : new byte[0]);
                record.setTimestamp(new java.util.Date());
                record.setUserSessionName(session.getName());
                record.setJudgment(judgment.result);
                record.setSimilarity(judgment.similarity);
                record.setColor(judgment.color);

                if (isFirst) {
                    byte[] respData = (baselineResponse != null && baselineResponse.length > 0)
                                      ? baselineResponse : null;
                    record.setBaselineResponseData(respData);
                }

                if (holder.errorMessage != null) {
                    record.setComment("请求失败: " + holder.errorMessage);
                } else if (judgment.note != null && !judgment.note.isEmpty()) {
                    record.setComment(judgment.note);
                }

                final RequestResponseRecord finalRecord = record;
                final boolean finalIsFirst = hasStoredBaseline ? false : isFirst;
                SwingUtilities.invokeLater(() -> {
                    if (callback != null) {
                        callback.onReplayComplete(finalRecord, finalIsFirst);
                    }
                });

            } catch (Exception e) {
                LogManager.getInstance().printError(
                        "[!] 权限测试重放异常 (user=" + session.getName() + "): " + e.getMessage());

                if (useAsBaselineFallback) {
                    LogManager.getInstance().printError("[!] 兼容模式：基线用户请求异常，后续会话将跳过判决");
                }

                RequestResponseRecord errorRecord = createSkipRecord(
                        originalRequest, httpService, requestId, session, "重放异常: " + e.getMessage());
                errorRecord.setJudgment(JudgmentResult.ERROR.name());
                errorRecord.setSimilarity(-1);

                SwingUtilities.invokeLater(() -> {
                    if (callback != null) {
                        callback.onReplayComplete(errorRecord, isFirst);
                    }
                });
            }
        }

        SwingUtilities.invokeLater(() -> {
            if (callback != null) {
                callback.onAllComplete();
            }
        });

        LogManager.getInstance().printOutput("[+] 权限测试重放完成: " + enabledSessions.size() + "个用户会话");
    }

    /**
     * 判决结果封装（内部使用）
     */
    private static class ReplayJudgment {
        private String result = JudgmentResult.PENDING.name();
        private double similarity = -1;
        private Color color = null;
        private String note = "";
        private boolean baselineUpdated = false;
        private byte[] newBaselineResponse;
        private int newBaselineStatusCode;
        private String newBaselineContentType;
    }

    /**
     * 根据响应结果评估判决（基线模式 / 比对模式）
     */
    private ReplayJudgment evaluateJudgment(SyncHttpSender.Result holder, boolean useAsBaselineFallback,
                                             byte[] baselineResponse, int baselineStatusCode,
                                             String baselineContentType, boolean baselineValid,
                                             UserSession session, int requestId) {
        ReplayJudgment judgment = new ReplayJudgment();

        if (holder.response != null && holder.response.length > 0) {
            if (useAsBaselineFallback) {
                judgment.newBaselineResponse = HttpMessageParser.extractResponseBody(holder.response);
                judgment.newBaselineStatusCode = holder.statusCode;
                String baselineHeaders = HttpMessageParser.extractResponseHeaders(holder.response);
                judgment.newBaselineContentType = JudgmentEngine.extractContentType(baselineHeaders);
                judgment.baselineUpdated = true;
                judgment.result = JudgmentResult.NOT_ESCALATED.name();
                judgment.note = "兼容模式：以此响应为基准";
            } else {
                String responseHeaders = HttpMessageParser.extractResponseHeaders(holder.response);
                byte[] responseBodyOnly = HttpMessageParser.extractResponseBody(holder.response);
                double threshold = 0.70;

                // 判决前诊断日志
                if (baselineResponse == null || baselineResponse.length == 0) {
                    LogManager.getInstance().printError(String.format(
                            "[!] 基准响应体为空(requestId=%d,用户=%s),相似度计算不可靠",
                            requestId, session.getName()));
                }
                if (responseBodyOnly == null || responseBodyOnly.length == 0) {
                    LogManager.getInstance().printError(String.format(
                            "[!] 当前响应体为空(用户=%s),相似度计算不可靠", session.getName()));
                }
                LogManager.getInstance().judgmentDebug(String.format(
                        "[判决] 判决前数据: baselineBodyLen=%d, currentBodyLen=%d, baselineStatusCode=%d, currentStatusCode=%d, threshold=%.2f",
                        baselineResponse != null ? baselineResponse.length : -1,
                        responseBodyOnly != null ? responseBodyOnly.length : -1,
                        baselineStatusCode, holder.statusCode, threshold));
                LogManager.getInstance().judgmentDebug(String.format(
                        "[判决] 基准响应体前200字: %s", truncateForLog(baselineResponse, 200)));
                LogManager.getInstance().judgmentDebug(String.format(
                        "[判决] 当前响应体前200字: %s", truncateForLog(responseBodyOnly, 200)));

                boolean allFieldsEmpty = session.getFieldValues().values().stream()
                        .allMatch(v -> v == null || v.isEmpty());

                JudgmentOutcome outcome = JudgmentEngine.judge(
                        holder.statusCode, responseHeaders, responseBodyOnly,
                        baselineResponse, baselineStatusCode, baselineContentType, threshold,
                        holder.durationMs, allFieldsEmpty);

                judgment.result = outcome.result.name();
                judgment.similarity = outcome.similarity;
                judgment.color = outcome.color;
                judgment.note = outcome.note;
            }
        } else {
            judgment.result = JudgmentResult.ERROR.name();
            if (useAsBaselineFallback) {
                LogManager.getInstance().printError("[!] 兼容模式：基线用户请求失败，后续会话将跳过判决");
            } else {
                judgment.note = "请求无响应";
            }
        }

        return judgment;
    }

    /**
     * 诊断并记录会话的字段配置状态
     */
    private void logSessionFieldDiagnostics(UserSession session, List<FieldDefinition> locations) {
        if (locations.isEmpty()) {
            LogManager.getInstance().printError(String.format(
                    "[!] 权限测试: 用户 '%s' (schemeId=%s) 没有关联的字段位置，"
                    + "将使用原始请求字段发送，可能导致误判！",
                    session.getName(), session.getSchemeId()));
        } else {
            int configuredCount = session.getFieldValues().size();
            if (configuredCount == 0) {
                LogManager.getInstance().printError(String.format(
                        "[!] 字段替换: 用户 '%s' → %d 个字段位置 / 0 个已配置值！"
                        + "所有字段将被从请求中删除，可能导致 401 认证失败！",
                        session.getName(), locations.size()));
            } else {
                java.util.Set<Integer> valueIds = session.getFieldValues().keySet();
                java.util.Set<Integer> locationIds = new java.util.HashSet<>();
                for (FieldDefinition loc : locations) {
                    locationIds.add(loc.getId());
                }
                long matchCount = valueIds.stream().filter(locationIds::contains).count();
                if (matchCount == 0) {
                    LogManager.getInstance().printError(String.format(
                            "[!] 字段替换: 用户 '%s' → 字段值ID(%s)与位置ID(%s)完全不匹配！"
                            + "请检查字段方案与用户配置是否对应",
                            session.getName(), valueIds, locationIds));
                } else {
                    LogManager.getInstance().printOutput(String.format(
                            "[*] 字段替换: 用户 '%s' → %d 个字段位置 / %d 个已配置值 (匹配%d个)",
                            session.getName(), locations.size(), configuredCount, matchCount));
                }
            }
        }
    }

    /**
     * 创建跳过/错误记录的通用方法
     */
    private RequestResponseRecord createSkipRecord(byte[] originalRequest, HttpService httpService,
                                                    int requestId, UserSession session, String comment) {
        RequestResponseRecord record = new RequestResponseRecord();
        record.setRequestId(requestId);
        populateRecordFromRequest(record, originalRequest, httpService);
        record.setStatusCode(0);
        record.setResponseTime(0);
        record.setRequestData(originalRequest);
        record.setResponseData(new byte[0]);
        record.setTimestamp(new java.util.Date());
        record.setUserSessionName(session.getName());
        record.setJudgment(JudgmentResult.ERROR.name());
        record.setSimilarity(-1);
        record.setComment(comment);
        return record;
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

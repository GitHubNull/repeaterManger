package org.oxff.repeater.privilege;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.proxy.http.InterceptedRequest;
import org.oxff.repeater.db.RequestDAO;
import org.oxff.repeater.http.HttpMessageParser;
import org.oxff.repeater.http.HttpRequestHelper;
import org.oxff.repeater.http.RequestManager;
import org.oxff.repeater.http.RequestResponseRecord;
import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.privilege.model.JudgmentResult;
import org.oxff.repeater.privilege.model.TokenLocation;
import org.oxff.repeater.privilege.model.UserSession;
import org.oxff.repeater.UIRequestDispatcher;

import javax.swing.SwingUtilities;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 自动化测试引擎（单例）
 * 从Scope匹配的代理流量中自动获取请求，遍历用户会话重放
 *
 * 工作流程：
 * 1. ScopeManager 在代理中拦截匹配的请求
 * 2. 调用 submitRequest() 提交给 AutoTestEngine
 * 3. AutoTestEngine 检查去重、遍历用户会话替换令牌并发送
 * 4. 结果通过 RepeaterManagerUI 回传到请求管理Tab
 */
public class AutoTestEngine {

    private static AutoTestEngine instance;

    private final ExecutorService executor;

    /** 已处理的API集合（用于去重，线程安全） */
    private final Set<String> processedApis = ConcurrentHashMap.newKeySet();

    private AutoTestEngine() {
        this.executor = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "AutoTest-Worker");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * 获取单例实例
     */
    public static synchronized AutoTestEngine getInstance() {
        if (instance == null) {
            instance = new AutoTestEngine();
        }
        return instance;
    }

    /**
     * 提交请求进行自动化测试
     *
     * @param interceptedRequest 代理拦截到的请求
     */
    public void submitRequest(InterceptedRequest interceptedRequest) {
        SessionManager sessionManager = SessionManager.getInstance();
        if (!sessionManager.hasEnabledSessions()) {
            LogManager.getInstance().printOutput("[*] 自动化测试：无已启用用户会话，跳过");
            return;
        }

        // 去重检查：使用 DedupConfigManager 按优先级链式计算去重键，失败时自动回退PATH
        DedupConfigManager dedupConfigManager = DedupConfigManager.getInstance();
        byte[] requestBytes = interceptedRequest.toByteArray().getBytes();
        String api = dedupConfigManager.computeDedupKey(
                requestBytes, interceptedRequest.httpService());
        if (ApiDedupEngine.checkAndAddKey(processedApis, api)) {
            LogManager.getInstance().printOutput("[*] 自动化测试：API已处理过，跳过去重: " + api);
            return;
        }

        executor.submit(() -> {
            try {
                HttpService httpService = interceptedRequest.httpService();

                LogManager.getInstance().printOutput("[*] 自动化测试：开始处理 " + api);

                List<UserSession> enabledSessions = sessionManager.getEnabledSessions();
                RequestManager requestManager = new RequestManager();

                // 保存原始请求到 requests 表（用于报告生成时获取原始报文）
                int requestId = -1;
                try {
                    RequestDAO requestDAO = new RequestDAO();
                    requestId = requestDAO.saveRequest(
                            httpService.secure() ? "https" : "http",
                            HttpRequestHelper.resolveDomainFromService(httpService),
                            interceptedRequest.path(),
                            interceptedRequest.query() != null ? interceptedRequest.query() : "",
                            interceptedRequest.method(),
                            requestBytes,
                            true  // isPrivilegeTest
                    );
                    if (requestId > 0) {
                        final int finalRequestId = requestId;
                        SwingUtilities.invokeLater(() -> {
                            UIRequestDispatcher.getInstance().addAutoTestRequestToPanel(finalRequestId, api,
                                    interceptedRequest.method(),
                                    httpService.secure() ? "https" : "http",
                                    HttpRequestHelper.resolveDomainFromService(httpService),
                                    interceptedRequest.path(),
                                    interceptedRequest.query() != null ? interceptedRequest.query() : "",
                                    requestBytes);
                        });
                    }
                } catch (Exception e) {
                    LogManager.getInstance().printError("[!] 保存自动化测试原始请求失败: " + e.getMessage());
                }

                // 存储基准用户响应
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
                    int retryDelayMs = sessionManager.getRetryDelay();

                    // 非基准用户：如果基准请求失败，跳过比对判决，标记为ERROR
                    if (!isFirst && !baselineValid) {
                        RequestResponseRecord skipRecord = new RequestResponseRecord();
                        skipRecord.setRequestId(requestId);
                        skipRecord.setMethod(interceptedRequest.method());
                        skipRecord.setProtocol(httpService.secure() ? "https" : "http");
                        skipRecord.setDomain(HttpRequestHelper.resolveDomainFromService(httpService));
                        skipRecord.setPath(interceptedRequest.path());
                        skipRecord.setQueryParameters(interceptedRequest.query() != null ? interceptedRequest.query() : "");
                        skipRecord.setApi(api);
                        skipRecord.setStatusCode(0);
                        skipRecord.setResponseLength(0);
                        skipRecord.setResponseTime(0);
                        skipRecord.setRequestData(requestBytes);
                        skipRecord.setResponseData(new byte[0]);
                        skipRecord.setTimestamp(new java.util.Date());
                        skipRecord.setUserSessionName(session.getName());
                        skipRecord.setJudgment(JudgmentResult.ERROR.name());
                        skipRecord.setSimilarity(-1);
                        skipRecord.setComment("基准请求失败，无法进行对比判决");

                        final RequestResponseRecord finalSkipRecord = skipRecord;
                        SwingUtilities.invokeLater(() -> {
                            UIRequestDispatcher.getInstance().addPrivilegeTestRecord(finalSkipRecord);
                        });

                        LogManager.getInstance().printOutput(String.format(
                                "[*] 自动化测试: 用户=%s, 判决=ERROR (基准请求失败)",
                                session.getName()));
                        continue;
                    }

                    try {
                        byte[] modifiedRequest = TokenReplacementEngine.replaceTokens(
                                requestBytes, locations, session);

                        // 检测 HTTP/2 协议版本，确保重放时保持与原始请求相同的协议
                        boolean useHttp2 = "HTTP/2".equals(interceptedRequest.httpVersion());

                        // 带重试的同步发送（使用会话级别的超时和重试配置）
                        SyncHttpSender.Result holder = sendSyncRequestWithRetry(
                                modifiedRequest, httpService, requestManager,
                                useHttp2, timeoutSeconds, retryCount, retryDelayMs);

                        // 判决
                        String judgment = JudgmentResult.PENDING.name();
                        double similarity = -1;
                        java.awt.Color judgmentColor = null;
                        String judgmentNote = "";

                        if (holder.response != null && holder.response.length > 0) {
                            if (isFirst) {
                                baselineResponse = HttpMessageParser.extractResponseBody(holder.response);
                                baselineStatusCode = holder.statusCode;
                                baselineValid = true;
                                judgment = JudgmentResult.NOT_ESCALATED.name();
                            } else {
                                String responseHeaders = HttpMessageParser.extractResponseHeaders(holder.response);
                                byte[] responseBodyOnly = HttpMessageParser.extractResponseBody(holder.response);
                                double threshold = sessionManager.getSimilarityThreshold();

                                // === 判决前诊断日志 ===
                                if (baselineResponse == null || baselineResponse.length == 0) {
                                    LogManager.getInstance().printError(String.format(
                                            "[!] 基准响应体为空(用户=%s),相似度计算不可靠", session.getName()));
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
                                LogManager.getInstance().printError("[!] 自动化测试：基准用户请求失败，后续会话将跳过判决");
                            }
                            if (holder.errorMessage != null && !holder.errorMessage.isEmpty()) {
                                judgmentNote = "请求失败: " + holder.errorMessage;
                                LogManager.getInstance().printError("[!] 自动化测试请求失败 (user=" + session.getName()
                                        + "): " + holder.errorMessage);
                            }
                        }

                        RequestResponseRecord record = new RequestResponseRecord();
                        record.setRequestId(requestId);
                        record.setMethod(interceptedRequest.method());
                        record.setProtocol(httpService.secure() ? "https" : "http");
                        record.setDomain(HttpRequestHelper.resolveDomainFromService(httpService));
                        record.setPath(interceptedRequest.path());
                        record.setQueryParameters(interceptedRequest.query() != null ? interceptedRequest.query() : "");
                        record.setApi(api);
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

                        if (judgmentNote != null && !judgmentNote.isEmpty()) {
                            record.setComment(judgmentNote);
                        }

                        // 通过 RepeaterManagerUI 回传
                        final RequestResponseRecord finalRecord = record;
                        SwingUtilities.invokeLater(() -> {
                            UIRequestDispatcher.getInstance().addPrivilegeTestRecord(finalRecord);
                        });

                        LogManager.getInstance().printOutput(String.format(
                                "[*] 自动化测试: 用户=%s, 判决=%s, 相似度=%.2f",
                                session.getName(),
                                JudgmentResult.toDisplayName(judgment),
                                similarity));

                    } catch (Exception e) {
                        LogManager.getInstance().printError("[!] 自动化测试重放异常 (user=" + session.getName() + "): " + e.getMessage());

                        // 基准用户异常时不设置baselineValid
                        if (isFirst) {
                            LogManager.getInstance().printError("[!] 自动化测试：基准用户请求异常，后续会话将跳过判决");
                        }
                    }
                }

                LogManager.getInstance().printOutput("[+] 自动化测试完成: " + api);

            } catch (Exception e) {
                LogManager.getInstance().printError("[!] 自动化测试处理请求异常: " + e.getMessage());
            }
        });
    }

    /**
     * 清除去重记录
     */
    public void clearProcessedApis() {
        processedApis.clear();
    }

    /**
     * 获取已处理API数量
     */
    public int getProcessedApiCount() {
        return processedApis.size();
    }

    // ==================== 内部方法 ====================

    /**
     * 带重试的同步发送HTTP请求（委托给 SyncHttpSender）
     *
     * @param useHttp2 是否使用 HTTP/2 协议重放，从 interceptedRequest.httpVersion() 检测
     */
    private SyncHttpSender.Result sendSyncRequestWithRetry(byte[] requestBytes, HttpService httpService,
                                                             RequestManager requestManager,
                                                             boolean useHttp2,
                                                             int timeoutSeconds, int retryCount, int retryDelayMs) {
        return SyncHttpSender.sendWithRetry(requestBytes, httpService, requestManager,
                useHttp2, timeoutSeconds, retryCount, retryDelayMs, "自动化测试");
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

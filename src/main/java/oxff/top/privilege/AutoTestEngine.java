package oxff.top.privilege;

import burp.BurpExtender;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.proxy.http.InterceptedRequest;
import oxff.top.http.HttpRequestHelper;
import oxff.top.http.RequestManager;
import oxff.top.http.RequestResponseRecord;
import oxff.top.privilege.model.JudgmentResult;
import oxff.top.privilege.model.TokenLocation;
import oxff.top.privilege.model.UserSession;

import javax.swing.SwingUtilities;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
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

    /** 已处理的API集合（用于去重） */
    private final Set<String> processedApis = new HashSet<>();

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
            BurpExtender.printOutput("[*] 自动化测试：无已启用用户会话，跳过");
            return;
        }

        // 去重检查
        if (sessionManager.isDedupEnabled()) {
            String api = HttpRequestHelper.computeApiFromRequest(
                    interceptedRequest.path(),
                    interceptedRequest.query() != null ? interceptedRequest.query() : "",
                    interceptedRequest.toByteArray().getBytes());
            synchronized (processedApis) {
                if (processedApis.contains(api)) {
                    BurpExtender.printOutput("[*] 自动化测试：API已处理过，跳过去重: " + api);
                    return;
                }
                processedApis.add(api);
            }
        }

        executor.submit(() -> {
            try {
                byte[] requestBytes = interceptedRequest.toByteArray().getBytes();
                HttpService httpService = interceptedRequest.httpService();
                String api = HttpRequestHelper.computeApiFromRequest(
                        interceptedRequest.path(),
                        interceptedRequest.query() != null ? interceptedRequest.query() : "",
                        requestBytes);

                BurpExtender.printOutput("[*] 自动化测试：开始处理 " + api);

                List<UserSession> enabledSessions = sessionManager.getEnabledSessions();
                List<TokenLocation> locations = sessionManager.getTokenLocations();
                RequestManager requestManager = new RequestManager();

                // 存储基准用户响应
                byte[] baselineResponse = null;
                int baselineStatusCode = -1;

                for (int i = 0; i < enabledSessions.size(); i++) {
                    UserSession session = enabledSessions.get(i);
                    boolean isFirst = (i == 0);

                    try {
                        byte[] modifiedRequest = TokenReplacementEngine.replaceTokens(
                                requestBytes, locations, session);

                        // 同步发送
                        ReplayEngine replayEngine = ReplayEngine.getInstance();
                        java.lang.reflect.Method sendSyncMethod = ReplayEngine.class.getDeclaredMethod(
                                "sendSync", byte[].class, HttpService.class, RequestManager.class);
                        sendSyncMethod.setAccessible(true);

                        // 使用 ReplayEngine 的内部同步发送方式
                        Object holderObj = sendSyncMethod.invoke(replayEngine, modifiedRequest, httpService, requestManager);

                        // 由于 sendSync 是 private，这里直接内联发送逻辑
                        ReplayResultHolder holder = sendSyncRequest(modifiedRequest, httpService, requestManager);

                        // 判决
                        String judgment = JudgmentResult.PENDING.name();
                        double similarity = -1;
                        java.awt.Color judgmentColor = null;
                        String judgmentNote = "";

                        if (holder.response != null && holder.response.length > 0) {
                            if (isFirst) {
                                baselineResponse = holder.response;
                                baselineStatusCode = holder.statusCode;
                                judgment = JudgmentResult.NOT_ESCALATED.name();
                            } else {
                                String responseHeaders = extractResponseHeaders(holder.response);
                                double threshold = sessionManager.getSimilarityThreshold();
                                JudgmentEngine.JudgmentOutcome outcome = JudgmentEngine.judge(
                                        holder.statusCode, responseHeaders, holder.response,
                                        baselineResponse, baselineStatusCode, threshold);
                                judgment = outcome.result.name();
                                similarity = outcome.similarity;
                                judgmentColor = outcome.color;
                                judgmentNote = outcome.note;
                            }
                        } else {
                            judgment = JudgmentResult.ERROR.name();
                        }

                        RequestResponseRecord record = new RequestResponseRecord();
                        record.setMethod(interceptedRequest.method());
                        record.setProtocol(httpService.secure() ? "https" : "http");
                        record.setDomain(httpService.host());
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
                        if (judgmentNote != null && !judgmentNote.isEmpty()) {
                            record.setComment(judgmentNote);
                        }

                        // 通过 RepeaterManagerUI 回传
                        final RequestResponseRecord finalRecord = record;
                        SwingUtilities.invokeLater(() -> {
                            burp.BurpExtender.addPrivilegeTestRecord(finalRecord);
                        });

                        BurpExtender.printOutput(String.format(
                                "[*] 自动化测试: 用户=%s, 判决=%s, 相似度=%.2f",
                                session.getName(), judgment, similarity));

                    } catch (Exception e) {
                        BurpExtender.printError("[!] 自动化测试重放异常 (user=" + session.getName() + "): " + e.getMessage());
                    }
                }

                BurpExtender.printOutput("[+] 自动化测试完成: " + api);

            } catch (Exception e) {
                BurpExtender.printError("[!] 自动化测试处理请求异常: " + e.getMessage());
            }
        });
    }

    /**
     * 清除去重记录
     */
    public void clearProcessedApis() {
        synchronized (processedApis) {
            processedApis.clear();
        }
    }

    /**
     * 获取已处理API数量
     */
    public int getProcessedApiCount() {
        synchronized (processedApis) {
            return processedApis.size();
        }
    }

    // ==================== 内部方法 ====================

    private String extractResponseHeaders(byte[] responseBytes) {
        if (responseBytes == null || responseBytes.length == 0) return "";
        try {
            String responseStr = new String(responseBytes, java.nio.charset.StandardCharsets.UTF_8);
            int bodySeparator = responseStr.indexOf("\r\n\r\n");
            if (bodySeparator > 0) return responseStr.substring(0, bodySeparator);
            bodySeparator = responseStr.indexOf("\n\n");
            if (bodySeparator > 0) return responseStr.substring(0, bodySeparator);
            return responseStr;
        } catch (Exception e) {
            return "";
        }
    }

    private ReplayResultHolder sendSyncRequest(byte[] requestBytes, HttpService httpService,
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
     * 内部结果持有者
     */
    private static class ReplayResultHolder {
        byte[] response;
        int statusCode = -1;
        long durationMs;
        String errorMessage;
    }
}

package org.oxff.repeater.privilege;

import burp.api.montoya.http.HttpService;
import org.oxff.repeater.http.RequestCallback;
import org.oxff.repeater.http.RequestManager;
import org.oxff.repeater.logging.LogManager;

/**
 * 同步 HTTP 请求发送工具类
 * 消除 AutoTestEngine 和 ReplayEngine 之间 ~80% 的重复代码
 *
 * 提供带超时等待的同步请求发送能力（底层使用异步 API + wait/notify 实现），
 * 以及失败重试逻辑。
 */
public final class SyncHttpSender {

    private SyncHttpSender() {
        // 工具类，禁止实例化
    }

    /**
     * 同步发送结果持有者
     */
    public static class Result {
        public byte[] response;
        public int statusCode = -1;
        public long durationMs;
        public String errorMessage;
    }

    /**
     * 带重试的同步发送 HTTP 请求
     *
     * @param requestBytes   请求字节数组
     * @param httpService    HTTP 服务信息
     * @param requestManager 请求管理器
     * @param useHttp2       是否使用 HTTP/2 协议
     * @param timeoutSeconds 请求超时时间（秒）
     * @param retryCount     失败重试次数
     * @param retryDelayMs   重试间隔（毫秒）
     * @param logContext     日志上下文标识（如 "重放"、"自动化测试"）
     */
    public static Result sendWithRetry(byte[] requestBytes, HttpService httpService,
                                        RequestManager requestManager, boolean useHttp2,
                                        int timeoutSeconds, int retryCount, int retryDelayMs,
                                        String logContext) {
        Result holder = sendOnce(requestBytes, httpService, requestManager, useHttp2, timeoutSeconds);

        int attempts = 0;
        while (holder.errorMessage != null && attempts < retryCount) {
            attempts++;
            LogManager.getInstance().printOutput(String.format("[*] %s重试 (%d/%d), 等待 %dms...",
                    logContext, attempts, retryCount, retryDelayMs));
            try {
                Thread.sleep(retryDelayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            holder = sendOnce(requestBytes, httpService, requestManager, useHttp2, timeoutSeconds);
        }

        return holder;
    }

    /**
     * 单次同步发送 HTTP 请求
     *
     * @param requestBytes   请求字节数组
     * @param httpService    HTTP 服务信息
     * @param requestManager 请求管理器
     * @param useHttp2       是否使用 HTTP/2 协议
     * @param timeoutSeconds 请求超时时间（秒）
     */
    public static Result sendOnce(byte[] requestBytes, HttpService httpService,
                                   RequestManager requestManager, boolean useHttp2,
                                   int timeoutSeconds) {
        Result holder = new Result();
        Object lock = new Object();
        boolean[] done = {false};

        requestManager.makeHttpRequestAsync(requestBytes, timeoutSeconds, -1, httpService, useHttp2,
                new RequestCallback() {
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
            // 超时后设置 errorMessage，使 sendWithRetry 的重试逻辑能被触发
            if (!done[0] && holder.errorMessage == null) {
                holder.errorMessage = String.format("请求超时（等待 %dms 未收到响应）", waitTimeoutMs);
                holder.durationMs = waitTimeoutMs;
                LogManager.getInstance().printError(String.format("[!] 请求超时：等待 %dms 未收到响应", waitTimeoutMs));
            }
        }

        return holder;
    }
}

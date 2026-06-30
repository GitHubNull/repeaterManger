package org.oxff.repeater.privilege.model;

/**
 * 重放配置值对象
 * 管理请求重放的全局默认参数
 */
public class ReplayConfig {

    /** 重放模式：true=实时重放，false=批量重放 */
    private boolean realtimeMode;

    /** 请求超时时间（秒） */
    private int requestTimeout;

    /** 并发线程数 */
    private int maxConcurrent;

    /** 失败重试次数 */
    private int retryCount;

    /** 重试间隔（毫秒） */
    private int retryDelay;

    /** 重放间隔延迟（毫秒），每次重放前的等待时间 */
    private int replayDelay;

    public ReplayConfig() {
        this.realtimeMode = true;
        this.requestTimeout = 30;
        this.maxConcurrent = 1;
        this.retryCount = 0;
        this.retryDelay = 1000;
        this.replayDelay = 0;
    }

    public boolean isRealtimeMode() {
        return realtimeMode;
    }

    public void setRealtimeMode(boolean realtimeMode) {
        this.realtimeMode = realtimeMode;
    }

    public int getRequestTimeout() {
        return requestTimeout;
    }

    public void setRequestTimeout(int requestTimeout) {
        this.requestTimeout = requestTimeout;
    }

    public int getMaxConcurrent() {
        return maxConcurrent;
    }

    public void setMaxConcurrent(int maxConcurrent) {
        this.maxConcurrent = maxConcurrent;
    }

    public int getRetryCount() {
        return retryCount;
    }

    public void setRetryCount(int retryCount) {
        this.retryCount = retryCount;
    }

    public int getRetryDelay() {
        return retryDelay;
    }

    public void setRetryDelay(int retryDelay) {
        this.retryDelay = retryDelay;
    }

    public int getReplayDelay() {
        return replayDelay;
    }

    public void setReplayDelay(int replayDelay) {
        this.replayDelay = replayDelay;
    }
}

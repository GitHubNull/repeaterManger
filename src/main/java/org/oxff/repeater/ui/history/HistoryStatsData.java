package org.oxff.repeater.ui.history;

/**
 * 历史记录统计数据值对象（VO）
 * 封装重放历史的所有统计字段
 */
public class HistoryStatsData {
    // 精简信息（收缩状态显示）
    private int totalCount;           // 重放历史总数
    private int successCount;         // 成功数量（HTTP 2xx）
    private int failureCount;         // 失败数量（非2xx）
    private int retryCount;           // 重放重试个数（按request_id分组，count-1）
    private int maxResponseTime;      // 最高耗时（毫秒）
    private int minResponseTime;      // 最低耗时（毫秒）

    // 完整信息（展开状态额外显示）
    private double avgResponseTime;   // 平均耗时
    private double variance;          // 方差
    private int modeResponseTime;     // 众数
    private double medianResponseTime; // 中位数
    private int requestCount;         // 基准报文表（requests表）总请求数

    public HistoryStatsData() {
        // 默认初始化所有数值为0
    }

    // Getters and Setters

    public int getTotalCount() {
        return totalCount;
    }

    public void setTotalCount(int totalCount) {
        this.totalCount = totalCount;
    }

    public int getSuccessCount() {
        return successCount;
    }

    public void setSuccessCount(int successCount) {
        this.successCount = successCount;
    }

    public int getFailureCount() {
        return failureCount;
    }

    public void setFailureCount(int failureCount) {
        this.failureCount = failureCount;
    }

    public int getRetryCount() {
        return retryCount;
    }

    public void setRetryCount(int retryCount) {
        this.retryCount = retryCount;
    }

    public int getMaxResponseTime() {
        return maxResponseTime;
    }

    public void setMaxResponseTime(int maxResponseTime) {
        this.maxResponseTime = maxResponseTime;
    }

    public int getMinResponseTime() {
        return minResponseTime;
    }

    public void setMinResponseTime(int minResponseTime) {
        this.minResponseTime = minResponseTime;
    }

    public double getAvgResponseTime() {
        return avgResponseTime;
    }

    public void setAvgResponseTime(double avgResponseTime) {
        this.avgResponseTime = avgResponseTime;
    }

    public double getVariance() {
        return variance;
    }

    public void setVariance(double variance) {
        this.variance = variance;
    }

    public int getModeResponseTime() {
        return modeResponseTime;
    }

    public void setModeResponseTime(int modeResponseTime) {
        this.modeResponseTime = modeResponseTime;
    }

    public double getMedianResponseTime() {
        return medianResponseTime;
    }

    public void setMedianResponseTime(double medianResponseTime) {
        this.medianResponseTime = medianResponseTime;
    }

    public int getRequestCount() {
        return requestCount;
    }

    public void setRequestCount(int requestCount) {
        this.requestCount = requestCount;
    }

    /**
     * 检查是否有任何历史记录数据
     */
    public boolean hasData() {
        return totalCount > 0;
    }

    @Override
    public String toString() {
        return String.format(
            "HistoryStatsData{total=%d, success=%d, failure=%d, retry=%d, max=%d, min=%d, avg=%.2f, var=%.2f, mode=%d, median=%.2f, requests=%d}",
            totalCount, successCount, failureCount, retryCount,
            maxResponseTime, minResponseTime, avgResponseTime, variance,
            modeResponseTime, medianResponseTime, requestCount
        );
    }
}

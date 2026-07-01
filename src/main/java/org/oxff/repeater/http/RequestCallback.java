package org.oxff.repeater.http;

/**
 * 请求回调接口
 */
public interface RequestCallback {
    void onSuccess(byte[] response, long requestTimeMs, long responseTimeMs, long durationMs);
    void onFailure(String errorMessage, long requestTimeMs, long responseTimeMs, long durationMs);
}

package org.oxff.repeater.api;

import burp.api.montoya.MontoyaApi;

/**
 * MontoyaApi 静态持有器
 *
 * 作为从旧版静态调用模式 (BurpExtender.callbacks/helpers) 过渡到
 * Montoya 构造注入模式的桥梁。核心组件应优先通过构造函数注入 MontoyaApi，
 * 此类仅用于无法通过构造注入获取 API 的遗留场景。
 */
public final class MontoyaApiHolder {

    private static MontoyaApi api;

    private MontoyaApiHolder() {}

    /**
     * 设置 MontoyaApi 实例（仅由 BurpExtender.initialize 调用一次）
     */
    public static void setApi(MontoyaApi montoyaApi) {
        api = montoyaApi;
    }

    /**
     * 获取 MontoyaApi 实例
     *
     * @return MontoyaApi 实例，如果未初始化则返回 null
     */
    public static MontoyaApi getApi() {
        return api;
    }
}

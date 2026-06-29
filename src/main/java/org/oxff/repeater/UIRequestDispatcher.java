package org.oxff.repeater;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.oxff.repeater.http.RequestResponseRecord;
import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.privilege.SessionParser;

import javax.swing.*;
import java.util.List;

/**
 * 统一 UI 请求调度器 — 负责所有外部模块到 RepeaterManagerUI 的桥接调用。
 * <p>
 * 将原本分散在 BurpExtender 中的 UI 桥接方法集中管理，解耦入口类与 UI 操作。
 */
public class UIRequestDispatcher {

    private static UIRequestDispatcher instance;

    private RepeaterManagerUI repeaterUI;
    private final LogManager logManager = LogManager.getInstance();

    private UIRequestDispatcher() {
    }

    public static synchronized UIRequestDispatcher getInstance() {
        if (instance == null) {
            instance = new UIRequestDispatcher();
        }
        return instance;
    }

    /**
     * 注入主 UI 实例（在插件初始化时调用）
     */
    public void setRepeaterUI(RepeaterManagerUI ui) {
        this.repeaterUI = ui;
    }

    // ==================== 单条请求调度 ====================

    /**
     * 将请求发送到 Repeater Manager
     */
    public void setRepeaterUIRequest(HttpRequestResponse requestResponse) {
        if (repeaterUI != null) {
            SwingUtilities.invokeLater(() -> {
                repeaterUI.setRequest(requestResponse);
                logManager.success("[+] 已将请求发送到 Repeater Manager，请切换到相应标签页查看");
            });
        }
    }

    /**
     * 将请求发送到权限测试模式
     */
    public void setPrivilegeTestRequest(HttpRequestResponse requestResponse) {
        if (repeaterUI != null) {
            SwingUtilities.invokeLater(() -> {
                repeaterUI.setPrivilegeTestRequest(requestResponse);
                logManager.success("[+] 已将请求发送到权限测试，重放结果将在请求管理标签页中显示");
            });
        }
    }

    // ==================== 批量请求调度 ====================

    /**
     * 批量将请求发送到 Repeater Manager
     */
    public void setRepeaterUIRequests(List<HttpRequestResponse> requestResponses) {
        if (repeaterUI != null && requestResponses != null && !requestResponses.isEmpty()) {
            SwingUtilities.invokeLater(() -> {
                repeaterUI.setRequests(requestResponses);
                logManager.success(String.format("[+] 已将 %d 条请求发送到 Repeater Manager，请切换到相应标签页查看",
                        requestResponses.size()));
            });
        }
    }

    /**
     * 批量将请求发送到权限测试模式
     */
    public void setPrivilegeTestRequests(List<HttpRequestResponse> requestResponses) {
        if (repeaterUI != null && requestResponses != null && !requestResponses.isEmpty()) {
            SwingUtilities.invokeLater(() -> {
                repeaterUI.setPrivilegeTestRequests(requestResponses);
                logManager.success(String.format("[+] 已将 %d 条请求发送到权限测试，重放结果将在请求管理标签页中显示",
                        requestResponses.size()));
            });
        }
    }

    // ==================== 自动化测试桥接 ====================

    /**
     * 添加自动化测试的权限测试记录到请求管理Tab
     */
    public void addPrivilegeTestRecord(RequestResponseRecord record) {
        if (repeaterUI != null) {
            SwingUtilities.invokeLater(() -> {
                repeaterUI.addPrivilegeTestHistoryRecord(record);
            });
        }
    }

    /**
     * 将自动化测试的原始请求添加到请求列表面板
     */
    public void addAutoTestRequestToPanel(int requestId, String api, String method,
                                          String protocol, String domain, String path, String query, byte[] requestData) {
        if (repeaterUI != null) {
            SwingUtilities.invokeLater(() -> {
                repeaterUI.addAutoTestRequest(requestId, api, method, protocol, domain, path, query, requestData);
            });
        }
    }

    // ==================== UI 刷新 ====================

    /**
     * 刷新权限测试数据（用户会话表格等）
     */
    public void refreshPrivilegeTestData() {
        if (repeaterUI != null) {
            SwingUtilities.invokeLater(() -> repeaterUI.refreshPrivilegeTestData());
        }
    }

    /**
     * 刷新UI数据 — 供外部模块在导入数据后安全调用
     */
    public void refreshUIData() {
        if (repeaterUI != null) {
            SwingUtilities.invokeLater(() -> repeaterUI.refreshAllData());
        }
    }

    // ==================== 会话解析（委托给 SessionParser） ====================

    /**
     * 从HTTP请求解析用户会话
     */
    public void parseSessionFromRequest(HttpRequest request) {
        SessionParser.getInstance().parseSessionFromRequest(request, repeaterUI);
    }
}

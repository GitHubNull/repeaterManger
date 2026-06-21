package org.oxff.repeater.privilege;

import burp.BurpExtender;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import org.oxff.repeater.api.MontoyaApiHolder;
import org.oxff.repeater.privilege.dao.ScopeDAO;
import org.oxff.repeater.privilege.model.ScopeEntry;

import java.util.ArrayList;
import java.util.List;

/**
 * Scope管理器（单例）
 * 管理自动化测试的范围条目，支持用户自定义Scope和Burp Suite Scope
 */
public class ScopeManager {

    private static ScopeManager instance;

    private final ScopeDAO scopeDAO;

    /** 缓存的Scope条目 */
    private List<ScopeEntry> cachedEntries;

    /** 缓存的已启用条目 */
    private List<ScopeEntry> cachedEnabledEntries;

    /** 是否使用Burp Suite自身的Scope */
    private boolean useBurpScope = false;

    /** 自动化测试开关 */
    private boolean autoTestEnabled = false;

    /** Burp Scope注册句柄 */
    private Registration proxyRegistration;

    private ScopeManager() {
        this.scopeDAO = new ScopeDAO();
        this.cachedEntries = new ArrayList<>();
        this.cachedEnabledEntries = new ArrayList<>();
    }

    /**
     * 获取单例实例
     */
    public static synchronized ScopeManager getInstance() {
        if (instance == null) {
            instance = new ScopeManager();
        }
        return instance;
    }

    /**
     * 刷新缓存
     */
    public void refreshCache() {
        cachedEntries = scopeDAO.getAllEntries();
        cachedEnabledEntries = scopeDAO.getEnabledEntries();
        BurpExtender.printOutput("[+] Scope缓存已刷新: " + cachedEntries.size() +
                "条目, " + cachedEnabledEntries.size() + "条已启用");
    }

    /**
     * 获取所有Scope条目
     */
    public List<ScopeEntry> getAllEntries() {
        if (cachedEntries.isEmpty()) {
            refreshCache();
        }
        return cachedEntries;
    }

    /**
     * 获取已启用的Scope条目
     */
    public List<ScopeEntry> getEnabledEntries() {
        if (cachedEnabledEntries.isEmpty()) {
            refreshCache();
        }
        return cachedEnabledEntries;
    }

    /**
     * 检查URL是否在Scope范围内
     */
    public boolean isInScope(String url) {
        if (url == null || url.isEmpty()) return false;

        // 检查Burp Scope
        if (useBurpScope) {
            try {
                MontoyaApi api = MontoyaApiHolder.getApi();
                if (api != null && api.scope().isInScope(url)) {
                    return true;
                }
            } catch (Exception e) {
                // Burp API不可用，忽略
            }
        }

        // 检查自定义Scope
        for (ScopeEntry entry : getEnabledEntries()) {
            if (entry.matches(url)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 添加Scope条目
     * @return 新条目ID
     */
    public int addEntry(ScopeEntry entry) {
        int id = scopeDAO.addEntry(entry);
        if (id > 0) {
            refreshCache();
        }
        return id;
    }

    /**
     * 更新Scope条目
     */
    public boolean updateEntry(ScopeEntry entry) {
        boolean result = scopeDAO.updateEntry(entry);
        if (result) {
            refreshCache();
        }
        return result;
    }

    /**
     * 删除Scope条目
     */
    public boolean deleteEntry(int id) {
        boolean result = scopeDAO.deleteEntry(id);
        if (result) {
            refreshCache();
        }
        return result;
    }

    /**
     * 切换条目启用状态
     */
    public boolean toggleEntryEnabled(int id, boolean enabled) {
        ScopeEntry entry = scopeDAO.getAllEntries().stream()
                .filter(e -> e.getId() == id).findFirst().orElse(null);
        if (entry == null) return false;
        entry.setEnabled(enabled);
        return updateEntry(entry);
    }

    public boolean isUseBurpScope() {
        return useBurpScope;
    }

    public void setUseBurpScope(boolean useBurpScope) {
        this.useBurpScope = useBurpScope;
    }

    public boolean isAutoTestEnabled() {
        return autoTestEnabled;
    }

    public void setAutoTestEnabled(boolean autoTestEnabled) {
        boolean wasEnabled = this.autoTestEnabled;
        this.autoTestEnabled = autoTestEnabled;

        if (autoTestEnabled && !wasEnabled) {
            registerProxyHandler();
            BurpExtender.printOutput("[+] 自动化测试已开启，监听代理流量");
        } else if (!autoTestEnabled && wasEnabled) {
            unregisterProxyHandler();
            BurpExtender.printOutput("[*] 自动化测试已关闭");
        }
    }

    /**
     * 注册代理请求处理器，拦截匹配Scope的请求
     */
    private void registerProxyHandler() {
        try {
            MontoyaApi api = MontoyaApiHolder.getApi();
            if (api == null) return;

            proxyRegistration = api.proxy().registerRequestHandler(new ProxyRequestHandler() {
                @Override
                public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
                    String url = interceptedRequest.url();
                    if (isInScope(url)) {
                        // 异步提交到自动测试引擎
                        AutoTestEngine.getInstance().submitRequest(interceptedRequest);
                    }
                    return ProxyRequestReceivedAction.continueWith(interceptedRequest);
                }

                @Override
                public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
                    return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
                }
            });
        } catch (Exception e) {
            BurpExtender.printError("[!] 注册代理处理器失败: " + e.getMessage());
        }
    }

    /**
     * 取消注册代理请求处理器
     */
    private void unregisterProxyHandler() {
        if (proxyRegistration != null) {
            try {
                proxyRegistration.deregister();
            } catch (Exception e) {
                // 忽略
            }
            proxyRegistration = null;
        }
    }
}

package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import oxff.top.RepeaterManagerUI;
import oxff.top.api.MontoyaApiHolder;
import oxff.top.controller.PopMenu;
import oxff.top.logging.LogLevel;
import oxff.top.logging.LogManager;

import oxff.top.http.RequestResponseRecord;

import javax.swing.SwingUtilities;

/**
 * Burp扩展入口点 - 负责注册插件并初始化所需组件
 * 使用 Montoya SDK 的 BurpExtension 接口
 */
public class BurpExtender implements BurpExtension {

    // 主UI组件
    private static RepeaterManagerUI repeaterUI;

    // 日志管理器
    private static final LogManager logManager = LogManager.getInstance();

    @Override
    public void initialize(MontoyaApi api) {
        // 保存 MontoyaApi 实例到全局持有器
        MontoyaApiHolder.setApi(api);

        // 设置插件名称
        api.extension().setName("repeaterManger");

        try {
            // 阶段1：初始化日志管理器（仅 BurpConsoleHandler）
            logManager.initialize(api);

            // 阶段2：加载早期配置（日志级别、UI、控制台、代理，不含文件 Handler）
            loadLogConfigEarly();

            // 阶段3：初始化数据库（创建会话目录 + 数据库）
            logManager.info("[*] 正在初始化数据库...");
            oxff.top.db.DatabaseManager dbManager = oxff.top.db.DatabaseManager.getInstance();

            if (dbManager.initialize()) {
                logManager.success("[+] 数据库初始化成功");

                // 测试写入示例数据
                dbManager.testDatabaseWithSampleData();
                logManager.success("[+] 数据库测试完成");

                // 检查数据库状态
                dbManager.checkDatabaseStatus();
            } else {
                logManager.error("[!] 数据库初始化失败");
            }

            // 阶段4：加载晚期配置（文件日志 Handler → 会话目录的 logs/）
            loadLogConfigLate();

            // 阶段4.5：加载全局API提取规则
            try {
                oxff.top.api.GlobalRuleManager.getInstance().loadRules();
                logManager.success("[+] 全局API提取规则加载完成");
            } catch (Exception e) {
                logManager.error("[!] 全局API提取规则加载失败: " + e.getMessage());
            }

            // 阶段4.6：加载全局令牌位置
            try {
                oxff.top.privilege.GlobalTokenLocationManager.getInstance().loadLocations();
                oxff.top.privilege.SessionManager.getInstance().loadGlobalTokenLocations();
                logManager.success("[+] 全局令牌位置加载完成");
            } catch (Exception e) {
                logManager.error("[!] 全局令牌位置加载失败: " + e.getMessage());
            }

            // 创建UI和功能组件
            repeaterUI = new RepeaterManagerUI(api);

            // 将UI组件注册到Burp的选项卡
            api.userInterface().registerSuiteTab("Repeater Manager", repeaterUI.getUiComponent());

            // 注册上下文菜单
            api.userInterface().registerContextMenuItemsProvider(new PopMenu());

            // 注册扩展卸载监听器
            api.extension().registerUnloadingHandler(() -> {
                logManager.info("[*] 插件正在卸载，关闭日志系统...");
                logManager.shutdown();
            });

            // 使用编码后的输出流打印信息
            logManager.success("[+] Repeater Manager 插件加载成功");
        } catch (Exception e) {
            // 使用 Montoya API 输出异常
            api.logging().logToError("[!] 插件加载失败: " + e.getMessage());
            api.logging().logToError(e);
        }
    }

    /**
     * 早期配置加载 - 日志级别、UI、控制台、代理（不含文件 Handler）
     * 在数据库初始化之前调用
     */
    private void loadLogConfigEarly() {
        try {
            oxff.top.config.DatabaseConfig config =
                oxff.top.db.DatabaseManager.getInstance().getConfig();

            // 日志级别
            String levelStr = config.getProperty("log.level", "INFO");
            logManager.setLevel(LogLevel.fromName(levelStr));

            // 文件日志开关（先记录状态，Handler 在 loadLogConfigLate 中创建）
            boolean fileEnabled = Boolean.parseBoolean(config.getProperty("log.file.enabled", "true"));
            logManager.setFileLoggingEnabled(fileEnabled);

            // UI日志
            boolean uiEnabled = Boolean.parseBoolean(config.getProperty("log.ui.enabled", "true"));
            logManager.setUILoggingEnabled(uiEnabled);

            // Burp控制台
            boolean burpEnabled = Boolean.parseBoolean(config.getProperty("log.burp_console.enabled", "true"));
            logManager.setBurpConsoleEnabled(burpEnabled);

            // 代理配置
            oxff.top.http.ProxyConfig proxyConfig = oxff.top.http.ProxyConfig.getInstance();
            proxyConfig.loadFromConfig(config);
        } catch (Exception e) {
            // 配置加载失败不应阻止插件运行
            System.err.println("加载早期日志配置失败: " + e.getMessage());
        }
    }

    /**
     * 晚期配置加载 - 文件日志 Handler
     * 在数据库初始化之后调用，将会话目录的 logs/ 子目录作为日志目录
     */
    private void loadLogConfigLate() {
        try {
            oxff.top.config.DatabaseConfig config =
                oxff.top.db.DatabaseManager.getInstance().getConfig();

            boolean fileEnabled = config.isLogFileEnabled();
            if (!fileEnabled) {
                return;
            }

            // 确定日志目录：优先使用用户自定义目录，否则使用会话目录的 logs/
            String logDir = config.getLogFileDirectory();
            if (logDir == null || logDir.isEmpty()) {
                // 使用会话目录的 logs/ 子目录
                java.io.File sessionLogsDir = oxff.top.db.DatabaseManager.getInstance().getLogsDirectory();
                if (sessionLogsDir != null) {
                    logDir = sessionLogsDir.getAbsolutePath();
                } else {
                    // 回退到旧默认值
                    logDir = System.getProperty("user.dir") + "/repeater_manager/logs";
                }
            }

            long maxSize = config.getLogFileMaxSize();
            int maxBackups = config.getLogFileMaxBackups();
            logManager.initializeFileHandler(logDir, maxSize, maxBackups);
            logManager.info("[+] 文件日志已初始化: " + logDir);
        } catch (Exception e) {
            // 文件日志初始化失败不应阻止插件运行
            System.err.println("加载晚期日志配置失败: " + e.getMessage());
        }
    }

    /**
     * 输出日志到标准输出 - 委托给LogManager
     *
     * @param message 日志消息
     */
    public static void printOutput(String message) {
        logManager.printOutput(message);
    }

    /**
     * 输出错误日志 - 委托给LogManager
     *
     * @param message 错误消息
     */
    public static void printError(String message) {
        // 过滤掉已知的无害错误信息
        if (shouldFilterError(message)) {
            return;
        }
        logManager.printError(message);
    }

    /**
     * 判断是否应该过滤掉特定的错误信息
     *
     * @param message 错误消息
     * @return 是否应该过滤
     */
    private static boolean shouldFilterError(String message) {
        if (message == null) {
            return false;
        }

        if (message.contains("ClassNotFoundException") &&
            (message.contains("com.intellij.") ||
             message.contains("EditorCopyPasteHelperImpl") ||
             message.contains("CopyPasteOptionsTransferableData"))) {
            return true;
        }

        if (message.contains("DataFlavor for: application/x-java-serialized-object") &&
            message.contains("com.intellij.openapi.editor.impl")) {
            return true;
        }

        return false;
    }

    public static void setRepeaterUIRequest(HttpRequestResponse requestResponse) {
        if (repeaterUI != null) {
            SwingUtilities.invokeLater(() -> {
                repeaterUI.setRequest(requestResponse);
                logManager.success("[+] 已将请求发送到 Repeater Manager，请切换到相应标签页查看");
            });
        }
    }

    /**
     * 将请求发送到权限测试模式
     * 加载请求后自动切换到请求管理标签页并启动权限测试重放
     */
    public static void setPrivilegeTestRequest(HttpRequestResponse requestResponse) {
        if (repeaterUI != null) {
            SwingUtilities.invokeLater(() -> {
                repeaterUI.setPrivilegeTestRequest(requestResponse);
                logManager.success("[+] 已将请求发送到权限测试，重放结果将在请求管理标签页中显示");
            });
        }
    }

    /**
     * 添加自动化测试的权限测试记录到请求管理Tab
     * 供 AutoTestEngine 调用
     */
    public static void addPrivilegeTestRecord(RequestResponseRecord record) {
        if (repeaterUI != null) {
            SwingUtilities.invokeLater(() -> {
                repeaterUI.addPrivilegeTestHistoryRecord(record);
            });
        }
    }

    /**
     * 将自动化测试的原始请求添加到请求列表面板
     * 供 AutoTestEngine 调用
     */
    public static void addAutoTestRequestToPanel(int requestId, String api, String method,
            String protocol, String domain, String path, String query, byte[] requestData) {
        if (repeaterUI != null) {
            SwingUtilities.invokeLater(() -> {
                repeaterUI.addAutoTestRequest(requestId, api, method, protocol, domain, path, query, requestData);
            });
        }
    }

    /**
     * 获取日志管理器实例
     */
    public static LogManager getLogManager() {
        return logManager;
    }
}
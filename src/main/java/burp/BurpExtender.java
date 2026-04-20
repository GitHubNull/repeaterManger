package burp;

import oxff.top.EnhancedRepeaterUI;
import oxff.top.controller.PopMenu;
import oxff.top.logging.LogLevel;
import oxff.top.logging.LogManager;

import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import javax.swing.SwingUtilities;

/**
 * Burp扩展入口点 - 负责注册插件并初始化所需组件
 */
public class BurpExtender implements IBurpExtender {

    // 公共变量，供插件其他部分使用
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;

    // 日志输出流（保留用于兼容，实际日志通过LogManager）
    @SuppressWarnings("unused")
    private static PrintWriter stdout;
    private static PrintWriter stderr;

    // 主UI组件
    private static EnhancedRepeaterUI repeaterUI;

    // 日志管理器
    private static final LogManager logManager = LogManager.getInstance();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // 保存回调对象
        BurpExtender.callbacks = callbacks;
        BurpExtender.helpers = callbacks.getHelpers();

        // 设置插件名称
        callbacks.setExtensionName("增强型Repeater");

        try {
            // 初始化带有正确编码的输出流（保留用于LogManager之前的输出）
            initializeOutputStreams(callbacks);

            // 初始化日志管理器（在数据库初始化之前）
            logManager.initialize(callbacks);

            // 从配置加载日志和代理设置
            loadLogConfig();

            // 测试数据库连接和持久化
            logManager.info("[*] 正在测试数据库连接和持久化...");
            oxff.top.db.DatabaseManager dbManager = oxff.top.db.DatabaseManager.getInstance();

            // 确保数据库初始化
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

            // 创建UI和功能组件
            repeaterUI = new EnhancedRepeaterUI();

            // 将UI组件添加到Burp的UI
            callbacks.addSuiteTab(repeaterUI);

            // 注册上下文菜单工厂
            callbacks.registerContextMenuFactory(new PopMenu());

            // 注册扩展卸载监听器
            callbacks.registerExtensionStateListener(() -> {
                logManager.info("[*] 插件正在卸载，关闭日志系统...");
                logManager.shutdown();
            });

            // 使用编码后的输出流打印信息
            logManager.success("[+] 增强型Repeater 插件加载成功");
        } catch (Exception e) {
            // 使用编码后的错误流输出异常
            if (stderr != null) {
                stderr.println("[!] 插件加载失败: " + e.getMessage());
                e.printStackTrace(stderr);
            } else {
                callbacks.printError("[!] 插件加载失败: " + e.getMessage());
                e.printStackTrace(new PrintWriter(callbacks.getStderr()));
            }
        }
    }

    /**
     * 从配置文件加载日志和代理设置
     */
    private void loadLogConfig() {
        try {
            oxff.top.config.DatabaseConfig config =
                oxff.top.db.DatabaseManager.getInstance().getConfig();

            // 日志级别
            String levelStr = config.getProperty("log.level", "INFO");
            logManager.setLevel(LogLevel.fromName(levelStr));

            // 文件日志
            boolean fileEnabled = Boolean.parseBoolean(config.getProperty("log.file.enabled", "true"));
            logManager.setFileLoggingEnabled(fileEnabled);

            if (fileEnabled) {
                String logDir = config.getProperty("log.file.directory", "");
                if (logDir == null || logDir.isEmpty()) {
                    logDir = System.getProperty("user.dir") + "/repeater_manager/logs";
                }
                long maxSize = Long.parseLong(config.getProperty("log.file.max_size", "5242880"));
                int maxBackups = Integer.parseInt(config.getProperty("log.file.max_backups", "5"));
                logManager.initializeFileHandler(logDir, maxSize, maxBackups);
            }

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
            System.err.println("加载日志配置失败: " + e.getMessage());
        }
    }

    /**
     * 初始化带有正确字符编码的输出流
     */
    private void initializeOutputStreams(IBurpExtenderCallbacks callbacks) {
        try {
            OutputStreamWriter outWriter = new OutputStreamWriter(callbacks.getStdout(), "UTF-8");
            OutputStreamWriter errWriter = new OutputStreamWriter(callbacks.getStderr(), "UTF-8");

            stdout = new PrintWriter(outWriter, true);
            stderr = new PrintWriter(errWriter, true);
        } catch (UnsupportedEncodingException e) {
            callbacks.printError("初始化自定义输出流失败: " + e.getMessage());

            stdout = new PrintWriter(callbacks.getStdout(), true);
            stderr = new PrintWriter(callbacks.getStderr(), true);
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

    public static void setRepeaterUIRequest(IHttpRequestResponse requestResponse) {
        if (repeaterUI != null) {
            SwingUtilities.invokeLater(() -> {
                repeaterUI.setRequest(requestResponse);
                logManager.success("[+] 已将请求发送到增强型Repeater，请切换到相应标签页查看");
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
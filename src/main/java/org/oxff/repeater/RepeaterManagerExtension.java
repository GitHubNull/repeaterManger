package org.oxff.repeater;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import org.oxff.repeater.api.MontoyaApiHolder;
import org.oxff.repeater.controller.PopMenu;
import org.oxff.repeater.logging.LogLevel;
import org.oxff.repeater.logging.LogManager;

/**
 * Repeater Manager 插件主入口类 — 负责插件生命周期管理。
 * <p>
 * 将原本臃肿的 {@code burp.BurpExtender} 中的生命周期逻辑提取到此处，
 * 使 {@code burp.BurpExtender} 仅作为 Burp Suite 类加载机制发现的空壳入口。
 */
public class RepeaterManagerExtension implements BurpExtension {

    private final LogManager logManager = LogManager.getInstance();

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
            org.oxff.repeater.db.DatabaseManager dbManager = org.oxff.repeater.db.DatabaseManager.getInstance();

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
                org.oxff.repeater.api.GlobalRuleManager.getInstance().loadRules();
                logManager.success("[+] 全局API提取规则加载完成");
            } catch (Exception e) {
                logManager.error("[!] 全局API提取规则加载失败: " + e.getMessage());
            }

            // 阶段4.6：加载全局字段定义
            try {
                org.oxff.repeater.privilege.GlobalFieldDefinitionManager.getInstance().loadFields();
                org.oxff.repeater.privilege.SessionManager.getInstance().loadGlobalFieldDefinitions();
                logManager.success("[+] 全局字段定义加载完成");
            } catch (Exception e) {
                logManager.error("[!] 全局字段定义加载失败: " + e.getMessage());
            }

            // 阶段4.6.1：加载全局方案
            try {
                org.oxff.repeater.privilege.SessionManager.getInstance().loadGlobalSchemes();
                logManager.success("[+] 全局方案加载完成");
            } catch (Exception e) {
                logManager.error("[!] 全局方案加载失败: " + e.getMessage());
            }

            // 阶段4.7：加载全局去重配置
            try {
                org.oxff.repeater.privilege.DedupConfigManager.getInstance().loadGlobalConfigs();
                logManager.success("[+] 全局去重配置加载完成");
            } catch (Exception e) {
                logManager.error("[!] 全局去重配置加载失败: " + e.getMessage());
            }

            // 创建UI和功能组件
            RepeaterManagerUI repeaterUI = new RepeaterManagerUI(api);

            // 注入 UI 到请求调度器
            UIRequestDispatcher.getInstance().setRepeaterUI(repeaterUI);

            // 将UI组件注册到Burp的选项卡
            api.userInterface().registerSuiteTab("Repeater Manager", repeaterUI.getUiComponent());

            // 注册上下文菜单
            api.userInterface().registerContextMenuItemsProvider(new PopMenu());

            // 注册扩展卸载监听器
            api.extension().registerUnloadingHandler(() -> {
                logManager.info("[*] 插件正在卸载，关闭资源...");

                // 1. 关闭UI层资源（RequestManager线程池、HistoryRecordingService）
                if (repeaterUI != null) {
                    repeaterUI.close();
                }

                // 2. 关闭数据库连接池和GC服务
                try {
                    org.oxff.repeater.db.DatabaseManager.getInstance().closeConnections();
                } catch (Exception e) {
                    logManager.printError("[!] 关闭数据库连接时异常: " + e.getMessage());
                }

                // 3. 关闭日志系统（最后关闭，确保其他组件的关闭日志可被记录）
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
            org.oxff.repeater.config.DatabaseConfig config =
                org.oxff.repeater.db.DatabaseManager.getInstance().getConfig();

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
            org.oxff.repeater.http.ProxyConfig proxyConfig = org.oxff.repeater.http.ProxyConfig.getInstance();
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
            org.oxff.repeater.config.DatabaseConfig config =
                org.oxff.repeater.db.DatabaseManager.getInstance().getConfig();

            boolean fileEnabled = config.isLogFileEnabled();
            if (!fileEnabled) {
                return;
            }

            // 确定日志目录：优先使用用户自定义目录，否则使用会话目录的 logs/
            String logDir = config.getLogFileDirectory();
            if (logDir == null || logDir.isEmpty()) {
                // 使用会话目录的 logs/ 子目录
                java.io.File sessionLogsDir = org.oxff.repeater.db.DatabaseManager.getInstance().getLogsDirectory();
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
}

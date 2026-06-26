package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.oxff.repeater.RepeaterManagerUI;
import org.oxff.repeater.api.MontoyaApiHolder;
import org.oxff.repeater.controller.PopMenu;
import org.oxff.repeater.logging.LogLevel;
import org.oxff.repeater.logging.LogManager;

import org.oxff.repeater.http.RequestResponseRecord;
import org.oxff.repeater.privilege.SessionManager;
import org.oxff.repeater.privilege.SessionParseResult;
import org.oxff.repeater.privilege.SessionParserEngine;
import org.oxff.repeater.privilege.SchemeMatch;
import org.oxff.repeater.privilege.model.TokenLocation;
import org.oxff.repeater.ui.privilege.ParseSessionFromClipboardDialog;

import javax.swing.*;
import java.awt.*;
import java.util.List;

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

            // 阶段4.6：加载全局令牌位置
            try {
                org.oxff.repeater.privilege.GlobalTokenLocationManager.getInstance().loadLocations();
                org.oxff.repeater.privilege.SessionManager.getInstance().loadGlobalTokenLocations();
                logManager.success("[+] 全局令牌位置加载完成");
            } catch (Exception e) {
                logManager.error("[!] 全局令牌位置加载失败: " + e.getMessage());
            }

            // 阶段4.6.1：加载全局令牌方案
            try {
                org.oxff.repeater.privilege.SessionManager.getInstance().loadGlobalTokenSchemes();
                logManager.success("[+] 全局令牌方案加载完成");
            } catch (Exception e) {
                logManager.error("[!] 全局令牌方案加载失败: " + e.getMessage());
            }

            // 阶段4.7：加载全局去重配置
            try {
                org.oxff.repeater.privilege.DedupConfigManager.getInstance().loadGlobalConfigs();
                logManager.success("[+] 全局去重配置加载完成");
            } catch (Exception e) {
                logManager.error("[!] 全局去重配置加载失败: " + e.getMessage());
            }

            // 创建UI和功能组件
            repeaterUI = new RepeaterManagerUI(api);

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
     * 批量将请求发送到 Repeater Manager
     * 供 PopMenu 右键菜单多选时调用
     */
    public static void setRepeaterUIRequests(List<HttpRequestResponse> requestResponses) {
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
     * 供 PopMenu 右键菜单多选时调用
     */
    public static void setPrivilegeTestRequests(List<HttpRequestResponse> requestResponses) {
        if (repeaterUI != null && requestResponses != null && !requestResponses.isEmpty()) {
            SwingUtilities.invokeLater(() -> {
                repeaterUI.setPrivilegeTestRequests(requestResponses);
                logManager.success(String.format("[+] 已将 %d 条请求发送到权限测试，重放结果将在请求管理标签页中显示",
                    requestResponses.size()));
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

    /**
     * 从HTTP请求解析用户会话
     * 供PopMenu右键菜单调用
     *
     * @param request Burp HTTP请求对象
     */
    public static void parseSessionFromRequest(HttpRequest request) {
        if (request == null || repeaterUI == null) {
            return;
        }

        SwingUtilities.invokeLater(() -> {
            try {
                // 获取请求字节数组
                byte[] httpMessage = request.toByteArray().getBytes();

                // 获取令牌位置和方案
                SessionManager sm = SessionManager.getInstance();
                List<TokenLocation> locations = sm.getTokenLocations();
                List<org.oxff.repeater.privilege.model.TokenScheme> schemes = sm.getTokenSchemes();

                if (locations.isEmpty()) {
                    JOptionPane.showMessageDialog(repeaterUI.getUiComponent(),
                            "未配置任何令牌位置，请先配置令牌位置",
                            "提示", JOptionPane.INFORMATION_MESSAGE);
                    return;
                }

                // 解析报文
                SessionParseResult parseResult = SessionParserEngine.parse(httpMessage, locations);
                List<SchemeMatch> schemeMatches = SessionParserEngine.matchSchemes(parseResult, schemes);

                // 生成建议名称
                String suggestedName = generateSuggestedName(parseResult, request);

                // 显示确认对话框
                Frame owner = (Frame) SwingUtilities.getWindowAncestor(repeaterUI.getUiComponent());
                ParseSessionFromClipboardDialog dialog = new ParseSessionFromClipboardDialog(
                        owner, parseResult, schemeMatches, locations, suggestedName);
                dialog.setVisible(true);

                if (dialog.isConfirmed()) {
                    String sessionName = dialog.getSessionName();
                    String colorHex = dialog.getColorHex();
                    boolean enabled = dialog.isEnabled();
                    Integer schemeId = dialog.getSelectedSchemeId();

                    int sessionId;
                    if (dialog.isUpdateExisting() && dialog.getExistingSessionId() != null) {
                        sessionId = dialog.getExistingSessionId();
                        sm.updateUserSession(sessionId, sessionName, colorHex, enabled, schemeId);
                        logManager.success("[+] 已更新用户会话: " + sessionName);
                    } else {
                        sessionId = sm.addUserSession(sessionName, colorHex, enabled, schemeId);
                        if (sessionId > 0) {
                            logManager.success("[+] 已创建用户会话: " + sessionName + " (ID=" + sessionId + ")");
                        }
                    }

                    if (sessionId > 0) {
                        java.util.Map<Integer, String> extractedValues = parseResult.getAllExtractedValues();
                        if (!extractedValues.isEmpty()) {
                            sm.saveTokenValues(sessionId, extractedValues);
                            logManager.success("[+] 已保存 " + extractedValues.size() + " 个令牌值");
                        }
                        refreshPrivilegeTestData();
                    }
                }
            } catch (Exception e) {
                logManager.error("[!] 解析用户会话时发生错误: " + e.getMessage());
                JOptionPane.showMessageDialog(repeaterUI.getUiComponent(),
                        "解析过程中发生错误: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
    }

    /**
     * 生成建议的会话名称（从请求）
     */
    private static String generateSuggestedName(SessionParseResult parseResult, HttpRequest request) {
        // 1. 尝试从Authorization header提取JWT中的sub/username
        String authHeader = parseResult.getExtractedValueByHeaderName("Authorization");
        if (authHeader != null && authHeader.toLowerCase().startsWith("bearer ")) {
            String jwt = authHeader.substring(7).trim();
            String username = extractJwtSubject(jwt);
            if (username != null && !username.isEmpty()) {
                return username;
            }
        }

        // 2. 从Host header推断
        String host = request.httpService() != null ? request.httpService().host() : null;
        if (host != null && !host.isEmpty() && !host.equalsIgnoreCase("localhost")
                && !host.matches("^\\d+\\.\\d+\\.\\d+\\.\\d+$")) {
            String[] hostParts = host.split("\\.");
            if (hostParts.length > 0) {
                return hostParts[0];
            }
        }

        // 3. 默认使用时间戳
        return "Session_" + System.currentTimeMillis();
    }

    /**
     * 从JWT token中提取subject（sub字段）
     */
    private static String extractJwtSubject(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length != 3) {
                return null;
            }
            String payload = parts[1].replace('-', '+').replace('_', '/');
            int padding = 4 - (payload.length() % 4);
            if (padding != 4) {
                payload += "=".repeat(padding);
            }
            byte[] decoded = java.util.Base64.getDecoder().decode(payload);
            String payloadJson = new String(decoded, java.nio.charset.StandardCharsets.UTF_8);

            com.google.gson.JsonObject jsonObj = com.google.gson.JsonParser.parseString(payloadJson).getAsJsonObject();
            String[] userFields = {"sub", "username", "user_name", "name", "email", "user", "id", "uid"};
            for (String field : userFields) {
                if (jsonObj.has(field)) {
                    String value = jsonObj.get(field).getAsString();
                    if (value != null && !value.isEmpty()) {
                        return value;
                    }
                }
            }
        } catch (Exception e) {
            // JWT解析失败，忽略
        }
        return null;
    }

    /**
     * 刷新权限测试数据（用户会话表格等）
     */
    public static void refreshPrivilegeTestData() {
        if (repeaterUI != null) {
            SwingUtilities.invokeLater(() -> repeaterUI.refreshPrivilegeTestData());
        }
    }

    /**
     * 刷新UI数据 - 供外部模块（如ErmArchiveReader）在导入数据后安全调用
     * 避免通过反射访问私有字段
     */
    public static void refreshUIData() {
        if (repeaterUI != null) {
            SwingUtilities.invokeLater(() -> repeaterUI.refreshAllData());
        }
    }
}
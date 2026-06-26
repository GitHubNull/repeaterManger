package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.privilege.FetchRequestParser;
import org.oxff.repeater.privilege.SchemeMatch;
import org.oxff.repeater.privilege.SessionManager;
import org.oxff.repeater.privilege.SessionParseResult;
import org.oxff.repeater.privilege.SessionParserEngine;
import org.oxff.repeater.privilege.model.TokenLocation;
import org.oxff.repeater.privilege.model.TokenScheme;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.util.List;

/**
 * 从剪贴板解析HTTP报文的后台Worker
 * 使用SwingWorker在后台线程执行解析，避免阻塞EDT
 */
public class ParseSessionWorker extends SwingWorker<ParseSessionWorker.Result, String> {

    private final Component parentComponent;
    private final JDialog progressDialog;
    private final JLabel progressLabel;

    public ParseSessionWorker(Component parentComponent) {
        this.parentComponent = parentComponent;

        // 创建进度对话框
        progressDialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(parentComponent), "解析中", true);
        progressDialog.setSize(300, 120);
        progressDialog.setLocationRelativeTo(parentComponent);
        progressDialog.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
        progressDialog.setResizable(false);

        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
        progressLabel = new JLabel("正在读取剪贴板...");
        progressLabel.setHorizontalAlignment(SwingConstants.CENTER);
        panel.add(progressLabel, BorderLayout.CENTER);

        JProgressBar progressBar = new JProgressBar();
        progressBar.setIndeterminate(true);
        panel.add(progressBar, BorderLayout.SOUTH);

        progressDialog.getContentPane().add(panel);
    }

    @Override
    protected Result doInBackground() throws Exception {
        publish("正在读取剪贴板...");

        // 1. 读取系统剪贴板
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        Transferable contents = clipboard.getContents(null);
        if (contents == null || !contents.isDataFlavorSupported(DataFlavor.stringFlavor)) {
            return Result.error("剪贴板中没有文本内容，请先复制HTTP报文");
        }

        String clipboardText = (String) contents.getTransferData(DataFlavor.stringFlavor);
        if (clipboardText == null || clipboardText.trim().isEmpty()) {
            return Result.error("剪贴板内容为空");
        }

        publish("正在解析HTTP报文...");

        // 2. 检测格式并转换
        FetchRequestParser.ClipboardFormat format = FetchRequestParser.detectFormat(clipboardText);
        byte[] httpMessage;
        if (format == FetchRequestParser.ClipboardFormat.FETCH_BROWSER
                || format == FetchRequestParser.ClipboardFormat.FETCH_NODEJS) {
            publish("正在转换 fetch 格式...");
            try {
                httpMessage = FetchRequestParser.convertToRawHttp(clipboardText);
            } catch (IllegalArgumentException e) {
                return Result.error("fetch 格式转换失败: " + e.getMessage());
            }
        } else if (format == FetchRequestParser.ClipboardFormat.RAW_HTTP) {
            httpMessage = clipboardText.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        } else {
            return Result.error("无法识别剪贴板内容格式，请复制原始HTTP报文或Chrome fetch格式");
        }

        // 3. 获取令牌位置和方案
        SessionManager sm = SessionManager.getInstance();
        List<TokenLocation> locations = sm.getTokenLocations();
        List<TokenScheme> schemes = sm.getTokenSchemes();

        if (locations.isEmpty()) {
            return Result.error("未配置任何令牌位置，请先配置令牌位置");
        }

        // 3. 调用解析引擎
        SessionParseResult parseResult = SessionParserEngine.parse(httpMessage, locations);

        publish("正在匹配令牌方案...");

        // 4. 匹配最佳方案
        List<SchemeMatch> schemeMatches = SessionParserEngine.matchSchemes(parseResult, schemes);

        // 5. 生成建议会话名称
        String suggestedName = generateSuggestedName(parseResult, clipboardText);

        return Result.success(parseResult, schemeMatches, locations, suggestedName);
    }

    @Override
    protected void process(List<String> chunks) {
        // 更新进度标签
        if (!chunks.isEmpty()) {
            progressLabel.setText(chunks.get(chunks.size() - 1));
        }
    }

    @Override
    protected void done() {
        // 关闭进度对话框
        progressDialog.dispose();

        try {
            Result result = get();
            if (result.isError()) {
                JOptionPane.showMessageDialog(parentComponent,
                        result.getErrorMessage(), "解析失败", JOptionPane.ERROR_MESSAGE);
                return;
            }

            SessionManager sm = SessionManager.getInstance();
            List<SchemeMatch> schemeMatches = result.getSchemeMatches();
            List<TokenScheme> allSchemes = sm.getTokenSchemes();

            // 检查是否有启用的方案
            boolean hasEnabledScheme = allSchemes.stream().anyMatch(TokenScheme::isEnabled);

            // 如果没有匹配到任何方案，或者没有任何启用的方案，让用户选择
            if (schemeMatches.isEmpty() || !hasEnabledScheme) {
                Frame owner = (Frame) SwingUtilities.getWindowAncestor(parentComponent);
                String message;
                if (!hasEnabledScheme) {
                    message = "<html>没有任何启用的令牌方案。<br>请选择一个方案，选中后将自动启用。</html>";
                } else {
                    message = "<html>没有启用的方案匹配当前报文。<br>请选择一个方案，选中后将自动启用。</html>";
                }

                SelectSchemeDialog selectDialog = new SelectSchemeDialog(owner, allSchemes, message);
                selectDialog.setVisible(true);

                if (!selectDialog.isConfirmed()) {
                    return; // 用户取消
                }

                TokenScheme selectedScheme = selectDialog.getSelectedScheme();
                if (selectedScheme == null) {
                    return;
                }

                // 自动启用用户选择的方案
                if (!selectedScheme.isEnabled()) {
                    selectedScheme.setEnabled(true);
                    sm.updateTokenScheme(selectedScheme.getId(), selectedScheme.getName(),
                            selectedScheme.getDescription(), true, selectedScheme.isPersistToGlobal());
                    LogManager.getInstance().printOutput("[+] 已自动启用令牌方案: " + selectedScheme.getName());
                }

                // 重新解析匹配（使用刚启用的方案）
                byte[] httpMessage = result.getParseResult().getRawHeader() != null
                        ? (result.getParseResult().getRawHeader() + "\r\n\r\n"
                           + (result.getParseResult().getRawBody() != null ? result.getParseResult().getRawBody() : ""))
                           .getBytes(java.nio.charset.StandardCharsets.UTF_8)
                        : new byte[0];
                SessionParseResult newParseResult = SessionParserEngine.parse(httpMessage, result.getAllLocations());
                schemeMatches = SessionParserEngine.matchSchemes(newParseResult, allSchemes);

                // 如果重新匹配后仍然没有匹配，构造一个手动匹配结果
                if (schemeMatches.isEmpty()) {
                    schemeMatches = java.util.Collections.singletonList(
                            new SchemeMatch(selectedScheme, 0, selectedScheme.getTokenLocationCount()));
                }
            }

            // 显示确认对话框
            Frame owner = (Frame) SwingUtilities.getWindowAncestor(parentComponent);
            ParseSessionFromClipboardDialog dialog = new ParseSessionFromClipboardDialog(
                    owner, result.getParseResult(), schemeMatches,
                    result.getAllLocations(), result.getSuggestedName());
            dialog.setVisible(true);

            if (dialog.isConfirmed()) {
                // 用户确认，创建或更新会话
                String sessionName = dialog.getSessionName();
                String colorHex = dialog.getColorHex();
                boolean enabled = dialog.isEnabled();
                Integer schemeId = dialog.getSelectedSchemeId();

                int sessionId;
                if (dialog.isUpdateExisting() && dialog.getExistingSessionId() != null) {
                    // 更新现有会话
                    sessionId = dialog.getExistingSessionId();
                    sm.updateUserSession(sessionId, sessionName, colorHex, enabled, schemeId);
                    LogManager.getInstance().printOutput("[+] 已更新用户会话: " + sessionName);
                } else {
                    // 创建新会话
                    sessionId = sm.addUserSession(sessionName, colorHex, enabled, schemeId);
                    if (sessionId > 0) {
                        LogManager.getInstance().printOutput("[+] 已创建用户会话: " + sessionName + " (ID=" + sessionId + ")");
                    }
                }

                if (sessionId > 0) {
                    // 保存令牌值
                    java.util.Map<Integer, String> extractedValues = result.getParseResult().getAllExtractedValues();
                    if (!extractedValues.isEmpty()) {
                        sm.saveTokenValues(sessionId, extractedValues);
                        LogManager.getInstance().printOutput("[+] 已保存 " + extractedValues.size() + " 个令牌值");
                    }

                    // 刷新UI
                    refreshUserSessionTab();
                }
            }
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] 解析用户会话时发生错误: " + e.getMessage());
            JOptionPane.showMessageDialog(parentComponent,
                    "解析过程中发生错误: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * 显示进度对话框并开始执行
     */
    public void start() {
        // 在后台显示进度对话框（避免阻塞）
        SwingUtilities.invokeLater(() -> {
            progressDialog.setVisible(true);
        });
        execute();
    }

    /**
     * 生成建议的会话名称
     * 优先从JWT payload提取sub/username，其次从Host header推断，最后使用时间戳
     */
    private String generateSuggestedName(SessionParseResult parseResult, String rawText) {
        // 1. 尝试从Authorization header提取JWT中的sub/username
        String authHeader = parseResult.getExtractedValueByHeaderName("Authorization");
        if (authHeader != null && authHeader.toLowerCase().startsWith("bearer ")) {
            String jwt = authHeader.substring(7).trim();
            String username = extractJwtSubject(jwt);
            if (username != null && !username.isEmpty()) {
                return username;
            }
        }

        // 2. 尝试从Cookie提取session/user信息
        String cookieHeader = parseResult.getExtractedValueByHeaderName("Cookie");
        if (cookieHeader != null) {
            // 简单提取可能的用户名
            String[] parts = cookieHeader.split("[;=&]");
            for (String part : parts) {
                String trimmed = part.trim();
                if (trimmed.toLowerCase().startsWith("username=") ||
                    trimmed.toLowerCase().startsWith("user=") ||
                    trimmed.toLowerCase().startsWith("login=")) {
                    int eqIdx = trimmed.indexOf('=');
                    if (eqIdx > 0) {
                        String value = trimmed.substring(eqIdx + 1).trim();
                        if (!value.isEmpty()) {
                            return value;
                        }
                    }
                }
            }
        }

        // 3. 从Host header推断
        String hostHeader = parseResult.getExtractedValueByHeaderName("Host");
        if (hostHeader != null && !hostHeader.isEmpty()) {
            String host = hostHeader.split(":")[0].trim();
            if (!host.isEmpty() && !host.equalsIgnoreCase("localhost") && !host.matches("^\\d+\\.\\d+\\.\\d+\\.\\d+$")) {
                // 取域名第一部分作为名称
                String[] hostParts = host.split("\\.");
                if (hostParts.length > 0) {
                    return hostParts[0];
                }
            }
        }

        // 4. 默认使用时间戳
        return "Session_" + System.currentTimeMillis();
    }

    /**
     * 从JWT token中提取subject（sub字段）
     */
    private String extractJwtSubject(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length != 3) {
                return null;
            }
            // Base64解码payload部分
            String payload = parts[1];
            // 处理Base64Url编码（替换字符）
            payload = payload.replace('-', '+').replace('_', '/');
            // 补齐padding
            int padding = 4 - (payload.length() % 4);
            if (padding != 4) {
                payload += "=".repeat(padding);
            }
            byte[] decoded = java.util.Base64.getDecoder().decode(payload);
            String payloadJson = new String(decoded, java.nio.charset.StandardCharsets.UTF_8);

            com.google.gson.JsonObject jsonObj = com.google.gson.JsonParser.parseString(payloadJson).getAsJsonObject();
            // 尝试常见的用户标识字段
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
     * 刷新用户会话标签页的表格数据
     */
    private void refreshUserSessionTab() {
        // 通过UIRequestDispatcher的桥接方法刷新UI
        org.oxff.repeater.UIRequestDispatcher.getInstance().refreshPrivilegeTestData();
    }

    // ==================== Result 内部类 ====================

    public static class Result {
        private final boolean error;
        private final String errorMessage;
        private final SessionParseResult parseResult;
        private final List<SchemeMatch> schemeMatches;
        private final List<TokenLocation> allLocations;
        private final String suggestedName;

        private Result(boolean error, String errorMessage, SessionParseResult parseResult,
                       List<SchemeMatch> schemeMatches, List<TokenLocation> allLocations,
                       String suggestedName) {
            this.error = error;
            this.errorMessage = errorMessage;
            this.parseResult = parseResult;
            this.schemeMatches = schemeMatches;
            this.allLocations = allLocations;
            this.suggestedName = suggestedName;
        }

        public static Result error(String message) {
            return new Result(true, message, null, null, null, null);
        }

        public static Result success(SessionParseResult parseResult, List<SchemeMatch> schemeMatches,
                                      List<TokenLocation> allLocations, String suggestedName) {
            return new Result(false, null, parseResult, schemeMatches, allLocations, suggestedName);
        }

        public boolean isError() {
            return error;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public SessionParseResult getParseResult() {
            return parseResult;
        }

        public List<SchemeMatch> getSchemeMatches() {
            return schemeMatches;
        }

        public List<TokenLocation> getAllLocations() {
            return allLocations;
        }

        public String getSuggestedName() {
            return suggestedName;
        }
    }
}

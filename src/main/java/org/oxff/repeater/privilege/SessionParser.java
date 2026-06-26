package org.oxff.repeater.privilege;

import burp.api.montoya.http.message.requests.HttpRequest;
import org.oxff.repeater.RepeaterManagerUI;
import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.privilege.model.TokenLocation;
import org.oxff.repeater.privilege.model.TokenScheme;
import org.oxff.repeater.ui.privilege.ParseSessionFromClipboardDialog;
import org.oxff.repeater.ui.privilege.SelectSchemeDialog;

import javax.swing.*;
import java.awt.*;
import java.util.List;

/**
 * 会话解析器 — 负责从 HTTP 请求中解析用户会话信息。
 * <p>
 * 将原本分散在 BurpExtender 中的会话解析逻辑集中管理。
 */
public class SessionParser {

    private static SessionParser instance;

    private final LogManager logManager = LogManager.getInstance();

    private SessionParser() {
    }

    public static synchronized SessionParser getInstance() {
        if (instance == null) {
            instance = new SessionParser();
        }
        return instance;
    }

    /**
     * 从HTTP请求解析用户会话
     *
     * @param request    Burp HTTP请求对象
     * @param repeaterUI 主UI实例（用于对话框父窗口和UI刷新）
     */
    public void parseSessionFromRequest(HttpRequest request, RepeaterManagerUI repeaterUI) {
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
                List<TokenScheme> schemes = sm.getTokenSchemes();

                if (locations.isEmpty()) {
                    JOptionPane.showMessageDialog(repeaterUI.getUiComponent(),
                            "未配置任何令牌位置，请先配置令牌位置",
                            "提示", JOptionPane.INFORMATION_MESSAGE);
                    return;
                }

                // 解析报文
                SessionParseResult parseResult = SessionParserEngine.parse(httpMessage, locations);
                List<SchemeMatch> schemeMatches = SessionParserEngine.matchSchemes(parseResult, schemes);

                // 检查是否有启用的方案
                boolean hasEnabledScheme = schemes.stream().anyMatch(TokenScheme::isEnabled);

                // 如果没有匹配到任何方案，或者没有任何启用的方案，让用户选择
                if (schemeMatches.isEmpty() || !hasEnabledScheme) {
                    Frame owner = (Frame) SwingUtilities.getWindowAncestor(repeaterUI.getUiComponent());
                    String message;
                    if (!hasEnabledScheme) {
                        message = "<html>没有任何启用的令牌方案。<br>请选择一个方案，选中后将自动启用。</html>";
                    } else {
                        message = "<html>没有启用的方案匹配当前报文。<br>请选择一个方案，选中后将自动启用。</html>";
                    }

                    SelectSchemeDialog selectDialog = new SelectSchemeDialog(owner, schemes, message);
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
                        logManager.success("[+] 已自动启用令牌方案: " + selectedScheme.getName());
                    }

                    // 重新解析匹配（使用刚启用的方案）
                    SessionParseResult newParseResult = SessionParserEngine.parse(httpMessage, locations);
                    schemeMatches = SessionParserEngine.matchSchemes(newParseResult, schemes);

                    // 如果重新匹配后仍然没有匹配，构造一个手动匹配结果
                    if (schemeMatches.isEmpty()) {
                        schemeMatches = java.util.Collections.singletonList(
                                new SchemeMatch(selectedScheme, 0, selectedScheme.getTokenLocationCount()));
                    }
                }

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
                        org.oxff.repeater.UIRequestDispatcher.getInstance().refreshPrivilegeTestData();
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
    public String generateSuggestedName(SessionParseResult parseResult, HttpRequest request) {
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
    public String extractJwtSubject(String jwt) {
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
}

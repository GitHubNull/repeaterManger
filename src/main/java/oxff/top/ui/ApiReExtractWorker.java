package oxff.top.ui;

import burp.BurpExtender;
import oxff.top.api.ApiExtractionEngine;
import oxff.top.api.ApiExtractionRule;
import oxff.top.api.ApiRuleManager;
import oxff.top.db.DatabaseManager;
import oxff.top.db.RequestDAO;
import oxff.top.db.history.HistoryReadDAO;
import oxff.top.db.pool.ContentSplitter;
import oxff.top.db.pool.PoolManager;
import oxff.top.db.pool.SplitResult;
import oxff.top.http.RequestResponseRecord;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * API重新提取工作器 - 在后台线程中重新提取所有请求和历史记录的API值
 */
public class ApiReExtractWorker {

    /**
     * 静默自动重新提取所有API值（规则变更时自动触发）
     *
     * @param onComplete 完成回调（在EDT中执行）
     */
    public static void reExtractSilently(final Runnable onComplete) {
        Thread worker = new Thread(() -> {
            try {
                BurpExtender.printOutput("[*] 规则变更，自动重新提取所有API值...");
                List<ApiExtractionRule> rules = ApiRuleManager.getInstance().getActiveRules();
                PoolManager poolMgr = new PoolManager();
                ContentSplitter splitter = new ContentSplitter();

                int reqUpdated = reExtractRequests(rules, poolMgr, splitter);
                int histUpdated = reExtractHistory(rules, poolMgr, splitter);

                BurpExtender.printOutput("[+] 自动重新提取API完成：请求 " + reqUpdated + " 条，历史 " + histUpdated + " 条");
                SwingUtilities.invokeLater(() -> {
                    if (onComplete != null) {
                        onComplete.run();
                    }
                });
            } catch (Exception e) {
                BurpExtender.printError("[!] 自动重新提取API异常: " + e.getMessage());
            }
        }, "api-reextract-auto");
        worker.setDaemon(true);
        worker.start();
    }

    /**
     * 带进度对话框的重新提取所有API值（用户手动触发）
     *
     * @param parent     父组件（用于对话框定位）
     * @param onComplete 完成回调（在EDT中执行）
     */
    public static void reExtractWithProgress(Component parent, final Runnable onComplete) {
        int confirm = JOptionPane.showConfirmDialog(parent,
                "确定要使用当前规则重新提取所有请求和历史记录的API值吗？\n" +
                "此操作可能需要一定时间。",
                "确认重新提取", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm != JOptionPane.YES_OPTION) return;

        final Frame parentFrame = (Frame) SwingUtilities.getWindowAncestor(parent);
        final JDialog progressDialog = new JDialog(parentFrame, "重新提取API", true);
        progressDialog.setLayout(new BorderLayout(10, 10));
        progressDialog.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);

        JProgressBar progressBar = new JProgressBar();
        progressBar.setIndeterminate(true);
        JLabel statusLabel = new JLabel("正在重新提取所有API值...");

        progressDialog.add(statusLabel, BorderLayout.NORTH);
        progressDialog.add(progressBar, BorderLayout.CENTER);
        progressDialog.setSize(350, 120);
        progressDialog.setLocationRelativeTo(parent);

        Thread worker = new Thread(() -> {
            try {
                List<ApiExtractionRule> rules = ApiRuleManager.getInstance().getActiveRules();
                PoolManager poolMgr = new PoolManager();
                ContentSplitter splitter = new ContentSplitter();

                RequestDAO requestDAO = new RequestDAO();
                List<Map<String, Object>> allRequests = requestDAO.getAllRequests();
                int reqUpdated = reExtractRequests(rules, poolMgr, splitter);

                HistoryReadDAO historyReadDAO = new HistoryReadDAO();
                List<RequestResponseRecord> allHistory = historyReadDAO.getAllHistory();
                int histUpdated = reExtractHistory(rules, poolMgr, splitter);

                final int finalReqUpdated = reqUpdated;
                final int finalReqTotal = allRequests.size();
                final int finalHistUpdated = histUpdated;
                final int finalHistTotal = allHistory.size();
                final int finalTotalUpdated = reqUpdated + histUpdated;
                SwingUtilities.invokeLater(() -> {
                    progressDialog.dispose();
                    JOptionPane.showMessageDialog(parent,
                            "API重新提取完成\n" +
                            "请求: " + finalReqTotal + " 条, 更新 " + finalReqUpdated + " 条\n" +
                            "历史: " + finalHistTotal + " 条, 更新 " + finalHistUpdated + " 条\n" +
                            "合计更新: " + finalTotalUpdated + " 条",
                            "完成", JOptionPane.INFORMATION_MESSAGE);
                    if (onComplete != null) {
                        onComplete.run();
                    }
                });
            } catch (Exception e) {
                BurpExtender.printError("[!] 重新提取API异常: " + e.getMessage());
                SwingUtilities.invokeLater(() -> {
                    progressDialog.dispose();
                    JOptionPane.showMessageDialog(parent,
                            "重新提取API时发生错误: " + e.getMessage(),
                            "错误", JOptionPane.ERROR_MESSAGE);
                });
            }
        });
        worker.start();

        progressDialog.setVisible(true);
    }

    /**
     * 重新提取 requests 表的API值
     */
    private static int reExtractRequests(List<ApiExtractionRule> rules, PoolManager poolMgr, ContentSplitter splitter) {
        RequestDAO requestDAO = new RequestDAO();
        List<Map<String, Object>> allRequests = requestDAO.getAllRequests();
        int updated = 0;

        for (Map<String, Object> req : allRequests) {
            try {
                String path = (String) req.get("path");
                String query = (String) req.get("query");
                byte[] requestData = (byte[]) req.get("request_data");
                int reqId = (Integer) req.get("id");

                List<String> headerList = new ArrayList<>();
                String contentType = null;
                byte[] body = null;

                if (requestData != null && requestData.length > 0) {
                    SplitResult split = splitter.splitRequest(requestData);
                    if (split.getHeaders() != null) {
                        String headersStr = new String(split.getHeaders(), StandardCharsets.UTF_8);
                        for (String line : headersStr.split("\r\n")) {
                            if (!line.isEmpty()) headerList.add(line);
                            if (line.toLowerCase().startsWith("content-type:")) {
                                contentType = line.substring("content-type:".length()).trim();
                            }
                        }
                    }
                    body = split.hasBody() ? split.getBody() : null;
                }

                String apiValue = ApiExtractionEngine.extractApi(path, query, headerList, body, contentType, rules);

                try (Connection conn = DatabaseManager.getInstance().getConnection()) {
                    conn.setAutoCommit(false);
                    try {
                        String oldApiHash = null;
                        try (PreparedStatement pstmt = conn.prepareStatement(
                                "SELECT api_hash FROM requests WHERE id = ?")) {
                            pstmt.setInt(1, reqId);
                            try (ResultSet rs = pstmt.executeQuery()) {
                                if (rs.next()) oldApiHash = rs.getString("api_hash");
                            }
                        }
                        String newApiHash = (apiValue != null && !apiValue.isEmpty())
                                ? poolMgr.ensureString(conn, apiValue) : null;
                        try (PreparedStatement pstmt = conn.prepareStatement(
                                "UPDATE requests SET api_hash = ? WHERE id = ?")) {
                            pstmt.setString(1, newApiHash);
                            pstmt.setInt(2, reqId);
                            pstmt.executeUpdate();
                        }
                        if (oldApiHash != null) poolMgr.releaseString(conn, oldApiHash);
                        conn.commit();
                        updated++;
                    } catch (SQLException ex) {
                        conn.rollback();
                        BurpExtender.printError("[!] 重提取API失败(reqId=" + reqId + "): " + ex.getMessage());
                    }
                }
            } catch (Exception e) {
                BurpExtender.printError("[!] 重提取请求API出错: " + e.getMessage());
            }
        }
        return updated;
    }

    /**
     * 重新提取 history 表的API值
     */
    private static int reExtractHistory(List<ApiExtractionRule> rules, PoolManager poolMgr, ContentSplitter splitter) {
        HistoryReadDAO historyReadDAO = new HistoryReadDAO();
        List<RequestResponseRecord> allHistory = historyReadDAO.getAllHistory();
        int updated = 0;

        for (RequestResponseRecord record : allHistory) {
            try {
                String path = record.getPath();
                byte[] requestData = record.getRequestData();
                int histId = record.getId();

                List<String> headerList = new ArrayList<>();
                String contentType = null;
                byte[] body = null;

                if (requestData != null && requestData.length > 0) {
                    SplitResult split = splitter.splitRequest(requestData);
                    if (split.getHeaders() != null) {
                        String headersStr = new String(split.getHeaders(), StandardCharsets.UTF_8);
                        for (String line : headersStr.split("\r\n")) {
                            if (!line.isEmpty()) headerList.add(line);
                            if (line.toLowerCase().startsWith("content-type:")) {
                                contentType = line.substring("content-type:".length()).trim();
                            }
                        }
                    }
                    body = split.hasBody() ? split.getBody() : null;
                }

                String apiValue = ApiExtractionEngine.extractApi(path, record.getQueryParameters(), headerList, body, contentType, rules);

                try (Connection conn = DatabaseManager.getInstance().getConnection()) {
                    conn.setAutoCommit(false);
                    try {
                        String oldApiHash = null;
                        try (PreparedStatement pstmt = conn.prepareStatement(
                                "SELECT api_hash FROM history WHERE id = ?")) {
                            pstmt.setInt(1, histId);
                            try (ResultSet rs = pstmt.executeQuery()) {
                                if (rs.next()) oldApiHash = rs.getString("api_hash");
                            }
                        }
                        String newApiHash = (apiValue != null && !apiValue.isEmpty())
                                ? poolMgr.ensureString(conn, apiValue) : null;
                        try (PreparedStatement pstmt = conn.prepareStatement(
                                "UPDATE history SET api_hash = ? WHERE id = ?")) {
                            pstmt.setString(1, newApiHash);
                            pstmt.setInt(2, histId);
                            pstmt.executeUpdate();
                        }
                        if (oldApiHash != null) poolMgr.releaseString(conn, oldApiHash);
                        conn.commit();
                        updated++;
                    } catch (SQLException ex) {
                        conn.rollback();
                        BurpExtender.printError("[!] 重提取历史API失败(histId=" + histId + "): " + ex.getMessage());
                    }
                }
            } catch (Exception e) {
                BurpExtender.printError("[!] 重提取历史API出错: " + e.getMessage());
            }
        }
        return updated;
    }
}

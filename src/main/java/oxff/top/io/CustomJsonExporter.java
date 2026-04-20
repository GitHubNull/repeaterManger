package oxff.top.io;

import burp.BurpExtender;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import oxff.top.db.DatabaseManager;
import oxff.top.db.HistoryDAO;
import oxff.top.db.RequestDAO;
import oxff.top.http.RequestResponseRecord;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Component;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Map;

/**
 * 自定义JSON格式导出器
 */
public class CustomJsonExporter {
    private final DatabaseManager dbManager;
    private final RequestDAO requestDAO;
    private final HistoryDAO historyDAO;

    public CustomJsonExporter() {
        this.dbManager = DatabaseManager.getInstance();
        this.requestDAO = new RequestDAO();
        this.historyDAO = new HistoryDAO();
    }

    /**
     * 导出数据到自定义JSON格式
     */
    public boolean export(Component parent) {
        try {
            BurpExtender.printOutput("[+] 开始JSON导出过程");

            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("导出JSON数据");
            FileNameExtensionFilter filter = new FileNameExtensionFilter("JSON Files (*.json)", "json");
            fileChooser.setFileFilter(filter);
            fileChooser.setSelectedFile(new File("replayer_export.json"));

            int result = fileChooser.showSaveDialog(parent);
            if (result != JFileChooser.APPROVE_OPTION) {
                return false;
            }

            File outputFile = fileChooser.getSelectedFile();
            if (!outputFile.getName().toLowerCase().endsWith(".json")) {
                outputFile = new File(outputFile.getAbsolutePath() + ".json");
            }

            if (outputFile.exists()) {
                int overwrite = JOptionPane.showConfirmDialog(
                    parent, "文件已存在，是否覆盖？", "确认覆盖", JOptionPane.YES_NO_OPTION);
                if (overwrite != JOptionPane.YES_OPTION) {
                    return false;
                }
            }

            exportDataToJson(outputFile, parent);
            return true;

        } catch (Exception e) {
            BurpExtender.printError("[!] 导出JSON失败: " + e.getMessage());
            JOptionPane.showMessageDialog(parent,
                "导出失败: " + e.getMessage(), "导出错误", JOptionPane.ERROR_MESSAGE);
            return false;
        }
    }

    private void exportDataToJson(File outputFile, Component parent) throws IOException {
        // 确保数据库已初始化
        String currentDbPath = dbManager.getCurrentDatabasePath();
        if (currentDbPath == null) {
            currentDbPath = dbManager.getConfig().getDatabasePath();
        }
        File sourceDb = new File(currentDbPath);
        if (!sourceDb.exists()) {
            if (!dbManager.initialize()) {
                BurpExtender.printOutput("[!] 警告：数据库初始化失败，将尝试继续导出可能为空的数据");
            }
            try (Connection conn = dbManager.getConnection();
                 Statement stmt = conn.createStatement()) {
                stmt.executeQuery("SELECT 1");
            } catch (SQLException e) {
                BurpExtender.printError("[!] 连接数据库失败: " + e.getMessage());
            }
        }

        dbManager.checkDatabaseStatus();

        List<Map<String, Object>> requests = requestDAO.getAllRequests();
        List<RequestResponseRecord> history = historyDAO.getAllHistory();

        BurpExtender.printOutput("[*] 从数据库获取到 " + requests.size() + " 条请求记录和 " +
                              history.size() + " 条历史记录");

        if (requests.isEmpty() && history.isEmpty()) {
            BurpExtender.printOutput("[!] 警告：数据库中没有找到任何数据");
            JOptionPane.showMessageDialog(parent,
                "警告：数据库中没有找到任何数据记录！\n导出的JSON文件将不包含有效数据。",
                "无数据警告", JOptionPane.WARNING_MESSAGE);
        }

        java.util.Map<String, Object> exportData = new java.util.HashMap<>();
        exportData.put("exportTime", new java.util.Date().toString());
        exportData.put("format", "enhanced-repeater-v1");
        exportData.put("requests", requests);
        exportData.put("history", history);

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(exportData);

        try (FileWriter writer = new FileWriter(outputFile)) {
            writer.write(json);
        }

        BurpExtender.printOutput("[+] JSON数据导出成功: " + outputFile.getAbsolutePath() +
                              "，包含 " + requests.size() + " 条请求和 " + history.size() + " 条历史记录");

        JOptionPane.showMessageDialog(parent,
            "数据导出成功！\n已导出 " + requests.size() + " 条请求和 " + history.size() + " 条历史记录。",
            "导出成功", JOptionPane.INFORMATION_MESSAGE);
    }
}

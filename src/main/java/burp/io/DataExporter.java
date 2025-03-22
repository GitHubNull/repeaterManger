package burp.io;

import burp.BurpExtender;
import burp.db.DatabaseManager;
import burp.db.RequestDAO;
import burp.db.HistoryDAO;
import burp.http.RequestResponseRecord;

import java.io.File;
import java.io.IOException;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Component;
import java.util.concurrent.CompletableFuture;
import java.sql.Connection;
import java.sql.Statement;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/**
 * 数据导出器 - 负责将数据导出到文件
 */
public class DataExporter {
    private final DatabaseManager dbManager;
    private final RequestDAO requestDAO;
    private final HistoryDAO historyDAO;
    
    /**
     * 创建数据导出器
     */
    public DataExporter() {
        this.dbManager = DatabaseManager.getInstance();
        this.requestDAO = new RequestDAO();
        this.historyDAO = new HistoryDAO();
    }
    
    /**
     * 执行导出操作
     */
    public void doExport(String format) {
        try {
            // 首先检查数据库状态
            BurpExtender.printOutput("[*] 准备导出数据，首先检查数据库状态...");
            dbManager.checkDatabaseStatus();
            
            JFileChooser fileChooser = new JFileChooser();
            FileNameExtensionFilter filter;
            
            if (format.equals("json")) {
                filter = new FileNameExtensionFilter("JSON Files", "json");
                fileChooser.setSelectedFile(new File("replayer_export.json"));
            } else { // 默认SQLite格式
                filter = new FileNameExtensionFilter("SQLite Files", "db", "sqlite");
                fileChooser.setSelectedFile(new File("replayer_export.db"));
            }
            
            fileChooser.setFileFilter(filter);
            
            int result = fileChooser.showSaveDialog(null);
            if (result == JFileChooser.APPROVE_OPTION) {
                File outputFile = fileChooser.getSelectedFile();
                
                // 检查文件扩展名
                if (format.equals("json") && !outputFile.getName().toLowerCase().endsWith(".json")) {
                    outputFile = new File(outputFile.getAbsolutePath() + ".json");
                } else if (!format.equals("json") && 
                          !outputFile.getName().toLowerCase().endsWith(".db") && 
                          !outputFile.getName().toLowerCase().endsWith(".sqlite")) {
                    outputFile = new File(outputFile.getAbsolutePath() + ".db");
                }
                
                // 确认覆盖已存在的文件
                if (outputFile.exists()) {
                    int overwrite = JOptionPane.showConfirmDialog(
                        null,
                        "文件已存在，是否覆盖？",
                        "确认覆盖",
                        JOptionPane.YES_NO_OPTION
                    );
                    
                    if (overwrite != JOptionPane.YES_OPTION) {
                        return;
                    }
                }
                
                if (format.equals("json")) {
                    exportDataToJson(outputFile);
                } else {
                    // 检查源数据库文件是否存在
                    String currentDbPath = dbManager.getConfig().getDatabasePath();
                    File sourceDb = new File(currentDbPath);
                    
                    if (!sourceDb.exists()) {
                        BurpExtender.printOutput("[*] 源数据库文件不存在，尝试初始化...");
                        
                        // 尝试初始化数据库
                        if (!dbManager.initialize()) {
                            throw new IOException("无法初始化数据库");
                        }
                        
                        // 再次检查数据库状态
                        dbManager.checkDatabaseStatus();
                        
                        // 如果初始化后文件仍然不存在，尝试通过执行查询来创建
                        if (!sourceDb.exists()) {
                            BurpExtender.printOutput("[*] 初始化后文件仍不存在，尝试创建数据库文件...");
                            try (Connection conn = dbManager.getConnection();
                                 Statement stmt = conn.createStatement()) {
                                // 执行简单查询以确保创建数据库文件
                                stmt.executeQuery("SELECT 1");
                                BurpExtender.printOutput("[+] 已成功创建数据库文件");
                            } catch (SQLException e) {
                                BurpExtender.printError("[!] 创建数据库文件失败: " + e.getMessage());
                                throw new IOException("创建数据库文件失败: " + e.getMessage());
                            }
                        }
                    }
                    
                    // 再次检查源数据库文件
                    if (!sourceDb.exists()) {
                        throw new IOException("源数据库文件不存在");
                    }
                    
                    // 再次检查数据库状态
                    dbManager.checkDatabaseStatus();
                    
                    // 复制数据库文件
                    Files.copy(sourceDb.toPath(), outputFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                    BurpExtender.printOutput("[+] 数据导出成功: " + outputFile.getAbsolutePath());
                    
                    // 提示用户检查导出的数据
                    JOptionPane.showMessageDialog(
                        null,
                        "数据导出已完成，但请注意检查是否包含您期望的数据。\n如果导出文件为空，可能表示数据库中没有存储任何数据。",
                        "导出完成",
                        JOptionPane.INFORMATION_MESSAGE
                    );
                }
            }
        } catch (IOException e) {
            BurpExtender.printError("[!] 导出数据失败: " + e.getMessage());
            JOptionPane.showMessageDialog(
                null,
                "导出数据失败: " + e.getMessage(),
                "导出失败",
                JOptionPane.ERROR_MESSAGE
            );
        }
    }
    
    /**
     * 导出数据到SQLite格式
     */
    public boolean exportToSQLite(Component parent) {
        // 使用doExport方法导出为SQLite格式
        CompletableFuture.runAsync(() -> {
            doExport("sqlite");
        });
        return true;
    }
    
    /**
     * 导出数据到JSON格式
     */
    public boolean exportToJson(Component parent) {
        // 使用doExport方法导出为JSON格式
        CompletableFuture.runAsync(() -> {
            doExport("json");
        });
        return true;
    }
    
    /**
     * 执行JSON导出
     */
    private void exportDataToJson(File outputFile) throws IOException {
        // 检查数据库文件是否存在，如果不存在则尝试初始化
        String currentDbPath = dbManager.getConfig().getDatabasePath();
        File sourceDb = new File(currentDbPath);
        if (!sourceDb.exists()) {
            BurpExtender.printOutput("[*] 数据库文件不存在，尝试初始化...");
            if (!dbManager.initialize()) {
                BurpExtender.printOutput("[!] 警告：数据库初始化失败，将尝试继续导出可能为空的数据");
            }
            
            // 确保连接可用，这可能会触发数据库文件创建
            try (Connection conn = dbManager.getConnection()) {
                BurpExtender.printOutput("[+] 已成功连接到数据库");
            } catch (SQLException e) {
                BurpExtender.printError("[!] 连接数据库失败: " + e.getMessage());
                // 继续尝试导出，虽然可能没有数据
            }
        }
        
        // 再次检查数据库状态
        dbManager.checkDatabaseStatus();
        
        // 获取请求和历史记录数据
        List<Map<String, Object>> requests = requestDAO.getAllRequests();
        List<RequestResponseRecord> history = historyDAO.getAllHistory();
        
        BurpExtender.printOutput("[*] 从数据库获取到 " + requests.size() + " 条请求记录和 " + 
                              history.size() + " 条历史记录");
        
        // 如果没有数据，提示用户
        if (requests.isEmpty() && history.isEmpty()) {
            BurpExtender.printOutput("[!] 警告：数据库中没有找到任何数据，将导出空的JSON文件");
            JOptionPane.showMessageDialog(
                null,
                "警告：数据库中没有找到任何数据记录！\n导出的JSON文件将不包含有效数据。",
                "无数据警告",
                JOptionPane.WARNING_MESSAGE
            );
        }
        
        // 构建导出数据结构
        java.util.Map<String, Object> exportData = new java.util.HashMap<>();
        exportData.put("exportTime", new java.util.Date().toString());
        exportData.put("requests", requests);
        exportData.put("history", history);
        
        // 将数据转换为JSON
        com.google.gson.Gson gson = new com.google.gson.GsonBuilder()
            .setPrettyPrinting()
            .create();
        
        String json = gson.toJson(exportData);
        
        // 写入文件
        try (java.io.FileWriter writer = new java.io.FileWriter(outputFile)) {
            writer.write(json);
        }
        
        BurpExtender.printOutput("[+] 数据导出到JSON成功: " + outputFile.getAbsolutePath() +
                              "，包含 " + requests.size() + " 条请求和 " + history.size() + " 条历史记录");
        
        // 导出结果提示
        if (requests.isEmpty() && history.isEmpty()) {
            JOptionPane.showMessageDialog(
                null,
                "数据导出已完成，但没有找到任何有效数据。\n请先使用插件保存一些请求或响应数据。",
                "导出完成",
                JOptionPane.INFORMATION_MESSAGE
            );
        } else {
            JOptionPane.showMessageDialog(
                null,
                "数据导出成功！\n已导出 " + requests.size() + " 条请求和 " + history.size() + " 条历史记录。",
                "导出成功",
                JOptionPane.INFORMATION_MESSAGE
            );
        }
    }
} 
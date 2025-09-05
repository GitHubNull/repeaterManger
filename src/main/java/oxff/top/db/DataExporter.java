package oxff.top.db;

import burp.BurpExtender;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.*;
import java.nio.file.*;
import java.sql.*;

/**
 * 负责数据导出功能的类
 */
public class DataExporter {
    private DatabaseManager dbManager;

    public DataExporter(DatabaseManager dbManager) {
        this.dbManager = dbManager;
    }

    /**
     * 导出SQLite数据库到用户选择的文件
     */
    public void exportToSQLite(Component parent) {
        BurpExtender.printOutput("[*] 开始SQLite数据库导出");
        
        // 检查数据库内容
        try {
            checkAndLogDatabaseContent();
        } catch (Exception e) {
            BurpExtender.printError("[!] 检查数据库内容时出错: " + e.getMessage());
            e.printStackTrace();
        }
        
        // 创建文件选择器
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("导出SQLite数据库");
        fileChooser.setSelectedFile(new File("replayer_export.db"));
        fileChooser.setFileFilter(new FileNameExtensionFilter("SQLite数据库 (*.db)", "db"));
        
        // 显示保存对话框
        int result = fileChooser.showSaveDialog(parent);
        BurpExtender.printOutput("[*] 文件对话框结果: " + (result == JFileChooser.APPROVE_OPTION ? "已选择文件" : "已取消"));
        
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            String filePath = selectedFile.getAbsolutePath();
            
            // 确保文件有.db扩展名
            if (!filePath.toLowerCase().endsWith(".db")) {
                filePath += ".db";
                selectedFile = new File(filePath);
            }
            
            BurpExtender.printOutput("[*] 选择的导出文件路径: " + filePath);
            
            // 检查文件是否存在
            if (selectedFile.exists()) {
                int overwrite = JOptionPane.showConfirmDialog(
                    parent,
                    "文件已存在，是否覆盖?",
                    "确认覆盖",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE
                );
                
                if (overwrite != JOptionPane.YES_OPTION) {
                    BurpExtender.printOutput("[*] 用户取消了覆盖现有文件");
                    return;
                }
                BurpExtender.printOutput("[*] 用户确认覆盖现有文件");
            }
            
            // 检查数据库状态
            try {
                BurpExtender.printOutput("[*] 开始检查数据库状态");
                dbManager.checkDatabaseStatus();
                BurpExtender.printOutput("[*] 数据库状态检查完成");
            } catch (Exception e) {
                BurpExtender.printError("[!] 检查数据库状态时出错: " + e.getMessage());
                e.printStackTrace();
                JOptionPane.showMessageDialog(parent, "检查数据库状态时出错: " + e.getMessage(),
                        "导出错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            // 获取源数据库文件
            String dbFilePath = dbManager.getDatabaseFilePath();
            File dbFile = new File(dbFilePath);
            
            BurpExtender.printOutput("[*] 源数据库文件路径: " + dbFilePath);
            BurpExtender.printOutput("[*] 源数据库文件是否存在: " + dbFile.exists());
            
            if (dbFile.exists()) {
                BurpExtender.printOutput("[*] 源数据库文件大小: " + dbFile.length() + " 字节");
            } else {
                BurpExtender.printError("[!] 源数据库文件不存在!");
                JOptionPane.showMessageDialog(parent, "源数据库文件不存在",
                        "导出错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            // 确保目标目录存在
            File parentDir = selectedFile.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                boolean created = parentDir.mkdirs();
                BurpExtender.printOutput("[*] 创建目标目录: " + (created ? "成功" : "失败"));
                if (!created) {
                    JOptionPane.showMessageDialog(parent, "无法创建目标目录",
                            "导出错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
            }
            
            // 检查目标目录写入权限
            if (parentDir != null && (!parentDir.canWrite() || !parentDir.isDirectory())) {
                BurpExtender.printError("[!] 无法写入目标目录，权限不足或目录不存在");
                JOptionPane.showMessageDialog(parent, "无法写入目标目录，权限不足或目录不存在",
                        "导出错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            try {
                // 确保所有事务已提交，并执行WAL检查点
                try (Connection conn = dbManager.getConnection()) {
                    BurpExtender.printOutput("[*] 执行WAL检查点以确保所有数据都已写入磁盘");
                    Statement stmt = conn.createStatement();
                    stmt.execute("PRAGMA wal_checkpoint(FULL)");
                    stmt.close();
                } catch (SQLException e) {
                    BurpExtender.printError("[!] 执行WAL检查点时出错: " + e.getMessage());
                }
                
                // 关闭数据库以确保所有写入都已完成
                BurpExtender.printOutput("[*] 临时关闭数据库连接以确保文件完整性");
                dbManager.closeConnections();
                
                // 拷贝数据库文件
                BurpExtender.printOutput("[*] 开始复制数据库文件");
                Files.copy(dbFile.toPath(), selectedFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                BurpExtender.printOutput("[+] 数据库文件复制完成");
                
                // 验证导出的文件
                File exportedFile = new File(filePath);
                if (exportedFile.exists()) {
                    BurpExtender.printOutput("[+] 导出的文件存在，大小: " + exportedFile.length() + " 字节");
                } else {
                    BurpExtender.printError("[!] 导出的文件不存在!");
                }
                
                // 重新初始化数据库连接
                BurpExtender.printOutput("[*] 重新初始化数据库连接");
                dbManager.initialize();
                
                JOptionPane.showMessageDialog(parent, "数据库导出成功!",
                        "导出成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException e) {
                BurpExtender.printError("[!] 复制数据库文件时出错: " + e.getMessage());
                e.printStackTrace();
                
                // 尝试使用传统方法复制
                try {
                    BurpExtender.printOutput("[*] 尝试使用备用方法复制文件");
                    copyFileUsingStream(dbFile, selectedFile);
                    BurpExtender.printOutput("[+] 使用备用方法复制文件成功");
                    
                    JOptionPane.showMessageDialog(parent, "数据库导出成功!",
                            "导出成功", JOptionPane.INFORMATION_MESSAGE);
                } catch (IOException ee) {
                    BurpExtender.printError("[!] 备用复制方法也失败: " + ee.getMessage());
                    ee.printStackTrace();
                    
                    JOptionPane.showMessageDialog(parent, "导出数据库时出错: " + e.getMessage(),
                            "导出错误", JOptionPane.ERROR_MESSAGE);
                }
            }
        }
    }
    
    /**
     * 导出数据到JSON文件
     */
    public void exportToJson(Component parent) {
        BurpExtender.printOutput("[*] 开始导出JSON数据");
        
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("导出JSON数据");
        fileChooser.setSelectedFile(new File("replayer_export.json"));
        fileChooser.setFileFilter(new FileNameExtensionFilter("JSON文件 (*.json)", "json"));
        
        int result = fileChooser.showSaveDialog(parent);
        BurpExtender.printOutput("[*] 文件对话框结果: " + (result == JFileChooser.APPROVE_OPTION ? "已选择文件" : "已取消"));
        
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            String filePath = selectedFile.getAbsolutePath();
            
            if (!filePath.toLowerCase().endsWith(".json")) {
                filePath += ".json";
                selectedFile = new File(filePath);
            }
            
            BurpExtender.printOutput("[*] 选择的导出文件路径: " + filePath);
            
            if (selectedFile.exists()) {
                int overwrite = JOptionPane.showConfirmDialog(
                    parent,
                    "文件已存在，是否覆盖?",
                    "确认覆盖",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE
                );
                
                if (overwrite != JOptionPane.YES_OPTION) {
                    BurpExtender.printOutput("[*] 用户取消了覆盖现有文件");
                    return;
                }
                BurpExtender.printOutput("[*] 用户确认覆盖现有文件");
            }
            
            try {
                exportDataToJson(parent, selectedFile);
            } catch (Exception e) {
                BurpExtender.printError("[!] 导出JSON数据时出错: " + e.getMessage());
                e.printStackTrace();
                JOptionPane.showMessageDialog(parent, "导出JSON数据时出错: " + e.getMessage(),
                        "导出错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    /**
     * 将数据导出到JSON文件
     */
    private void exportDataToJson(Component parent, File outputFile) {
        BurpExtender.printOutput("[*] 开始从数据库导出数据到JSON");
        try (Connection conn = dbManager.getConnection()) {
            // 这里实现从数据库中读取数据并转换为JSON格式
            // 示例: 使用JSONObject或Gson等库将查询结果转换为JSON
            
            // 临时代码 - 创建一个简单的JSON文件
            try (PrintWriter writer = new PrintWriter(outputFile)) {
                writer.println("{");
                writer.println("  \"requests\": [");
                
                // 从请求表查询数据
                try (Statement stmt = conn.createStatement();
                     ResultSet rs = stmt.executeQuery("SELECT id, data FROM requests")) {
                    
                    boolean first = true;
                    while (rs.next()) {
                        if (!first) {
                            writer.println(",");
                        }
                        first = false;
                        
                        int id = rs.getInt("id");
                        byte[] data = rs.getBytes("data");
                        String base64Data = java.util.Base64.getEncoder().encodeToString(data);
                        
                        writer.print("    {");
                        writer.print("\"id\": " + id + ", ");
                        writer.print("\"data\": \"" + base64Data + "\"");
                        writer.print("}");
                    }
                    writer.println();
                }
                
                writer.println("  ],");
                writer.println("  \"history\": [");
                
                // 从历史表查询数据
                try (Statement stmt = conn.createStatement();
                     ResultSet rs = stmt.executeQuery(
                             "SELECT id, request_id, request_data, response_data, timestamp FROM history")) {
                    
                    boolean first = true;
                    while (rs.next()) {
                        if (!first) {
                            writer.println(",");
                        }
                        first = false;
                        
                        int id = rs.getInt("id");
                        int requestId = rs.getInt("request_id");
                        byte[] requestData = rs.getBytes("request_data");
                        byte[] responseData = rs.getBytes("response_data");
                        long timestamp = rs.getLong("timestamp");
                        
                        String requestBase64 = java.util.Base64.getEncoder().encodeToString(requestData);
                        String responseBase64 = responseData != null ? 
                                java.util.Base64.getEncoder().encodeToString(responseData) : "";
                        
                        writer.print("    {");
                        writer.print("\"id\": " + id + ", ");
                        writer.print("\"request_id\": " + requestId + ", ");
                        writer.print("\"request_data\": \"" + requestBase64 + "\", ");
                        writer.print("\"response_data\": \"" + responseBase64 + "\", ");
                        writer.print("\"timestamp\": " + timestamp);
                        writer.print("}");
                    }
                    writer.println();
                }
                
                writer.println("  ]");
                writer.println("}");
            }
            
            BurpExtender.printOutput("[+] JSON数据导出成功: " + outputFile.getAbsolutePath());
            JOptionPane.showMessageDialog(parent, "JSON数据导出成功!",
                    "导出成功", JOptionPane.INFORMATION_MESSAGE);
            
        } catch (SQLException e) {
            BurpExtender.printError("[!] 从数据库读取数据时出错: " + e.getMessage());
            throw new RuntimeException("数据库错误", e);
        } catch (IOException e) {
            BurpExtender.printError("[!] 写入JSON文件时出错: " + e.getMessage());
            throw new RuntimeException("文件写入错误", e);
        }
    }

    // 辅助方法：检查并记录数据库内容
    private void checkAndLogDatabaseContent() {
        try (Connection conn = dbManager.getConnection()) {
            BurpExtender.printOutput("[*] 正在检查数据库内容");
            
            // 检查请求表
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM requests")) {
                if (rs.next()) {
                    int count = rs.getInt(1);
                    BurpExtender.printOutput("[*] 请求表记录数: " + count);
                    
                    // 如果有记录，获取一些示例
                    if (count > 0) {
                        try (ResultSet sample = stmt.executeQuery("SELECT id, length(data) FROM requests LIMIT 3")) {
                            while (sample.next()) {
                                BurpExtender.printOutput("[*] 请求ID: " + sample.getInt(1) + 
                                                        ", 数据大小: " + sample.getInt(2) + " 字节");
                            }
                        }
                    }
                }
            }
            
            // 检查历史表
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM history")) {
                if (rs.next()) {
                    int count = rs.getInt(1);
                    BurpExtender.printOutput("[*] 历史表记录数: " + count);
                    
                    // 如果有记录，获取一些示例
                    if (count > 0) {
                        try (ResultSet sample = stmt.executeQuery(
                                "SELECT id, request_id, length(request_data), length(response_data) FROM history LIMIT 3")) {
                            while (sample.next()) {
                                BurpExtender.printOutput("[*] 历史ID: " + sample.getInt(1) + 
                                                        ", 请求ID: " + sample.getInt(2) + 
                                                        ", 请求大小: " + sample.getInt(3) + " 字节" + 
                                                        ", 响应大小: " + sample.getInt(4) + " 字节");
                            }
                        }
                    }
                }
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 检查数据库内容时SQL错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    // 辅助方法：使用流复制文件
    private void copyFileUsingStream(File source, File dest) throws IOException {
        BurpExtender.printOutput("[*] 使用流方法复制文件: " + source.getAbsolutePath() + " -> " + dest.getAbsolutePath());
        try (InputStream is = new FileInputStream(source);
             OutputStream os = new FileOutputStream(dest)) {
            
            byte[] buffer = new byte[8192];
            int length;
            long totalBytes = 0;
            
            while ((length = is.read(buffer)) > 0) {
                os.write(buffer, 0, length);
                totalBytes += length;
            }
            
            os.flush();
            BurpExtender.printOutput("[*] 共复制了 " + totalBytes + " 字节");
        }
    }
} 
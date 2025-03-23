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
    public void doExport(String format, Component parent) {
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
            
            int result = fileChooser.showSaveDialog(parent);
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
                        parent,
                        "文件已存在，是否覆盖？",
                        "确认覆盖",
                        JOptionPane.YES_NO_OPTION
                    );
                    
                    if (overwrite != JOptionPane.YES_OPTION) {
                        return;
                    }
                }
                
                if (format.equals("json")) {
                    exportDataToJson(outputFile, parent);
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
                        parent,
                        "数据导出已完成，但请注意检查是否包含您期望的数据。\n如果导出文件为空，可能表示数据库中没有存储任何数据。",
                        "导出完成",
                        JOptionPane.INFORMATION_MESSAGE
                    );
                }
            }
        } catch (IOException e) {
            BurpExtender.printError("[!] 导出数据失败: " + e.getMessage());
            JOptionPane.showMessageDialog(
                parent,
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
        try {
            BurpExtender.printOutput("[+] 开始SQLite数据库导出过程 - 直接执行");
            
            // 创建文件选择器
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("导出SQLite数据库");
            
            // 设置文件过滤器
            FileNameExtensionFilter filter = new FileNameExtensionFilter("SQLite Files (*.db)", "db");
            fileChooser.setFileFilter(filter);
            fileChooser.setSelectedFile(new File("replayer_export.db"));
            
            // 显示保存对话框
            int result = fileChooser.showSaveDialog(parent);
            BurpExtender.printOutput("[*] 文件选择对话框结果: " + (result == JFileChooser.APPROVE_OPTION ? "已选择文件" : "已取消"));
            
            if (result == JFileChooser.APPROVE_OPTION) {
                // 获取选择的文件
                File outputFile = fileChooser.getSelectedFile();
                
                // 确保有.db扩展名
                if (!outputFile.getName().toLowerCase().endsWith(".db")) {
                    outputFile = new File(outputFile.getAbsolutePath() + ".db");
                }
                
                BurpExtender.printOutput("[*] 选择的输出文件: " + outputFile.getAbsolutePath());
                
                // 检查文件是否已存在，如果存在则询问是否覆盖
                if (outputFile.exists()) {
                    int overwrite = JOptionPane.showConfirmDialog(
                        parent,
                        "文件已存在，是否覆盖？",
                        "确认覆盖",
                        JOptionPane.YES_NO_OPTION
                    );
                    
                    if (overwrite != JOptionPane.YES_OPTION) {
                        BurpExtender.printOutput("[*] 用户取消了覆盖操作");
                        return false;
                    }
                }
                
                // 获取源数据库路径
                String currentDbPath = dbManager.getConfig().getDatabasePath();
                File sourceDb = new File(currentDbPath);
                BurpExtender.printOutput("[*] 源数据库路径: " + currentDbPath + ", 文件存在: " + sourceDb.exists());
                
                if (sourceDb.exists()) {
                    BurpExtender.printOutput("[*] 源数据库文件大小: " + sourceDb.length() + " 字节");
                }
                
                // 使用超时机制检查数据库状态
                BurpExtender.printOutput("[*] 开始检查数据库状态 (带超时保护)");
                boolean dbStatusChecked = false;
                
                try {
                    // 创建一个带超时的线程来检查数据库状态
                    Thread dbCheckThread = new Thread(() -> {
                        try {
                            dbManager.checkDatabaseStatus();
                            BurpExtender.printOutput("[*] 数据库状态检查线程执行完成");
                        } catch (Exception e) {
                            BurpExtender.printError("[!] 数据库状态检查线程中发生异常: " + e.getMessage());
                            e.printStackTrace();
                        }
                    });
                    
                    dbCheckThread.start();
                    
                    // 等待最多5秒
                    dbCheckThread.join(5000);
                    
                    if (dbCheckThread.isAlive()) {
                        BurpExtender.printError("[!] 数据库状态检查超时，继续执行...");
                        // 尝试中断线程
                        dbCheckThread.interrupt();
                    } else {
                        dbStatusChecked = true;
                        BurpExtender.printOutput("[*] 数据库状态检查完成");
                    }
                } catch (Exception e) {
                    BurpExtender.printError("[!] 数据库状态检查过程异常: " + e.getMessage());
                    e.printStackTrace();
                }
                
                // 如果数据库检查失败，尝试替代方法
                if (!dbStatusChecked) {
                    BurpExtender.printOutput("[*] 尝试替代方法验证数据库...");
                    
                    try (Connection conn = dbManager.getConnection()) {
                        // 简单查询测试连接
                        try (Statement stmt = conn.createStatement()) {
                            stmt.executeQuery("SELECT 1");
                            BurpExtender.printOutput("[+] 数据库连接测试成功");
                        }
                    } catch (SQLException e) {
                        BurpExtender.printError("[!] 数据库连接测试失败: " + e.getMessage());
                        // 继续尝试，因为源文件可能仍然可以复制
                    }
                }
                
                // 检查目标目录是否存在并可写
                File targetDir = outputFile.getParentFile();
                if (targetDir != null && !targetDir.exists()) {
                    BurpExtender.printOutput("[*] 目标目录不存在，尝试创建: " + targetDir.getAbsolutePath());
                    try {
                        if (!targetDir.mkdirs()) {
                            String errorMessage = "无法创建目标目录: " + targetDir.getAbsolutePath();
                            BurpExtender.printError("[!] " + errorMessage);
                            JOptionPane.showMessageDialog(
                                parent,
                                errorMessage,
                                "导出失败",
                                JOptionPane.ERROR_MESSAGE
                            );
                            return false;
                        }
                    } catch (Exception e) {
                        String errorMessage = "创建目标目录时发生异常: " + e.getMessage();
                        BurpExtender.printError("[!] " + errorMessage);
                        JOptionPane.showMessageDialog(
                            parent,
                            errorMessage,
                            "导出失败",
                            JOptionPane.ERROR_MESSAGE
                        );
                        return false;
                    }
                }
                
                if (targetDir != null) {
                    BurpExtender.printOutput("[*] 目标目录存在: " + targetDir.exists() + ", 可写: " + targetDir.canWrite());
                    
                    if (!targetDir.canWrite()) {
                        String errorMessage = "目标目录没有写入权限: " + targetDir.getAbsolutePath();
                        BurpExtender.printError("[!] " + errorMessage);
                        JOptionPane.showMessageDialog(
                            parent,
                            errorMessage,
                            "导出失败",
                            JOptionPane.ERROR_MESSAGE
                        );
                        return false;
                    }
                }
                
                if (!sourceDb.exists()) {
                    BurpExtender.printOutput("[*] 源数据库文件不存在，尝试初始化...");
                    
                    // 尝试初始化数据库
                    if (!dbManager.initialize()) {
                        BurpExtender.printError("[!] 数据库初始化失败，尝试强制创建空数据库");
                        
                        // 尝试通过执行查询强制创建数据库文件
                        try (Connection conn = dbManager.getConnection();
                             Statement stmt = conn.createStatement()) {
                            // 执行简单查询以确保创建数据库文件
                            stmt.executeQuery("SELECT 1");
                            BurpExtender.printOutput("[+] 已成功创建数据库文件");
                        } catch (SQLException e) {
                            BurpExtender.printError("[!] 创建数据库文件失败: " + e.getMessage());
                            
                            // 如果仍然失败，尝试手动创建一个空的SQLite文件
                            BurpExtender.printOutput("[*] 尝试手动创建空的SQLite数据库文件...");
                            
                            try {
                                // 创建一个空的SQLite文件
                                try (java.io.FileOutputStream fos = new java.io.FileOutputStream(outputFile)) {
                                    // SQLite文件头
                                    byte[] sqliteHeader = new byte[] {
                                        0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 
                                        0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00
                                    };
                                    fos.write(sqliteHeader);
                                    BurpExtender.printOutput("[+] 已创建空的SQLite数据库文件");
                                    
                                    JOptionPane.showMessageDialog(
                                        parent,
                                        "已创建一个空的SQLite数据库文件，因为无法访问源数据库。",
                                        "导出提示",
                                        JOptionPane.INFORMATION_MESSAGE
                                    );
                                    return true;
                                }
                            } catch (IOException ex) {
                                BurpExtender.printError("[!] 创建空SQLite文件失败: " + ex.getMessage());
                                JOptionPane.showMessageDialog(
                                    parent,
                                    "导出数据失败: " + ex.getMessage(),
                                    "导出失败",
                                    JOptionPane.ERROR_MESSAGE
                                );
                                return false;
                            }
                        }
                    }
                }
                
                // 再次检查源数据库文件
                BurpExtender.printOutput("[*] 再次检查源数据库文件: " + sourceDb.exists() + ", 大小: " + 
                                       (sourceDb.exists() ? sourceDb.length() : 0) + " 字节");
                
                if (!sourceDb.exists()) {
                    String errorMessage = "尝试所有方法后，源数据库文件仍不存在";
                    BurpExtender.printError("[!] " + errorMessage);
                    JOptionPane.showMessageDialog(
                        parent,
                        errorMessage,
                        "导出失败",
                        JOptionPane.ERROR_MESSAGE
                    );
                    return false;
                }
                
                // 确保数据库文件未被锁定
                BurpExtender.printOutput("[*] 检查数据库文件是否可读...");
                boolean canReadDb = false;
                
                try (java.io.FileInputStream testStream = new java.io.FileInputStream(sourceDb)) {
                    // 尝试读取前100个字节
                    byte[] testBuffer = new byte[100];
                    int bytesRead = testStream.read(testBuffer);
                    BurpExtender.printOutput("[*] 成功从数据库文件读取 " + bytesRead + " 字节");
                    canReadDb = true;
                } catch (IOException e) {
                    BurpExtender.printError("[!] 无法读取数据库文件: " + e.getMessage());
                }
                
                if (!canReadDb) {
                    String errorMessage = "无法读取源数据库文件，可能被锁定或权限不足";
                    BurpExtender.printError("[!] " + errorMessage);
                    JOptionPane.showMessageDialog(
                        parent,
                        errorMessage,
                        "导出失败",
                        JOptionPane.ERROR_MESSAGE
                    );
                    return false;
                }
                
                try {
                    // 复制数据库文件
                    BurpExtender.printOutput("[*] 正在复制数据库文件...");
                    boolean copySuccess = false;
                    
                    try {
                        // 先尝试直接复制文件
                        Files.copy(sourceDb.toPath(), outputFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                        BurpExtender.printOutput("[+] 文件复制成功 (NIO 方式)");
                        copySuccess = true;
                    } catch (IOException e) {
                        BurpExtender.printError("[!] 使用Files.copy复制文件失败: " + e.getMessage());
                        
                        // 如果失败，尝试使用传统的文件流复制
                        BurpExtender.printOutput("[*] 尝试使用文件流方式复制文件...");
                        try (java.io.FileInputStream fis = new java.io.FileInputStream(sourceDb);
                             java.io.FileOutputStream fos = new java.io.FileOutputStream(outputFile)) {
                            
                            byte[] buffer = new byte[8192];
                            int length;
                            long total = 0;
                            
                            while ((length = fis.read(buffer)) > 0) {
                                fos.write(buffer, 0, length);
                                total += length;
                            }
                            
                            BurpExtender.printOutput("[+] 使用文件流复制成功，共复制 " + total + " 字节");
                            copySuccess = true;
                        } catch (IOException ex) {
                            BurpExtender.printError("[!] 使用文件流复制也失败: " + ex.getMessage());
                            
                            // 尝试第三种方法 - 使用FileChannel
                            BurpExtender.printOutput("[*] 尝试使用FileChannel复制文件...");
                            try (java.io.FileInputStream fis = new java.io.FileInputStream(sourceDb);
                                 java.io.FileOutputStream fos = new java.io.FileOutputStream(outputFile);
                                 java.nio.channels.FileChannel inChannel = fis.getChannel();
                                 java.nio.channels.FileChannel outChannel = fos.getChannel()) {
                                
                                long size = inChannel.size();
                                long position = 0;
                                long count = 0;
                                
                                while (position < size) {
                                    count = inChannel.transferTo(position, 1024*1024, outChannel);
                                    position += count;
                                }
                                
                                BurpExtender.printOutput("[+] 使用FileChannel复制成功，共复制 " + size + " 字节");
                                copySuccess = true;
                            } catch (IOException e3) {
                                BurpExtender.printError("[!] 使用FileChannel复制也失败: " + e3.getMessage());
                            }
                        }
                    }
                    
                    // 检查目标文件是否存在和大小
                    if (outputFile.exists()) {
                        BurpExtender.printOutput("[+] 确认目标文件已成功创建，大小: " + outputFile.length() + " 字节");
                    } else {
                        BurpExtender.printError("[!] 目标文件复制后不存在，这是一个严重错误");
                        if (copySuccess) {
                            BurpExtender.printError("[!] 复制过程报告成功但文件不存在，可能是权限或磁盘问题");
                        }
                    }
                    
                    if (!copySuccess) {
                        String errorMessage = "尝试了所有复制方法后仍然失败";
                        BurpExtender.printError("[!] " + errorMessage);
                        JOptionPane.showMessageDialog(
                            parent,
                            errorMessage,
                            "导出失败",
                            JOptionPane.ERROR_MESSAGE
                        );
                        return false;
                    }
                    
                    BurpExtender.printOutput("[+] 数据导出成功: " + outputFile.getAbsolutePath());
                    
                    // 提示用户检查导出的数据
                    JOptionPane.showMessageDialog(
                        parent,
                        "数据导出已完成，但请注意检查是否包含您期望的数据。\n如果导出文件为空，可能表示数据库中没有存储任何数据。",
                        "导出完成",
                        JOptionPane.INFORMATION_MESSAGE
                    );
                    return true;
                } catch (Exception e) {
                    String errorMessage = "导出数据失败: " + e.getMessage();
                    BurpExtender.printError("[!] " + errorMessage);
                    e.printStackTrace();
                    JOptionPane.showMessageDialog(
                        parent,
                        errorMessage,
                        "导出失败",
                        JOptionPane.ERROR_MESSAGE
                    );
                    return false;
                }
            }
            return false; // 用户取消
        } catch (Exception e) {
            BurpExtender.printError("[!] 导出过程发生异常: " + e.getMessage());
            e.printStackTrace();
            JOptionPane.showMessageDialog(
                parent,
                "导出过程发生异常: " + e.getMessage(),
                "导出错误",
                JOptionPane.ERROR_MESSAGE
            );
            return false;
        }
    }
    
    /**
     * 导出数据到JSON格式
     */
    public boolean exportToJson(Component parent) {
        try {
            BurpExtender.printOutput("[+] 开始JSON导出过程 - 直接执行");
            
            // 创建文件选择器
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("导出JSON数据");
            
            // 设置文件过滤器
            FileNameExtensionFilter filter = new FileNameExtensionFilter("JSON Files (*.json)", "json");
            fileChooser.setFileFilter(filter);
            fileChooser.setSelectedFile(new File("replayer_export.json"));
            
            // 显示保存对话框
            int result = fileChooser.showSaveDialog(parent);
            BurpExtender.printOutput("[*] 文件选择对话框结果: " + (result == JFileChooser.APPROVE_OPTION ? "已选择文件" : "已取消"));
            
            if (result == JFileChooser.APPROVE_OPTION) {
                // 获取选择的文件
                File outputFile = fileChooser.getSelectedFile();
                
                // 确保有.json扩展名
                if (!outputFile.getName().toLowerCase().endsWith(".json")) {
                    outputFile = new File(outputFile.getAbsolutePath() + ".json");
                }
                
                BurpExtender.printOutput("[*] 选择的输出文件: " + outputFile.getAbsolutePath());
                
                // 检查文件是否已存在，如果存在则询问是否覆盖
                if (outputFile.exists()) {
                    int overwrite = JOptionPane.showConfirmDialog(
                        parent,
                        "文件已存在，是否覆盖？",
                        "确认覆盖",
                        JOptionPane.YES_NO_OPTION
                    );
                    
                    if (overwrite != JOptionPane.YES_OPTION) {
                        BurpExtender.printOutput("[*] 用户取消了覆盖操作");
                        return false;
                    }
                }
                
                try {
                    // 检查数据库状态
                    BurpExtender.printOutput("[*] 开始检查数据库状态");
                    dbManager.checkDatabaseStatus();
                    
                    // 执行JSON导出
                    exportDataToJson(outputFile, parent);
                    return true;
                } catch (IOException e) {
                    String errorMessage = "导出数据失败: " + e.getMessage();
                    BurpExtender.printError("[!] " + errorMessage);
                    JOptionPane.showMessageDialog(
                        parent,
                        errorMessage,
                        "导出失败",
                        JOptionPane.ERROR_MESSAGE
                    );
                    return false;
                }
            }
            return false; // 用户取消
        } catch (Exception e) {
            BurpExtender.printError("[!] 导出过程发生异常: " + e.getMessage());
            e.printStackTrace();
            JOptionPane.showMessageDialog(
                parent,
                "导出过程发生异常: " + e.getMessage(),
                "导出错误",
                JOptionPane.ERROR_MESSAGE
            );
            return false;
        }
    }
    
    /**
     * 执行JSON导出
     */
    private void exportDataToJson(File outputFile, Component parent) throws IOException {
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
                parent,
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
        BurpExtender.printOutput("[*] 正在将数据转换为JSON格式...");
        com.google.gson.Gson gson = new com.google.gson.GsonBuilder()
            .setPrettyPrinting()
            .create();
        
        String json = gson.toJson(exportData);
        BurpExtender.printOutput("[*] JSON转换完成，文件大小: " + json.length() + " 字节");
        
        // 写入文件
        BurpExtender.printOutput("[*] 正在将JSON数据写入文件: " + outputFile.getAbsolutePath());
        try (java.io.FileWriter writer = new java.io.FileWriter(outputFile)) {
            writer.write(json);
            BurpExtender.printOutput("[+] JSON数据写入文件成功");
        } catch (IOException e) {
            BurpExtender.printError("[!] 写入JSON文件失败: " + e.getMessage());
            throw e;
        }
        
        BurpExtender.printOutput("[+] 数据导出到JSON成功: " + outputFile.getAbsolutePath() +
                              "，包含 " + requests.size() + " 条请求和 " + history.size() + " 条历史记录");
        
        // 导出结果提示
        if (requests.isEmpty() && history.isEmpty()) {
            JOptionPane.showMessageDialog(
                parent,
                "数据导出已完成，但没有找到任何有效数据。\n请先使用插件保存一些请求或响应数据。",
                "导出完成",
                JOptionPane.INFORMATION_MESSAGE
            );
        } else {
            JOptionPane.showMessageDialog(
                parent,
                "数据导出成功！\n已导出 " + requests.size() + " 条请求和 " + history.size() + " 条历史记录。",
                "导出成功",
                JOptionPane.INFORMATION_MESSAGE
            );
        }
    }
} 
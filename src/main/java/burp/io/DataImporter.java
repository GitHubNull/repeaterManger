package burp.io;

import burp.BurpExtender;
import burp.db.DatabaseManager;
import burp.db.RequestDAO;
import burp.db.HistoryDAO;
import burp.http.RequestResponseRecord;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.sql.SQLException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Component;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.InputStreamReader;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * 数据导入器 - 负责从文件导入数据
 */
public class DataImporter {
    private final DatabaseManager dbManager;
    private final RequestDAO requestDAO;
    private final HistoryDAO historyDAO;
    private final AtomicBoolean isImporting = new AtomicBoolean(false);
    
    /**
     * 创建数据导入器
     */
    public DataImporter() {
        this.dbManager = DatabaseManager.getInstance();
        this.requestDAO = new RequestDAO();
        this.historyDAO = new HistoryDAO();
    }
    
    /**
     * 从SQLite数据库文件导入数据
     * 
     * @param parent 父组件（用于显示文件选择器）
     * @return 是否开始导入操作
     */
    public boolean importFromSQLite(Component parent) {
        if (isImporting.get()) {
            JOptionPane.showMessageDialog(
                parent,
                "另一个导入操作正在进行中，请稍后再试。",
                "导入繁忙",
                JOptionPane.WARNING_MESSAGE
            );
            return false;
        }
        
        // 显示文件选择对话框
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("导入数据库");
        fileChooser.setFileFilter(new FileNameExtensionFilter("SQLite数据库文件 (*.db)", "db"));
        fileChooser.setAcceptAllFileFilterUsed(false);
        
        int result = fileChooser.showOpenDialog(parent);
        if (result != JFileChooser.APPROVE_OPTION) {
            return false;
        }
        
        File selectedFile = fileChooser.getSelectedFile();
        
        if (!selectedFile.exists() || !selectedFile.isFile()) {
            JOptionPane.showMessageDialog(
                parent,
                "所选文件不存在",
                "导入错误",
                JOptionPane.ERROR_MESSAGE
            );
            return false;
        }
        
        // 确认导入操作（将覆盖现有数据）
        int confirm = JOptionPane.showConfirmDialog(
            parent,
            "导入操作将覆盖现有数据，是否继续？",
            "确认导入",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE
        );
        
        if (confirm != JOptionPane.YES_OPTION) {
            return false;
        }
        
        // 标记导入状态
        isImporting.set(true);
        
        // 在后台线程执行导入操作
        CompletableFuture.runAsync(() -> {
            try {
                doImportFromSQLite(selectedFile);
                
                // 显示成功消息
                JOptionPane.showMessageDialog(
                    parent,
                    "数据导入成功",
                    "导入成功",
                    JOptionPane.INFORMATION_MESSAGE
                );
                
            } catch (Exception e) {
                BurpExtender.printError("[!] 导入数据失败: " + e.getMessage());
                
                // 显示错误消息
                JOptionPane.showMessageDialog(
                    parent,
                    "导入数据失败: " + e.getMessage(),
                    "导入错误",
                    JOptionPane.ERROR_MESSAGE
                );
            } finally {
                isImporting.set(false);
            }
        });
        
        return true;
    }
    
    /**
     * 执行SQLite数据库导入
     */
    private void doImportFromSQLite(File sourceFile) throws IOException, SQLException {
        // 获取当前运行的数据库路径
        String currentDbPath = dbManager.getConfig().getDatabasePath();
        File targetFile = new File(currentDbPath);
        File backupFile = new File(currentDbPath + ".bak");
        
        BurpExtender.printOutput("[*] 开始释放数据库资源，准备导入...");
        
        try {
            // 确保自动保存服务停止
            try {
                // 尝试停止自动保存服务
                java.lang.reflect.Field extenderField = BurpExtender.class.getDeclaredField("mainUI");
                extenderField.setAccessible(true);
                Object mainUI = extenderField.get(null); // static字段
                
                if (mainUI != null && mainUI.getClass().getName().equals("burp.ui.MainUI")) {
                    // 调用自动保存服务停止方法
                    java.lang.reflect.Method onUnloadMethod = mainUI.getClass().getMethod("onUnload");
                    onUnloadMethod.invoke(mainUI);
                    BurpExtender.printOutput("[+] 已停止自动保存服务");
                }
            } catch (Exception e) {
                BurpExtender.printError("[!] 停止自动保存服务失败: " + e.getMessage());
            }
            
            // 关闭当前数据库连接
            dbManager.close();
            BurpExtender.printOutput("[+] 数据库连接池已关闭");
            
            // 等待一段时间确保所有连接都释放
            for (int i = 0; i < 3; i++) {
                System.gc(); // 请求垃圾回收，帮助释放资源
                try {
                    Thread.sleep(1000); // 等待1秒
                    BurpExtender.printOutput("[*] 等待数据库资源释放...");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            
            // 检查文件是否可访问
            boolean fileAccessible = true;
            if (targetFile.exists()) {
                try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(targetFile, "rw")) {
                    // 尝试写入以确认文件已解锁
                    raf.getFD().sync();
                    BurpExtender.printOutput("[+] 确认数据库文件已解锁，可以访问");
                } catch (Exception e) {
                    fileAccessible = false;
                    BurpExtender.printError("[!] 数据库文件仍然被锁定: " + e.getMessage());
                }
            }
            
            if (!fileAccessible) {
                BurpExtender.printOutput("[*] 尝试强制释放数据库资源...");
                // 再次尝试垃圾回收和等待
                System.gc();
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        
            // 备份当前数据库
            if (targetFile.exists()) {
                // 先确认备份目录存在
                File backupDir = backupFile.getParentFile();
                if (!backupDir.exists()) {
                    backupDir.mkdirs();
                }
                
                try {
                    Files.copy(targetFile.toPath(), backupFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                    BurpExtender.printOutput("[+] 已备份当前数据库到: " + backupFile.getAbsolutePath());
                } catch (Exception e) {
                    throw new IOException("备份数据库失败: " + e.getMessage(), e);
                }
            }
            
            // 确保目标目录存在
            File targetDir = targetFile.getParentFile();
            if (!targetDir.exists()) {
                targetDir.mkdirs();
                BurpExtender.printOutput("[+] 已创建目标目录: " + targetDir.getAbsolutePath());
            }
            
            // 复制导入的数据库文件到当前位置
            try {
                // 使用Java NIO进行文件复制
                Files.copy(sourceFile.toPath(), targetFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                BurpExtender.printOutput("[+] 已复制数据库文件到: " + targetFile.getAbsolutePath());
            } catch (Exception e) {
                // 如果复制失败，尝试使用FileChannel
                BurpExtender.printError("[!] 标准复制失败，尝试备用方法: " + e.getMessage());
                try (java.io.FileInputStream fis = new java.io.FileInputStream(sourceFile);
                     java.io.FileOutputStream fos = new java.io.FileOutputStream(targetFile);
                     java.nio.channels.FileChannel sourceChannel = fis.getChannel();
                     java.nio.channels.FileChannel destChannel = fos.getChannel()) {
                    destChannel.transferFrom(sourceChannel, 0, sourceChannel.size());
                    BurpExtender.printOutput("[+] 使用备用方法成功复制数据库文件");
                } catch (Exception ex) {
                    throw new IOException("复制数据库文件失败: " + ex.getMessage(), ex);
                }
            }
            
            // 验证文件是否已成功复制
            if (!targetFile.exists() || targetFile.length() == 0) {
                throw new IOException("复制后的目标文件不存在或为空");
            }
            
            // 等待文件系统操作完成
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            
            BurpExtender.printOutput("[*] 开始重新初始化数据库连接...");
            
            // 重新初始化数据库连接
            boolean success = false;
            for (int i = 0; i < 3; i++) { // 尝试多次初始化
                try {
                    success = dbManager.initialize();
                    if (success) {
                        BurpExtender.printOutput("[+] 数据库连接重新初始化成功");
                        break;
                    }
                } catch (Exception e) {
                    BurpExtender.printError("[!] 初始化尝试 " + (i+1) + " 失败: " + e.getMessage());
                }
                // 短暂等待后重试
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            
            if (!success) {
                // 如果初始化失败，恢复备份
                if (backupFile.exists()) {
                    BurpExtender.printError("[!] 数据库初始化失败，正在恢复备份...");
                    Files.copy(backupFile.toPath(), targetFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                    dbManager.initialize();
                    throw new SQLException("导入数据库后初始化失败，已恢复备份");
                } else {
                    throw new SQLException("导入数据库后初始化失败，且无备份可恢复");
                }
            }
            
            BurpExtender.printOutput("[+] 数据导入成功: " + sourceFile.getAbsolutePath());
            
            // 导入成功后，刷新界面数据
            try {
                // 查找并获取主UI实例
                refreshUIAfterImport();
            } catch (Exception e) {
                BurpExtender.printError("[!] 刷新UI失败，可能需要重启插件: " + e.getMessage());
                e.printStackTrace();
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 导入过程中发生错误: " + e.getMessage());
            if (e instanceof IOException || e instanceof SQLException) {
                throw e; // 重新抛出原始异常
            } else {
                throw new IOException("导入过程中发生未知错误: " + e.getMessage(), e);
            }
        }
    }
    
    /**
     * 在导入后刷新UI界面
     */
    private void refreshUIAfterImport() {
        BurpExtender.printOutput("[*] 正在刷新界面数据...");
        
        try {
            // 尝试直接访问BurpExtender中的repeaterUI实例
            java.lang.reflect.Field repeaterUIField = BurpExtender.class.getDeclaredField("repeaterUI");
            repeaterUIField.setAccessible(true);
            
            Object repeaterUIObj = repeaterUIField.get(null); // static字段，传入null
            if (repeaterUIObj != null && repeaterUIObj instanceof burp.EnhancedRepeaterUI) {
                burp.EnhancedRepeaterUI repeaterUI = (burp.EnhancedRepeaterUI) repeaterUIObj;
                
                // 刷新数据
                repeaterUI.refreshAllData();
                BurpExtender.printOutput("[+] 界面数据刷新成功");
            } else {
                BurpExtender.printOutput("[!] 无法获取EnhancedRepeaterUI实例，请手动切换到其他标签再切回");
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 刷新界面数据时出错: " + e.getMessage());
            e.printStackTrace();
            
            // 提示用户手动刷新
            BurpExtender.printOutput("[*] 请尝试切换到其他Burp标签页，然后再切回插件标签页以刷新数据");
        }
    }
    
    /**
     * 递归查找EnhancedRepeaterUI实例
     * 由于类型兼容性问题这个方法不太可靠，仅作备用
     */
    @SuppressWarnings("unused")
    private Object findEnhancedRepeaterUI(java.awt.Component component) {
        // 通过类名检查，避免直接类型比较导致的兼容性问题
        if (component.getClass().getName().equals("burp.EnhancedRepeaterUI")) {
            return component;
        }
        
        if (component instanceof java.awt.Container) {
            java.awt.Container container = (java.awt.Container) component;
            for (java.awt.Component child : container.getComponents()) {
                Object ui = findEnhancedRepeaterUI(child);
                if (ui != null) {
                    return ui;
                }
            }
        }
        
        return null;
    }
    
    /**
     * 从JSON文件导入数据
     */
    public boolean importFromJson(Component parent) {
        if (isImporting.get()) {
            JOptionPane.showMessageDialog(
                parent,
                "另一个导入操作正在进行中，请稍后再试。",
                "导入繁忙",
                JOptionPane.WARNING_MESSAGE
            );
            return false;
        }
        
        // 显示文件选择对话框
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("从JSON导入数据");
        fileChooser.setFileFilter(new FileNameExtensionFilter("JSON文件 (*.json)", "json"));
        fileChooser.setAcceptAllFileFilterUsed(false);
        
        int result = fileChooser.showOpenDialog(parent);
        if (result != JFileChooser.APPROVE_OPTION) {
            return false;
        }
        
        File selectedFile = fileChooser.getSelectedFile();
        
        if (!selectedFile.exists() || !selectedFile.isFile()) {
            JOptionPane.showMessageDialog(
                parent,
                "所选文件不存在",
                "导入错误",
                JOptionPane.ERROR_MESSAGE
            );
            return false;
        }
        
        // 确认导入操作
        int mergeOrReplace = JOptionPane.showOptionDialog(
            parent,
            "选择导入模式：\n- 合并：将导入数据添加到现有数据\n- 替换：清空现有数据后导入",
            "选择导入模式",
            JOptionPane.DEFAULT_OPTION,
            JOptionPane.QUESTION_MESSAGE,
            null,
            new String[]{"合并", "替换", "取消"},
            "合并"
        );
        
        if (mergeOrReplace == 2 || mergeOrReplace == JOptionPane.CLOSED_OPTION) {
            return false;
        }
        
        final boolean isReplace = (mergeOrReplace == 1);
        
        // 标记导入状态
        isImporting.set(true);
        
        // 在后台线程执行导入操作
        CompletableFuture.runAsync(() -> {
            try {
                doImportFromJson(selectedFile, isReplace);
                
                // 显示成功消息
                JOptionPane.showMessageDialog(
                    parent,
                    "数据导入成功",
                    "导入成功",
                    JOptionPane.INFORMATION_MESSAGE
                );
                
            } catch (Exception e) {
                BurpExtender.printError("[!] 导入数据失败: " + e.getMessage());
                e.printStackTrace();
                
                // 显示错误消息
                JOptionPane.showMessageDialog(
                    parent,
                    "导入数据失败: " + e.getMessage(),
                    "导入错误",
                    JOptionPane.ERROR_MESSAGE
                );
            } finally {
                isImporting.set(false);
            }
        });
        
        return true;
    }
    
    /**
     * 执行从JSON文件导入的操作
     */
    private void doImportFromJson(File jsonFile, boolean replace) throws IOException, SQLException {
        if (replace) {
            // 清空现有数据
            requestDAO.clearAllRequests();
            historyDAO.clearAllHistory();
            BurpExtender.printOutput("[+] 已清空现有数据，准备导入");
        }
        
        // 解析JSON文件
        try (FileInputStream fis = new FileInputStream(jsonFile);
             InputStreamReader reader = new InputStreamReader(fis, StandardCharsets.UTF_8)) {
            
            JsonElement jsonElement = JsonParser.parseReader(reader);
            JsonObject rootObject = jsonElement.getAsJsonObject();
            
            // 导入请求数据
            if (rootObject.has("requests")) {
                JsonArray requestsArray = rootObject.getAsJsonArray("requests");
                for (JsonElement element : requestsArray) {
                    JsonObject requestObj = element.getAsJsonObject();
                    importRequestFromJson(requestObj);
                }
            }
            
            // 导入历史记录数据
            if (rootObject.has("history")) {
                JsonArray historyArray = rootObject.getAsJsonArray("history");
                for (JsonElement element : historyArray) {
                    JsonObject historyObj = element.getAsJsonObject();
                    importHistoryFromJson(historyObj);
                }
            }
        }
        
        BurpExtender.printOutput("[+] 从JSON文件导入数据成功: " + jsonFile.getAbsolutePath());
    }
    
    /**
     * 从JSON对象导入请求
     */
    private void importRequestFromJson(JsonObject requestObj) {
        try {
            String protocol = getStringFromJson(requestObj, "protocol");
            String domain = getStringFromJson(requestObj, "domain");
            String path = getStringFromJson(requestObj, "path");
            String query = getStringFromJson(requestObj, "query");
            String method = getStringFromJson(requestObj, "method");
            String comment = getStringFromJson(requestObj, "comment");
            
            // 获取请求数据
            byte[] requestData = null;
            if (requestObj.has("request_data") && !requestObj.get("request_data").isJsonNull()) {
                String base64Data = requestObj.get("request_data").getAsString();
                if (base64Data != null && !base64Data.isEmpty()) {
                    try {
                        requestData = Base64.getDecoder().decode(base64Data);
                    } catch (IllegalArgumentException e) {
                        requestData = base64Data.getBytes(StandardCharsets.UTF_8);
                    }
                }
            }
            
            // 保存请求
            int newRequestId = requestDAO.saveRequest(protocol, domain, path, query, method, requestData);
            
            // 设置备注
            if (comment != null && !comment.isEmpty()) {
                requestDAO.updateRequestComment(newRequestId, comment);
            }
            
            // 设置颜色
            if (requestObj.has("color") && !requestObj.get("color").isJsonNull()) {
                String colorStr = requestObj.get("color").getAsString();
                if (colorStr != null && !colorStr.isEmpty()) {
                    try {
                        java.awt.Color color = java.awt.Color.decode(colorStr);
                        requestDAO.updateRequestColor(newRequestId, color);
                    } catch (Exception e) {
                        // 忽略颜色错误
                    }
                }
            }
            
        } catch (Exception e) {
            BurpExtender.printError("[!] 导入请求失败: " + e.getMessage());
        }
    }
    
    /**
     * 从JSON对象导入历史记录
     */
    private void importHistoryFromJson(JsonObject historyObj) {
        try {
            RequestResponseRecord record = new RequestResponseRecord();
            
            // 设置基本属性
            record.setRequestId(getIntFromJson(historyObj, "request_id", 1));
            record.setMethod(getStringFromJson(historyObj, "method"));
            record.setProtocol(getStringFromJson(historyObj, "protocol"));
            record.setDomain(getStringFromJson(historyObj, "domain"));
            record.setPath(getStringFromJson(historyObj, "path"));
            record.setQueryParameters(getStringFromJson(historyObj, "query"));
            record.setStatusCode(getIntFromJson(historyObj, "status_code", 0));
            record.setResponseLength(getIntFromJson(historyObj, "response_length", 0));
            record.setResponseTime(getIntFromJson(historyObj, "response_time", 0));
            record.setComment(getStringFromJson(historyObj, "comment"));
            
            // 获取请求响应数据
            if (historyObj.has("request_data") && !historyObj.get("request_data").isJsonNull()) {
                String base64Data = historyObj.get("request_data").getAsString();
                if (base64Data != null && !base64Data.isEmpty()) {
                    try {
                        record.setRequestData(Base64.getDecoder().decode(base64Data));
                    } catch (IllegalArgumentException e) {
                        record.setRequestData(base64Data.getBytes(StandardCharsets.UTF_8));
                    }
                }
            }
            
            if (historyObj.has("response_data") && !historyObj.get("response_data").isJsonNull()) {
                String base64Data = historyObj.get("response_data").getAsString();
                if (base64Data != null && !base64Data.isEmpty()) {
                    try {
                        record.setResponseData(Base64.getDecoder().decode(base64Data));
                    } catch (IllegalArgumentException e) {
                        record.setResponseData(base64Data.getBytes(StandardCharsets.UTF_8));
                    }
                }
            }
            
            // 保存历史记录
            historyDAO.saveHistory(record);
            
        } catch (Exception e) {
            BurpExtender.printError("[!] 导入历史记录失败: " + e.getMessage());
        }
    }
    
    /**
     * 从JSON获取字符串值
     */
    private String getStringFromJson(JsonObject jsonObj, String key) {
        if (jsonObj.has(key) && !jsonObj.get(key).isJsonNull()) {
            return jsonObj.get(key).getAsString();
        }
        return "";
    }
    
    /**
     * 从JSON获取整数值
     */
    private int getIntFromJson(JsonObject jsonObj, String key, int defaultValue) {
        if (jsonObj.has(key) && !jsonObj.get(key).isJsonNull()) {
            try {
                return jsonObj.get(key).getAsInt();
            } catch (Exception e) {
                return defaultValue;
            }
        }
        return defaultValue;
    }
} 
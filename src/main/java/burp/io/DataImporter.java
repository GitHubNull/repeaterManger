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
        
        // 关闭当前数据库连接
        dbManager.close();
        
        // 备份当前数据库
        File backupFile = new File(currentDbPath + ".bak");
        if (targetFile.exists()) {
            Files.copy(targetFile.toPath(), backupFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            BurpExtender.printOutput("[+] 已备份当前数据库到: " + backupFile.getAbsolutePath());
        }
        
        // 复制导入的数据库文件到当前位置
        Files.copy(sourceFile.toPath(), targetFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
        
        // 重新初始化数据库连接
        boolean success = dbManager.initialize();
        
        if (!success) {
            // 如果初始化失败，恢复备份
            if (backupFile.exists()) {
                Files.copy(backupFile.toPath(), targetFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                dbManager.initialize();
                throw new SQLException("导入数据库后初始化失败，已恢复备份");
            } else {
                throw new SQLException("导入数据库后初始化失败，且无备份可恢复");
            }
        }
        
        BurpExtender.printOutput("[+] 数据导入成功: " + sourceFile.getAbsolutePath());
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
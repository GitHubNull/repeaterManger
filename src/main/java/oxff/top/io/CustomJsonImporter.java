package oxff.top.io;

import burp.BurpExtender;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import oxff.top.db.DatabaseManager;
import oxff.top.db.HistoryDAO;
import oxff.top.db.RequestDAO;
import oxff.top.http.RequestResponseRecord;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Component;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 自定义JSON格式导入器
 */
public class CustomJsonImporter {
    @SuppressWarnings("unused")
    private final DatabaseManager dbManager;
    private final RequestDAO requestDAO;
    private final HistoryDAO historyDAO;
    private final AtomicBoolean isImporting = new AtomicBoolean(false);

    public CustomJsonImporter() {
        this.dbManager = DatabaseManager.getInstance();
        this.requestDAO = new RequestDAO();
        this.historyDAO = new HistoryDAO();
    }

    /**
     * 从自定义JSON文件导入（UI入口）
     */
    public boolean importFromFile(Component parent) {
        if (isImporting.get()) {
            JOptionPane.showMessageDialog(parent,
                "另一个导入操作正在进行中，请稍后再试。", "导入繁忙", JOptionPane.WARNING_MESSAGE);
            return false;
        }

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
            JOptionPane.showMessageDialog(parent, "所选文件不存在", "导入错误", JOptionPane.ERROR_MESSAGE);
            return false;
        }

        int mergeOrReplace = JOptionPane.showOptionDialog(parent,
            "选择导入模式：\n- 合并：将导入数据添加到现有数据\n- 替换：清空现有数据后导入",
            "选择导入模式", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE,
            null, new String[]{"合并", "替换", "取消"}, "合并");

        if (mergeOrReplace == 2 || mergeOrReplace == JOptionPane.CLOSED_OPTION) {
            return false;
        }

        final boolean isReplace = (mergeOrReplace == 1);

        isImporting.set(true);
        CompletableFuture.runAsync(() -> {
            try {
                doImport(selectedFile, isReplace);
                JOptionPane.showMessageDialog(parent, "数据导入成功", "导入成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                BurpExtender.printError("[!] 导入数据失败: " + e.getMessage());
                JOptionPane.showMessageDialog(parent,
                    "导入数据失败: " + e.getMessage(), "导入错误", JOptionPane.ERROR_MESSAGE);
            } finally {
                isImporting.set(false);
            }
        });

        return true;
    }

    /**
     * 执行导入
     */
    private void doImport(File jsonFile, boolean replace) throws IOException, SQLException {
        if (replace) {
            requestDAO.clearAllRequests();
            historyDAO.clearAllHistory();
            BurpExtender.printOutput("[+] 已清空现有数据，准备导入");
        }

        try (FileInputStream fis = new FileInputStream(jsonFile);
             InputStreamReader reader = new InputStreamReader(fis, StandardCharsets.UTF_8)) {

            JsonElement jsonElement = JsonParser.parseReader(reader);
            JsonObject rootObject = jsonElement.getAsJsonObject();

            if (rootObject.has("requests")) {
                JsonArray requestsArray = rootObject.getAsJsonArray("requests");
                for (JsonElement element : requestsArray) {
                    importRequestFromJson(element.getAsJsonObject());
                }
            }

            if (rootObject.has("history")) {
                JsonArray historyArray = rootObject.getAsJsonArray("history");
                for (JsonElement element : historyArray) {
                    importHistoryFromJson(element.getAsJsonObject());
                }
            }
        }

        BurpExtender.printOutput("[+] 从JSON文件导入数据成功: " + jsonFile.getAbsolutePath());
    }

    private void importRequestFromJson(JsonObject requestObj) {
        try {
            String protocol = getStringFromJson(requestObj, "protocol");
            String domain = getStringFromJson(requestObj, "domain");
            String path = getStringFromJson(requestObj, "path");
            String query = getStringFromJson(requestObj, "query");
            String method = getStringFromJson(requestObj, "method");
            String comment = getStringFromJson(requestObj, "comment");

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

            int newRequestId = requestDAO.saveRequest(protocol, domain, path, query, method, requestData);

            if (comment != null && !comment.isEmpty()) {
                requestDAO.updateRequestComment(newRequestId, comment);
            }

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

    private void importHistoryFromJson(JsonObject historyObj) {
        try {
            RequestResponseRecord record = new RequestResponseRecord();
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

            historyDAO.saveHistory(record);
        } catch (Exception e) {
            BurpExtender.printError("[!] 导入历史记录失败: " + e.getMessage());
        }
    }

    private String getStringFromJson(JsonObject jsonObj, String key) {
        if (jsonObj.has(key) && !jsonObj.get(key).isJsonNull()) {
            return jsonObj.get(key).getAsString();
        }
        return "";
    }

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

package oxff.top.io;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * 文件格式检测器 - 自动识别导入文件格式
 */
public class FormatDetector {

    public enum ImportFormat {
        SQLITE3,
        POSTMAN_V21,
        UNKNOWN
    }

    /**
     * 检测文件格式
     */
    public static ImportFormat detectFormat(File file) {
        if (file == null || !file.exists() || !file.isFile()) {
            return ImportFormat.UNKNOWN;
        }

        String name = file.getName().toLowerCase();

        // 步骤1: 根据扩展名和文件头快速检测SQLite
        if (name.endsWith(".sqlite3") || name.endsWith(".db") || name.endsWith(".sqlite")) {
            if (isSQLiteFile(file)) {
                return ImportFormat.SQLITE3;
            }
        }

        // 步骤2: 对于.json文件或没有扩展名的文件，检查内容
        if (name.endsWith(".json") || !name.contains(".")) {
            return detectJsonFormat(file);
        }

        // 步骤3: 即使扩展名不匹配，也尝试检测SQLite魔术字节
        if (isSQLiteFile(file)) {
            return ImportFormat.SQLITE3;
        }

        // 步骤4: 尝试作为JSON解析
        return detectJsonFormat(file);
    }

    /**
     * 检测是否为SQLite文件（通过魔术字节）
     */
    private static boolean isSQLiteFile(File file) {
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] header = new byte[16];
            int read = fis.read(header);
            if (read < 16) {
                return false;
            }
            String magic = new String(header, StandardCharsets.US_ASCII);
            return magic.startsWith("SQLite format 3");
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * 检测JSON文件的具体格式
     */
    private static ImportFormat detectJsonFormat(File file) {
        try (FileInputStream fis = new FileInputStream(file);
             InputStreamReader reader = new InputStreamReader(fis, StandardCharsets.UTF_8)) {

            JsonElement rootElement = JsonParser.parseReader(reader);
            if (!rootElement.isJsonObject()) {
                return ImportFormat.UNKNOWN;
            }

            JsonObject rootObject = rootElement.getAsJsonObject();

            // 检测Postman Collection格式
            if (isPostmanCollection(rootObject)) {
                return ImportFormat.POSTMAN_V21;
            }

            // 备用检测：如果有item数组且第一个元素有request，也认为是Postman
            if (rootObject.has("item") && rootObject.get("item").isJsonArray()) {
                return ImportFormat.POSTMAN_V21;
            }

        } catch (Exception e) {
            // 不是有效的JSON
        }
        return ImportFormat.UNKNOWN;
    }

    /**
     * 判断是否为Postman Collection格式
     */
    private static boolean isPostmanCollection(JsonObject rootObject) {
        // 必须有info对象
        if (!rootObject.has("info") || !rootObject.get("info").isJsonObject()) {
            return false;
        }

        JsonObject info = rootObject.getAsJsonObject("info");

        // 检查schema字段是否包含getpostman.com
        if (info.has("schema")) {
            String schema = info.get("schema").getAsString();
            if (schema.contains("getpostman.com") || schema.contains("postman.com")) {
                return true;
            }
        }

        // 检查是否有_postman_id（Postman集合通常有）
        if (info.has("_postman_id")) {
            return true;
        }

        // 检查是否有item数组
        if (rootObject.has("item") && rootObject.get("item").isJsonArray()) {
            return true;
        }

        return false;
    }

}

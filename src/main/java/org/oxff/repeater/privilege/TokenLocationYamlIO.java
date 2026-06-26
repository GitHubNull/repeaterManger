package org.oxff.repeater.privilege;

import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.privilege.model.TokenLocation;
import org.oxff.repeater.privilege.model.TokenLocationType;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.*;

/**
 * 令牌位置YAML读写工具类
 * 用于全局令牌位置持久化
 */
public class TokenLocationYamlIO {

    private static final String YAML_VERSION = "1";

    /**
     * 将令牌位置列表序列化为YAML字符串
     *
     * @param locations 令牌位置列表
     * @return YAML格式字符串
     */
    public static String toYaml(List<TokenLocation> locations) {
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        options.setAllowUnicode(true);

        Yaml yaml = new Yaml(options);

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("version", YAML_VERSION);

        List<Map<String, Object>> locationList = new ArrayList<>();
        for (TokenLocation loc : locations) {
            Map<String, Object> locMap = new LinkedHashMap<>();
            locMap.put("type", loc.getType().name());
            locMap.put("expression", loc.getExpression());
            locMap.put("description", loc.getDescription());
            locMap.put("persistToGlobal", loc.isPersistToGlobal());
            locMap.put("enabled", loc.isEnabled());
            locationList.add(locMap);
        }
        root.put("locations", locationList);

        return yaml.dump(root);
    }

    /**
     * 从YAML字符串反序列化令牌位置列表
     *
     * @param yamlContent YAML格式字符串
     * @return 令牌位置列表，解析失败返回空列表
     */
    @SuppressWarnings("unchecked")
    public static List<TokenLocation> fromYaml(String yamlContent) {
        List<TokenLocation> locations = new ArrayList<>();
        if (yamlContent == null || yamlContent.trim().isEmpty()) {
            return locations;
        }

        try {
            Yaml yaml = new Yaml();
            Map<String, Object> root = yaml.load(yamlContent);
            if (root == null) {
                return locations;
            }

            Object locationsObj = root.get("locations");
            if (!(locationsObj instanceof List)) {
                LogManager.getInstance().printError("[!] 令牌位置YAML格式错误：缺少locations列表");
                return locations;
            }

            List<Object> locationList = (List<Object>) locationsObj;
            for (Object item : locationList) {
                if (!(item instanceof Map)) {
                    continue;
                }
                Map<String, Object> locMap = (Map<String, Object>) item;
                try {
                    TokenLocation loc = parseLocationFromMap(locMap);
                    if (loc != null) {
                        locations.add(loc);
                    }
                } catch (Exception e) {
                    LogManager.getInstance().printError("[!] 解析YAML令牌位置条目失败: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] 令牌位置YAML解析失败: " + e.getMessage());
        }
        return locations;
    }

    /**
     * 从Map解析单条令牌位置
     */
    private static TokenLocation parseLocationFromMap(Map<String, Object> map) {
        String typeStr = getStringValue(map, "type", "HEADER");
        String expression = getStringValue(map, "expression", "");
        String description = getStringValue(map, "description", "");
        boolean persistToGlobal = getBooleanValue(map, "persistToGlobal", true);
        boolean enabled = getBooleanValue(map, "enabled", true);

        if (expression.isEmpty()) {
            return null;
        }

        TokenLocation loc = new TokenLocation();
        loc.setType(TokenLocationType.fromString(typeStr));
        loc.setExpression(expression);
        loc.setDescription(description);
        loc.setPersistToGlobal(persistToGlobal);
        loc.setEnabled(enabled);
        return loc;
    }

    /**
     * 将令牌位置列表写入YAML文件（原子写入：先写临时文件再重命名）
     *
     * @param locations 令牌位置列表
     * @param filePath  目标文件路径
     * @return 是否写入成功
     */
    public static boolean writeToFile(List<TokenLocation> locations, String filePath) {
        File targetFile = new File(filePath);
        File parentDir = targetFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            if (!parentDir.mkdirs()) {
                LogManager.getInstance().printError("[!] 无法创建目录: " + parentDir.getAbsolutePath());
                return false;
            }
        }

        // 原子写入：先写临时文件
        File tempFile = new File(filePath + ".tmp");
        try (Writer writer = new OutputStreamWriter(new FileOutputStream(tempFile), StandardCharsets.UTF_8)) {
            writer.write(toYaml(locations));
            writer.flush();
        } catch (IOException e) {
            LogManager.getInstance().printError("[!] 写入令牌位置YAML临时文件失败: " + e.getMessage());
            tempFile.delete();
            return false;
        }

        // 原子替换
        try {
            Files.move(tempFile.toPath(), targetFile.toPath(), StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
            return true;
        } catch (IOException e) {
            // ATOMIC_MOVE可能在某些文件系统上不支持，回退到非原子替换
            try {
                Files.move(tempFile.toPath(), targetFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                return true;
            } catch (IOException e2) {
                LogManager.getInstance().printError("[!] 替换令牌位置YAML文件失败: " + e2.getMessage());
                tempFile.delete();
                return false;
            }
        }
    }

    /**
     * 从YAML文件读取令牌位置列表
     *
     * @param filePath YAML文件路径
     * @return 令牌位置列表，读取失败返回空列表
     */
    public static List<TokenLocation> readFromFile(String filePath) {
        File file = new File(filePath);
        if (!file.exists() || !file.canRead()) {
            return new ArrayList<>();
        }

        try (Reader reader = new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8)) {
            StringBuilder sb = new StringBuilder();
            char[] buffer = new char[4096];
            int len;
            while ((len = reader.read(buffer)) != -1) {
                sb.append(buffer, 0, len);
            }
            return fromYaml(sb.toString());
        } catch (IOException e) {
            LogManager.getInstance().printError("[!] 读取令牌位置YAML文件失败: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    // ---- 类型安全取值辅助方法 ----

    private static String getStringValue(Map<String, Object> map, String key, String defaultValue) {
        Object value = map.get(key);
        if (value == null) return defaultValue;
        return value.toString();
    }

    private static boolean getBooleanValue(Map<String, Object> map, String key, boolean defaultValue) {
        Object value = map.get(key);
        if (value == null) return defaultValue;
        if (value instanceof Boolean) return (Boolean) value;
        if (value instanceof Number) return ((Number) value).intValue() != 0;
        return defaultValue;
    }
}

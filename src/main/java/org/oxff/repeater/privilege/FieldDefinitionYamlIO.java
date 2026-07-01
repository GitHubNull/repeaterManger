package org.oxff.repeater.privilege;

import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.privilege.model.FieldDefinition;
import org.oxff.repeater.privilege.model.FieldType;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.*;

/**
 * 字段定义YAML读写工具类
 * 用于全局字段定义持久化
 */
public class FieldDefinitionYamlIO {

    private static final String YAML_VERSION = "1";

    /**
     * 将字段定义列表序列化为YAML字符串
     *
     * @param fields 字段定义列表
     * @return YAML格式字符串
     */
    public static String toYaml(List<FieldDefinition> fields) {
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        options.setAllowUnicode(true);

        Yaml yaml = new Yaml(options);

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("version", YAML_VERSION);

        List<Map<String, Object>> fieldList = new ArrayList<>();
        for (FieldDefinition field : fields) {
            Map<String, Object> fieldMap = new LinkedHashMap<>();
            fieldMap.put("type", field.getType().name());
            fieldMap.put("expression", field.getExpression());
            fieldMap.put("description", field.getDescription());
            fieldMap.put("persistToGlobal", field.isPersistToGlobal());
            fieldMap.put("enabled", field.isEnabled());
            fieldList.add(fieldMap);
        }
        root.put("fields", fieldList);

        return yaml.dump(root);
    }

    /**
     * 从YAML字符串反序列化字段定义列表
     *
     * @param yamlContent YAML格式字符串
     * @return 字段定义列表，解析失败返回空列表
     */
    @SuppressWarnings("unchecked")
    public static List<FieldDefinition> fromYaml(String yamlContent) {
        List<FieldDefinition> fields = new ArrayList<>();
        if (yamlContent == null || yamlContent.trim().isEmpty()) {
            return fields;
        }

        try {
            Yaml yaml = new Yaml();
            Map<String, Object> root = yaml.load(yamlContent);
            if (root == null) {
                return fields;
            }

            Object fieldsObj = root.get("fields");
            if (!(fieldsObj instanceof List)) {
                LogManager.getInstance().printError("[!] 字段定义YAML格式错误：缺少fields列表");
                return fields;
            }

            List<Object> fieldList = (List<Object>) fieldsObj;
            for (Object item : fieldList) {
                if (!(item instanceof Map)) {
                    continue;
                }
                Map<String, Object> fieldMap = (Map<String, Object>) item;
                try {
                    FieldDefinition field = parseFieldFromMap(fieldMap);
                    if (field != null) {
                        fields.add(field);
                    }
                } catch (Exception e) {
                    LogManager.getInstance().printError("[!] 解析YAML字段定义条目失败: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] 字段定义YAML解析失败: " + e.getMessage());
        }
        return fields;
    }

    /**
     * 从Map解析单条字段定义
     */
    private static FieldDefinition parseFieldFromMap(Map<String, Object> map) {
        String typeStr = getStringValue(map, "type", "HEADER");
        String expression = getStringValue(map, "expression", "");
        String description = getStringValue(map, "description", "");
        boolean persistToGlobal = getBooleanValue(map, "persistToGlobal", true);
        boolean enabled = getBooleanValue(map, "enabled", true);

        if (expression.isEmpty()) {
            return null;
        }

        FieldDefinition field = new FieldDefinition();
        field.setType(FieldType.fromString(typeStr));
        field.setExpression(expression);
        field.setDescription(description);
        field.setPersistToGlobal(persistToGlobal);
        field.setEnabled(enabled);
        return field;
    }

    /**
     * 将字段定义列表写入YAML文件（原子写入：先写临时文件再重命名）
     *
     * @param fields   字段定义列表
     * @param filePath 目标文件路径
     * @return 是否写入成功
     */
    public static boolean writeToFile(List<FieldDefinition> fields, String filePath) {
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
            writer.write(toYaml(fields));
            writer.flush();
        } catch (IOException e) {
            LogManager.getInstance().printError("[!] 写入字段定义YAML临时文件失败: " + e.getMessage());
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
                LogManager.getInstance().printError("[!] 替换字段定义YAML文件失败: " + e2.getMessage());
                tempFile.delete();
                return false;
            }
        }
    }

    /**
     * 从YAML文件读取字段定义列表
     *
     * @param filePath YAML文件路径
     * @return 字段定义列表，读取失败返回空列表
     */
    public static List<FieldDefinition> readFromFile(String filePath) {
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
            LogManager.getInstance().printError("[!] 读取字段定义YAML文件失败: " + e.getMessage());
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

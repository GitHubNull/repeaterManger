package org.oxff.repeater.privilege;

import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.privilege.model.FieldDefinition;
import org.oxff.repeater.privilege.model.Scheme;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.*;

/**
 * 方案YAML读写工具类
 * 用于方案数据的导入导出功能
 *
 * 字段定义使用type+expression作为标识（而非数据库ID），
 * 确保跨项目导入导出的可移植性
 */
public class SchemeYamlIO {

    private static final String YAML_VERSION = "1";

    /**
     * 将方案列表序列化为YAML字符串
     *
     * @param schemes 方案列表
     * @param fields  字段定义列表（用于将fieldId解析为type+expression）
     * @return YAML格式字符串
     */
    public static String toYaml(List<Scheme> schemes, List<FieldDefinition> fields) {
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        options.setAllowUnicode(true);

        Yaml yaml = new Yaml(options);

        // 构建ID到FieldDefinition的映射
        Map<Integer, FieldDefinition> fieldMap = new HashMap<>();
        for (FieldDefinition field : fields) {
            fieldMap.put(field.getId(), field);
        }

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("version", YAML_VERSION);

        List<Map<String, Object>> schemeList = new ArrayList<>();
        for (Scheme scheme : schemes) {
            Map<String, Object> schemeMap = new LinkedHashMap<>();
            schemeMap.put("name", scheme.getName() != null ? scheme.getName() : "");
            schemeMap.put("description", scheme.getDescription() != null ? scheme.getDescription() : "");
            schemeMap.put("persistToGlobal", scheme.isPersistToGlobal());
            schemeMap.put("enabled", scheme.isEnabled());

            // 序列化字段引用：将ID解析为type+expression
            List<Map<String, Object>> fieldRefList = new ArrayList<>();
            for (int fieldId : scheme.getFieldIds()) {
                FieldDefinition field = fieldMap.get(fieldId);
                if (field != null) {
                    Map<String, Object> fieldRefMap = new LinkedHashMap<>();
                    fieldRefMap.put("type", field.getType().name());
                    fieldRefMap.put("expression", field.getExpression());
                    fieldRefList.add(fieldRefMap);
                }
            }
            schemeMap.put("fields", fieldRefList);

            schemeList.add(schemeMap);
        }
        root.put("schemes", schemeList);

        return yaml.dump(root);
    }

    /**
     * 从YAML字符串反序列化方案列表
     *
     * @param yamlContent YAML格式字符串
     * @param fields      当前项目的字段定义列表（用于将type+expression解析为fieldId）
     * @return 方案列表，解析失败返回空列表
     */
    @SuppressWarnings("unchecked")
    public static List<Scheme> fromYaml(String yamlContent, List<FieldDefinition> fields) {
        List<Scheme> schemes = new ArrayList<>();
        if (yamlContent == null || yamlContent.trim().isEmpty()) {
            return schemes;
        }

        // 构建type|expression到fieldId的映射
        Map<String, Integer> fieldKeyToId = new HashMap<>();
        for (FieldDefinition field : fields) {
            fieldKeyToId.put(field.getType().name() + "|" + field.getExpression(), field.getId());
        }

        try {
            Yaml yaml = new Yaml();
            Map<String, Object> root = yaml.load(yamlContent);
            if (root == null) {
                return schemes;
            }

            Object schemesObj = root.get("schemes");
            if (!(schemesObj instanceof List)) {
                LogManager.getInstance().printError("[!] 方案YAML格式错误：缺少schemes列表");
                return schemes;
            }

            List<Object> schemeList = (List<Object>) schemesObj;
            for (Object item : schemeList) {
                if (!(item instanceof Map)) {
                    continue;
                }
                Map<String, Object> schemeMap = (Map<String, Object>) item;
                try {
                    Scheme scheme = parseSchemeFromMap(schemeMap, fieldKeyToId);
                    if (scheme != null) {
                        schemes.add(scheme);
                    }
                } catch (Exception e) {
                    LogManager.getInstance().printError("[!] 解析YAML方案条目失败: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] 方案YAML解析失败: " + e.getMessage());
        }
        return schemes;
    }

    /**
     * 从Map解析单条方案
     */
    @SuppressWarnings("unchecked")
    private static Scheme parseSchemeFromMap(Map<String, Object> map, Map<String, Integer> fieldKeyToId) {
        String name = getStringValue(map, "name", "");
        String description = getStringValue(map, "description", "");
        boolean persistToGlobal = getBooleanValue(map, "persistToGlobal", true);
        boolean enabled = getBooleanValue(map, "enabled", true);

        if (name.isEmpty()) {
            return null;
        }

        Scheme scheme = new Scheme();
        scheme.setName(name);
        scheme.setDescription(description);
        scheme.setPersistToGlobal(persistToGlobal);
        scheme.setEnabled(enabled);

        // 解析fields
        Object fieldsObj = map.get("fields");
        if (fieldsObj instanceof List) {
            List<Object> fieldRefList = (List<Object>) fieldsObj;
            List<Integer> fieldIds = new ArrayList<>();
            int matched = 0;
            int unmatched = 0;

            for (Object fieldRefItem : fieldRefList) {
                if (!(fieldRefItem instanceof Map)) {
                    continue;
                }
                Map<String, Object> fieldRefMap = (Map<String, Object>) fieldRefItem;
                String type = getStringValue(fieldRefMap, "type", "");
                String expression = getStringValue(fieldRefMap, "expression", "");

                String key = type + "|" + expression;
                Integer fieldId = fieldKeyToId.get(key);
                if (fieldId != null) {
                    fieldIds.add(fieldId);
                    matched++;
                } else {
                    unmatched++;
                    LogManager.getInstance().printError("[!] 导入方案时未匹配的字段: " + type + " [" + expression + "]");
                }
            }

            scheme.setFieldIds(fieldIds);

            if (unmatched > 0) {
                LogManager.getInstance().printOutput("[*] 方案 '" + name + "' 导入: " + matched + " 个字段匹配, " + unmatched + " 个未匹配（已跳过）");
            }
        }

        return scheme;
    }

    /**
     * 将方案列表写入YAML文件（原子写入）
     */
    public static boolean writeToFile(List<Scheme> schemes, List<FieldDefinition> fields, String filePath) {
        File targetFile = new File(filePath);
        File parentDir = targetFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            if (!parentDir.mkdirs()) {
                LogManager.getInstance().printError("[!] 无法创建目录: " + parentDir.getAbsolutePath());
                return false;
            }
        }

        File tempFile = new File(filePath + ".tmp");
        try (Writer writer = new OutputStreamWriter(new FileOutputStream(tempFile), StandardCharsets.UTF_8)) {
            writer.write(toYaml(schemes, fields));
            writer.flush();
        } catch (IOException e) {
            LogManager.getInstance().printError("[!] 写入方案YAML临时文件失败: " + e.getMessage());
            tempFile.delete();
            return false;
        }

        try {
            Files.move(tempFile.toPath(), targetFile.toPath(), StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
            return true;
        } catch (IOException e) {
            try {
                Files.move(tempFile.toPath(), targetFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                return true;
            } catch (IOException e2) {
                LogManager.getInstance().printError("[!] 替换方案YAML文件失败: " + e2.getMessage());
                tempFile.delete();
                return false;
            }
        }
    }

    /**
     * 从YAML文件读取方案列表
     */
    public static List<Scheme> readFromFile(String filePath, List<FieldDefinition> fields) {
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
            return fromYaml(sb.toString(), fields);
        } catch (IOException e) {
            LogManager.getInstance().printError("[!] 读取方案YAML文件失败: " + e.getMessage());
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

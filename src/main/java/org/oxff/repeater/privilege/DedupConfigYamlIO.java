package org.oxff.repeater.privilege;

import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.privilege.model.DedupConfig;
import org.oxff.repeater.privilege.model.DedupKeepPolicy;
import org.oxff.repeater.privilege.model.DedupStrategy;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.*;

/**
 * 去重配置YAML读写工具类
 * 用于全局去重配置的持久化，存储到 ~/.burp/repeater_manager/dedup_configs.yaml
 */
public class DedupConfigYamlIO {

    private static final String YAML_VERSION = "1";

    /**
     * 将去重配置列表序列化为YAML字符串
     */
    public static String toYaml(List<DedupConfig> configs) {
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        options.setAllowUnicode(true);

        Yaml yaml = new Yaml(options);

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("version", YAML_VERSION);

        List<Map<String, Object>> configList = new ArrayList<>();
        for (DedupConfig config : configs) {
            Map<String, Object> configMap = new LinkedHashMap<>();
            configMap.put("strategy", config.getStrategy().name());
            configMap.put("expression", config.getExpression());
            configMap.put("keepPolicy", config.getKeepPolicy().name());
            configMap.put("priority", config.getPriority());
            configMap.put("enabled", config.isEnabled());
            configMap.put("storageType", config.getStorageType().name());
            configList.add(configMap);
        }
        root.put("configs", configList);

        return yaml.dump(root);
    }

    /**
     * 从YAML字符串反序列化去重配置列表
     */
    @SuppressWarnings("unchecked")
    public static List<DedupConfig> fromYaml(String yamlContent) {
        List<DedupConfig> configs = new ArrayList<>();
        if (yamlContent == null || yamlContent.trim().isEmpty()) {
            return configs;
        }

        try {
            Yaml yaml = new Yaml();
            Map<String, Object> root = yaml.load(yamlContent);
            if (root == null) {
                return configs;
            }

            Object configsObj = root.get("configs");
            if (!(configsObj instanceof List)) {
                LogManager.getInstance().printError("[!] 去重配置YAML格式错误：缺少configs列表");
                return configs;
            }

            List<Object> configList = (List<Object>) configsObj;
            int idCounter = 1;
            for (Object item : configList) {
                if (!(item instanceof Map)) {
                    continue;
                }
                Map<String, Object> configMap = (Map<String, Object>) item;
                try {
                    DedupConfig config = parseConfigFromMap(configMap, idCounter++);
                    if (config != null) {
                        configs.add(config);
                    }
                } catch (Exception e) {
                    LogManager.getInstance().printError("[!] 解析YAML去重配置条目失败: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] 去重配置YAML解析失败: " + e.getMessage());
        }
        return configs;
    }

    /**
     * 从Map解析单条去重配置
     */
    private static DedupConfig parseConfigFromMap(Map<String, Object> map, int id) {
        String strategyStr = getStringValue(map, "strategy", "PATH");
        String expression = getStringValue(map, "expression", "");
        String keepPolicyStr = getStringValue(map, "keepPolicy", "FIRST");
        int priority = getIntValue(map, "priority", 10);
        boolean enabled = getBooleanValue(map, "enabled", true);
        String storageTypeStr = getStringValue(map, "storageType", "GLOBAL");

        DedupConfig config = new DedupConfig();
        config.setId(id);
        config.setStrategy(DedupStrategy.fromString(strategyStr));
        config.setExpression(expression);
        config.setKeepPolicy(DedupKeepPolicy.fromString(keepPolicyStr));
        config.setPriority(priority);
        config.setEnabled(enabled);
        config.setStorageType(DedupConfig.StorageType.fromString(storageTypeStr));
        return config;
    }

    /**
     * 将去重配置列表写入YAML文件（原子写入）
     */
    public static boolean writeToFile(List<DedupConfig> configs, String filePath) {
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
            writer.write(toYaml(configs));
            writer.flush();
        } catch (IOException e) {
            LogManager.getInstance().printError("[!] 写入去重配置YAML临时文件失败: " + e.getMessage());
            tempFile.delete();
            return false;
        }

        // 原子替换
        try {
            Files.move(tempFile.toPath(), targetFile.toPath(), StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
            return true;
        } catch (IOException e) {
            try {
                Files.move(tempFile.toPath(), targetFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                return true;
            } catch (IOException e2) {
                LogManager.getInstance().printError("[!] 替换去重配置YAML文件失败: " + e2.getMessage());
                tempFile.delete();
                return false;
            }
        }
    }

    /**
     * 从YAML文件读取去重配置列表
     */
    public static List<DedupConfig> readFromFile(String filePath) {
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
            LogManager.getInstance().printError("[!] 读取去重配置YAML文件失败: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    // ---- 类型安全取值辅助方法 ----

    private static String getStringValue(Map<String, Object> map, String key, String defaultValue) {
        Object value = map.get(key);
        if (value == null) return defaultValue;
        return value.toString();
    }

    private static int getIntValue(Map<String, Object> map, String key, int defaultValue) {
        Object value = map.get(key);
        if (value == null) return defaultValue;
        if (value instanceof Number) return ((Number) value).intValue();
        try {
            return Integer.parseInt(value.toString());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private static boolean getBooleanValue(Map<String, Object> map, String key, boolean defaultValue) {
        Object value = map.get(key);
        if (value == null) return defaultValue;
        if (value instanceof Boolean) return (Boolean) value;
        if (value instanceof Number) return ((Number) value).intValue() != 0;
        return defaultValue;
    }
}

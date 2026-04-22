package oxff.top.api;

import burp.BurpExtender;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.*;

/**
 * API提取规则YAML读写工具类
 * 用于全局规则持久化和导入导出功能
 */
public class ApiRuleYamlIO {

    private static final String YAML_VERSION = "1";

    /**
     * 将规则列表导出为YAML字符串
     *
     * @param rules 规则列表
     * @return YAML格式字符串
     */
    public static String toYaml(List<ApiExtractionRule> rules) {
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        options.setAllowUnicode(true);

        Yaml yaml = new Yaml(options);

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("version", YAML_VERSION);

        List<Map<String, Object>> ruleList = new ArrayList<>();
        for (ApiExtractionRule rule : rules) {
            Map<String, Object> ruleMap = new LinkedHashMap<>();
            ruleMap.put("name", rule.getName());
            ruleMap.put("source", rule.getSource().toDbValue());
            ruleMap.put("method", rule.getMethod().toDbValue());
            ruleMap.put("expression", rule.getExpression());
            ruleMap.put("enabled", rule.isEnabled());
            ruleMap.put("priority", rule.getPriority());
            ruleMap.put("remark", rule.getRemark());
            ruleList.add(ruleMap);
        }
        root.put("rules", ruleList);

        return yaml.dump(root);
    }

    /**
     * 从YAML字符串解析规则列表
     *
     * @param yamlContent YAML格式字符串
     * @return 规则列表，解析失败返回空列表
     */
    @SuppressWarnings("unchecked")
    public static List<ApiExtractionRule> fromYaml(String yamlContent) {
        List<ApiExtractionRule> rules = new ArrayList<>();
        if (yamlContent == null || yamlContent.trim().isEmpty()) {
            return rules;
        }

        try {
            Yaml yaml = new Yaml();
            Map<String, Object> root = yaml.load(yamlContent);
            if (root == null) {
                return rules;
            }

            Object rulesObj = root.get("rules");
            if (!(rulesObj instanceof List)) {
                BurpExtender.printError("[!] YAML格式错误：缺少rules列表");
                return rules;
            }

            List<Object> ruleList = (List<Object>) rulesObj;
            for (Object item : ruleList) {
                if (!(item instanceof Map)) {
                    continue;
                }
                Map<String, Object> ruleMap = (Map<String, Object>) item;
                try {
                    ApiExtractionRule rule = parseRuleFromMap(ruleMap);
                    if (rule != null) {
                        rules.add(rule);
                    }
                } catch (Exception e) {
                    BurpExtender.printError("[!] 解析YAML规则条目失败: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] YAML解析失败: " + e.getMessage());
        }
        return rules;
    }

    /**
     * 从Map解析单条规则
     */
    private static ApiExtractionRule parseRuleFromMap(Map<String, Object> map) {
        String name = getStringValue(map, "name", "");
        String sourceStr = getStringValue(map, "source", "URL_PATH");
        String methodStr = getStringValue(map, "method", "REGEX");
        String expression = getStringValue(map, "expression", "");
        boolean enabled = getBooleanValue(map, "enabled", true);
        int priority = getIntValue(map, "priority", 1);
        String remark = getStringValue(map, "remark", "");

        if (expression.isEmpty()) {
            return null;
        }

        ApiExtractionRule rule = new ApiExtractionRule();
        rule.setName(name);
        rule.setSource(ApiRuleSource.fromDbValue(sourceStr));
        rule.setMethod(ApiRuleMethod.fromDbValue(methodStr));
        rule.setExpression(expression);
        rule.setEnabled(enabled);
        rule.setPriority(priority);
        rule.setRemark(remark);
        return rule;
    }

    /**
     * 将规则列表写入YAML文件（原子写入：先写临时文件再重命名）
     *
     * @param rules 规则列表
     * @param filePath 目标文件路径
     * @return 是否写入成功
     */
    public static boolean writeToFile(List<ApiExtractionRule> rules, String filePath) {
        File targetFile = new File(filePath);
        File parentDir = targetFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            if (!parentDir.mkdirs()) {
                BurpExtender.printError("[!] 无法创建目录: " + parentDir.getAbsolutePath());
                return false;
            }
        }

        // 原子写入：先写临时文件
        File tempFile = new File(filePath + ".tmp");
        try (Writer writer = new OutputStreamWriter(new FileOutputStream(tempFile), StandardCharsets.UTF_8)) {
            writer.write(toYaml(rules));
            writer.flush();
        } catch (IOException e) {
            BurpExtender.printError("[!] 写入YAML临时文件失败: " + e.getMessage());
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
                BurpExtender.printError("[!] 替换YAML文件失败: " + e2.getMessage());
                tempFile.delete();
                return false;
            }
        }
    }

    /**
     * 从YAML文件读取规则列表
     *
     * @param filePath YAML文件路径
     * @return 规则列表，读取失败返回空列表
     */
    public static List<ApiExtractionRule> readFromFile(String filePath) {
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
            BurpExtender.printError("[!] 读取YAML文件失败: " + e.getMessage());
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
}

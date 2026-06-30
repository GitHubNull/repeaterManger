package org.oxff.repeater.privilege;

import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.privilege.model.JudgmentRule;
import org.oxff.repeater.privilege.model.RuleCondition;
import org.oxff.repeater.privilege.model.RuleMethod;
import org.oxff.repeater.privilege.model.RuleTarget;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.*;

/**
 * 判决规则YAML读写工具类
 * 用于规则导入导出功能
 */
public class JudgmentRuleYamlIO {

    private static final String YAML_VERSION = "2";

    /**
     * 将规则列表导出为YAML字符串
     */
    public static String toYaml(List<JudgmentRule> rules) {
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        options.setAllowUnicode(true);

        Yaml yaml = new Yaml(options);

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("version", YAML_VERSION);

        List<Map<String, Object>> ruleList = new ArrayList<>();
        for (JudgmentRule rule : rules) {
            Map<String, Object> ruleMap = new LinkedHashMap<>();
            ruleMap.put("name", rule.getName() != null ? rule.getName() : "");
            ruleMap.put("is_active", rule.isActive());
            ruleMap.put("enabled", rule.isEnabled());
            ruleMap.put("success_color", rule.getSuccessColorHex());
            ruleMap.put("failure_color", rule.getFailureColorHex());
            ruleMap.put("success_note", rule.getSuccessNote());
            ruleMap.put("failure_note", rule.getFailureNote());
            ruleMap.put("remark", rule.getRemark());

            // 序列化 conditions（v13：不输出 operator）
            List<RuleCondition> conditions = rule.getEffectiveConditions();
            if (conditions != null && !conditions.isEmpty()) {
                List<Map<String, Object>> condList = new ArrayList<>();
                for (RuleCondition cond : conditions) {
                    Map<String, Object> condMap = new LinkedHashMap<>();
                    condMap.put("target", cond.getTarget() != null ? cond.getTarget().name() : "");
                    condMap.put("method", cond.getMethod() != null ? cond.getMethod().name() : "");
                    condMap.put("expression", cond.getExpression() != null ? cond.getExpression() : "");
                    condMap.put("negate", cond.isNegate());
                    condList.add(condMap);
                }
                ruleMap.put("conditions", condList);
            }

            ruleList.add(ruleMap);
        }
        root.put("judgment_rule_groups", ruleList);

        return yaml.dump(root);
    }

    /**
     * 从YAML字符串解析规则列表（v13：仅支持新格式）
     */
    @SuppressWarnings("unchecked")
    public static List<JudgmentRule> fromYaml(String yamlContent) {
        List<JudgmentRule> rules = new ArrayList<>();
        if (yamlContent == null || yamlContent.trim().isEmpty()) {
            return rules;
        }

        try {
            Yaml yaml = new Yaml();
            Map<String, Object> root = yaml.load(yamlContent);
            if (root == null) return rules;

            Object rulesObj = root.get("judgment_rule_groups");
            if (!(rulesObj instanceof List)) {
                LogManager.getInstance().printError("[!] YAML格式错误：缺少judgment_rule_groups列表");
                return rules;
            }

            List<Object> ruleList = (List<Object>) rulesObj;
            for (Object item : ruleList) {
                if (!(item instanceof Map)) continue;
                Map<String, Object> ruleMap = (Map<String, Object>) item;
                try {
                    JudgmentRule rule = parseRuleFromMap(ruleMap);
                    if (rule != null) {
                        rules.add(rule);
                    }
                } catch (Exception e) {
                    LogManager.getInstance().printError("[!] 解析YAML规则条目失败: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] YAML解析失败: " + e.getMessage());
        }
        return rules;
    }

    /**
     * 从Map解析单条规则（v13 新格式）
     */
    private static JudgmentRule parseRuleFromMap(Map<String, Object> map) {
        String name = getStringValue(map, "name", "");
        boolean enabled = getBooleanValue(map, "enabled", true);
        boolean isActive = getBooleanValue(map, "is_active", false);
        String successColor = getStringValue(map, "success_color", "#FF0000");
        String failureColor = getStringValue(map, "failure_color", "#90EE90");
        String successNote = getStringValue(map, "success_note", "");
        String failureNote = getStringValue(map, "failure_note", "");
        String remark = getStringValue(map, "remark", "");

        // 解析 conditions
        List<RuleCondition> conditions = new ArrayList<>();
        Object conditionsObj = map.get("conditions");
        if (conditionsObj instanceof List) {
            @SuppressWarnings("unchecked")
            List<Object> condList = (List<Object>) conditionsObj;
            for (Object item : condList) {
                if (item instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> condMap = (Map<String, Object>) item;
                    RuleCondition cond = new RuleCondition();
                    cond.setTarget(RuleTarget.fromString(getStringValue(condMap, "target", "STATUS_CODE")));
                    cond.setMethod(RuleMethod.fromString(getStringValue(condMap, "method", "REGEX")));
                    cond.setExpression(getStringValue(condMap, "expression", ""));
                    cond.setNegate(getBooleanValue(condMap, "negate", false));
                    if (cond.isValid()) {
                        conditions.add(cond);
                    }
                }
            }
        }

        if (conditions.isEmpty()) return null;

        JudgmentRule rule = new JudgmentRule();
        rule.setName(name);
        rule.setEnabled(enabled);
        rule.setActive(isActive);
        rule.setSuccessColor(JudgmentRule.hexToColor(successColor));
        rule.setFailureColor(JudgmentRule.hexToColor(failureColor));
        rule.setSuccessNote(successNote);
        rule.setFailureNote(failureNote);
        rule.setRemark(remark);
        rule.setConditions(conditions);

        return rule;
    }

    /**
     * 将规则列表写入YAML文件（原子写入）
     */
    public static boolean writeToFile(List<JudgmentRule> rules, String filePath) {
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
            writer.write(toYaml(rules));
            writer.flush();
        } catch (IOException e) {
            LogManager.getInstance().printError("[!] 写入YAML临时文件失败: " + e.getMessage());
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
                LogManager.getInstance().printError("[!] 替换YAML文件失败: " + e2.getMessage());
                tempFile.delete();
                return false;
            }
        }
    }

    /**
     * 从YAML文件读取规则列表
     */
    public static List<JudgmentRule> readFromFile(String filePath) {
        File file = new File(filePath);
        if (!file.exists() || !file.canRead()) return new ArrayList<>();

        try (Reader reader = new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8)) {
            StringBuilder sb = new StringBuilder();
            char[] buffer = new char[4096];
            int len;
            while ((len = reader.read(buffer)) != -1) {
                sb.append(buffer, 0, len);
            }
            return fromYaml(sb.toString());
        } catch (IOException e) {
            LogManager.getInstance().printError("[!] 读取YAML文件失败: " + e.getMessage());
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

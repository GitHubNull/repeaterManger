package org.oxff.repeater.privilege;

import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.privilege.model.FieldDefinition;
import org.oxff.repeater.privilege.model.Scheme;
import org.oxff.repeater.privilege.model.UserSession;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.*;

/**
 * 用户会话YAML读写工具类
 * 用于用户会话数据的导入导出功能
 *
 * field_values使用type+expression作为键（而非数据库ID），
 * 确保跨项目导入导出的可移植性
 */
public class UserSessionYamlIO {

    private static final String YAML_VERSION = "1";

    /**
     * 将用户会话列表序列化为YAML字符串
     *
     * @param sessions  用户会话列表
     * @param locations 字段定义列表（用于将fieldId解析为type+expression）
     * @param schemes   方案列表（用于将schemeId解析为方案名称）
     * @return YAML格式字符串
     */
    public static String toYaml(List<UserSession> sessions, List<FieldDefinition> locations, List<Scheme> schemes) {
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        options.setAllowUnicode(true);

        Yaml yaml = new Yaml(options);

        // 构建ID到FieldDefinition的映射
        Map<Integer, FieldDefinition> locationMap = new HashMap<>();
        for (FieldDefinition loc : locations) {
            locationMap.put(loc.getId(), loc);
        }

        // 构建ID到Scheme名称的映射
        Map<Integer, String> schemeNameMap = new HashMap<>();
        for (Scheme scheme : schemes) {
            schemeNameMap.put(scheme.getId(), scheme.getName());
        }

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("version", YAML_VERSION);

        List<Map<String, Object>> sessionList = new ArrayList<>();
        for (UserSession session : sessions) {
            Map<String, Object> sessionMap = new LinkedHashMap<>();
            sessionMap.put("name", session.getName() != null ? session.getName() : "");
            sessionMap.put("color", session.getColorHex() != null ? session.getColorHex() : "");
            sessionMap.put("enabled", session.isEnabled());

            // 方案名称
            if (session.getSchemeId() != null) {
                String schemeName = schemeNameMap.get(session.getSchemeId());
                if (schemeName != null) {
                    sessionMap.put("scheme_name", schemeName);
                }
            }

            // 重放配置
            Map<String, Object> replayMap = new LinkedHashMap<>();
            replayMap.put("request_timeout", session.getRequestTimeout());
            replayMap.put("max_concurrent", session.getMaxConcurrent());
            replayMap.put("retry_count", session.getRetryCount());
            replayMap.put("retry_delay", session.getRetryDelay());
            replayMap.put("replay_delay", session.getReplayDelay());
            sessionMap.put("replay_config", replayMap);

            // 序列化field_values：将ID映射的字段值转换为type+expression格式
            List<Map<String, Object>> fieldValuesList = new ArrayList<>();
            for (Map.Entry<Integer, String> entry : session.getFieldValues().entrySet()) {
                FieldDefinition loc = locationMap.get(entry.getKey());
                if (loc != null) {
                    Map<String, Object> tvMap = new LinkedHashMap<>();
                    tvMap.put("type", loc.getType().name());
                    tvMap.put("expression", loc.getExpression());
                    tvMap.put("value", entry.getValue() != null ? entry.getValue() : "");
                    fieldValuesList.add(tvMap);
                }
            }
            sessionMap.put("field_values", fieldValuesList);

            sessionList.add(sessionMap);
        }
        root.put("user_sessions", sessionList);

        return yaml.dump(root);
    }

    /**
     * 从YAML字符串反序列化用户会话列表
     *
     * @param yamlContent YAML格式字符串
     * @param locations   当前项目的字段定义列表（用于将type+expression解析为fieldId）
     * @param schemes     当前项目的方案列表（用于将scheme_name解析为schemeId）
     * @return 用户会话列表，解析失败返回空列表
     */
    @SuppressWarnings("unchecked")
    public static List<UserSession> fromYaml(String yamlContent, List<FieldDefinition> locations, List<Scheme> schemes) {
        List<UserSession> sessions = new ArrayList<>();
        if (yamlContent == null || yamlContent.trim().isEmpty()) {
            return sessions;
        }

        // 构建type|expression到fieldId的映射
        Map<String, Integer> locationKeyToId = new HashMap<>();
        for (FieldDefinition loc : locations) {
            locationKeyToId.put(loc.getType().name() + "|" + loc.getExpression(), loc.getId());
        }

        // 构建方案名称到schemeId的映射
        Map<String, Integer> schemeNameToId = new HashMap<>();
        for (Scheme scheme : schemes) {
            schemeNameToId.put(scheme.getName(), scheme.getId());
        }

        try {
            Yaml yaml = new Yaml();
            Map<String, Object> root = yaml.load(yamlContent);
            if (root == null) {
                return sessions;
            }

            // 支持 "user_sessions" 或 "sessions" 作为键
            Object sessionsObj = root.get("user_sessions");
            if (sessionsObj == null) {
                sessionsObj = root.get("sessions");
            }
            if (!(sessionsObj instanceof List)) {
                LogManager.getInstance().printError("[!] 用户会话YAML格式错误：缺少user_sessions列表");
                return sessions;
            }

            List<Object> sessionList = (List<Object>) sessionsObj;
            for (Object item : sessionList) {
                if (!(item instanceof Map)) {
                    continue;
                }
                Map<String, Object> sessionMap = (Map<String, Object>) item;
                try {
                    UserSession session = parseSessionFromMap(sessionMap, locationKeyToId, schemeNameToId);
                    if (session != null) {
                        sessions.add(session);
                    }
                } catch (Exception e) {
                    LogManager.getInstance().printError("[!] 解析YAML用户会话条目失败: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] 用户会话YAML解析失败: " + e.getMessage());
        }
        return sessions;
    }

    /**
     * 从Map解析单条用户会话
     */
    @SuppressWarnings("unchecked")
    private static UserSession parseSessionFromMap(Map<String, Object> map, Map<String, Integer> locationKeyToId,
                                                   Map<String, Integer> schemeNameToId) {
        String name = getStringValue(map, "name", "");
        String colorHex = getStringValue(map, "color", "");
        boolean enabled = getBooleanValue(map, "enabled", true);

        if (name.isEmpty()) {
            return null;
        }

        UserSession session = new UserSession();
        session.setName(name);
        session.setColorHex(colorHex);
        session.setEnabled(enabled);

        // 解析scheme_name
        String schemeName = getStringValue(map, "scheme_name", "");
        if (!schemeName.isEmpty()) {
            Integer schemeId = schemeNameToId.get(schemeName);
            if (schemeId != null) {
                session.setSchemeId(schemeId);
            } else {
                LogManager.getInstance().printOutput("[*] 用户会话 '" + name + "' 引用的方案 '" + schemeName + "' 不存在，跳过关联");
            }
        }

        // 解析replay_config
        Object replayConfigObj = map.get("replay_config");
        if (replayConfigObj instanceof Map) {
            Map<String, Object> replayMap = (Map<String, Object>) replayConfigObj;
            session.setRequestTimeout(getIntValue(replayMap, "request_timeout", 30));
            session.setMaxConcurrent(getIntValue(replayMap, "max_concurrent", 1));
            session.setRetryCount(getIntValue(replayMap, "retry_count", 0));
            session.setRetryDelay(getIntValue(replayMap, "retry_delay", 1000));
            session.setReplayDelay(getIntValue(replayMap, "replay_delay", 0));
        }

        // 解析field_values
        Object fieldValuesObj = map.get("field_values");
        if (fieldValuesObj instanceof List) {
            List<Object> tvList = (List<Object>) fieldValuesObj;
            Map<Integer, String> fieldValues = new LinkedHashMap<>();
            int matched = 0;
            int unmatched = 0;

            for (Object tvItem : tvList) {
                if (!(tvItem instanceof Map)) {
                    continue;
                }
                Map<String, Object> tvMap = (Map<String, Object>) tvItem;
                String type = getStringValue(tvMap, "type", "");
                String expression = getStringValue(tvMap, "expression", "");
                String value = getStringValue(tvMap, "value", "");

                String key = type + "|" + expression;
                Integer locationId = locationKeyToId.get(key);
                if (locationId != null) {
                    fieldValues.put(locationId, value);
                    matched++;
                } else {
                    unmatched++;
                    LogManager.getInstance().printError("[!] 导入用户会话时未匹配的字段定义: " + type + " [" + expression + "]");
                }
            }
            
            session.setFieldValues(fieldValues);
            
            if (unmatched > 0) {
                LogManager.getInstance().printOutput("[*] 用户会话 '" + name + "' 导入: " + matched + " 个字段值匹配, " + unmatched + " 个未匹配（已跳过）");
            }
        }

        return session;
    }

    /**
     * 将用户会话列表写入YAML文件（原子写入：先写临时文件再重命名）
     *
     * @param sessions  用户会话列表
     * @param locations 字段定义列表
     * @param filePath  目标文件路径
     * @return 是否写入成功
     */
    public static boolean writeToFile(List<UserSession> sessions, List<FieldDefinition> locations,
                                      List<Scheme> schemes, String filePath) {
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
            writer.write(toYaml(sessions, locations, schemes));
            writer.flush();
        } catch (IOException e) {
            LogManager.getInstance().printError("[!] 写入用户会话YAML临时文件失败: " + e.getMessage());
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
                LogManager.getInstance().printError("[!] 替换用户会话YAML文件失败: " + e2.getMessage());
                tempFile.delete();
                return false;
            }
        }
    }

    /**
     * 从YAML文件读取用户会话列表
     *
     * @param filePath  YAML文件路径
     * @param locations 当前项目的字段定义列表
     * @return 用户会话列表，读取失败返回空列表
     */
    public static List<UserSession> readFromFile(String filePath, List<FieldDefinition> locations,
                                                 List<Scheme> schemes) {
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
            return fromYaml(sb.toString(), locations, schemes);
        } catch (IOException e) {
            LogManager.getInstance().printError("[!] 读取用户会话YAML文件失败: " + e.getMessage());
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

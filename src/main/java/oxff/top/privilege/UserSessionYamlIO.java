package oxff.top.privilege;

import burp.BurpExtender;
import oxff.top.privilege.model.TokenLocation;
import oxff.top.privilege.model.UserSession;
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
 * token_values使用type+expression作为键（而非数据库ID），
 * 确保跨项目导入导出的可移植性
 */
public class UserSessionYamlIO {

    private static final String YAML_VERSION = "1";

    /**
     * 将用户会话列表序列化为YAML字符串
     *
     * @param sessions  用户会话列表
     * @param locations 令牌位置列表（用于将tokenLocationId解析为type+expression）
     * @return YAML格式字符串
     */
    public static String toYaml(List<UserSession> sessions, List<TokenLocation> locations) {
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        options.setAllowUnicode(true);

        Yaml yaml = new Yaml(options);

        // 构建ID到TokenLocation的映射
        Map<Integer, TokenLocation> locationMap = new HashMap<>();
        for (TokenLocation loc : locations) {
            locationMap.put(loc.getId(), loc);
        }

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("version", YAML_VERSION);

        List<Map<String, Object>> sessionList = new ArrayList<>();
        for (UserSession session : sessions) {
            Map<String, Object> sessionMap = new LinkedHashMap<>();
            sessionMap.put("name", session.getName() != null ? session.getName() : "");
            sessionMap.put("color", session.getColorHex() != null ? session.getColorHex() : "");
            sessionMap.put("enabled", session.isEnabled());

            // 序列化token_values：将ID映射的token值转换为type+expression格式
            List<Map<String, Object>> tokenValuesList = new ArrayList<>();
            for (Map.Entry<Integer, String> entry : session.getTokenValues().entrySet()) {
                TokenLocation loc = locationMap.get(entry.getKey());
                if (loc != null) {
                    Map<String, Object> tvMap = new LinkedHashMap<>();
                    tvMap.put("type", loc.getType().name());
                    tvMap.put("expression", loc.getExpression());
                    tvMap.put("value", entry.getValue() != null ? entry.getValue() : "");
                    tokenValuesList.add(tvMap);
                }
            }
            sessionMap.put("token_values", tokenValuesList);

            sessionList.add(sessionMap);
        }
        root.put("user_sessions", sessionList);

        return yaml.dump(root);
    }

    /**
     * 从YAML字符串反序列化用户会话列表
     *
     * @param yamlContent YAML格式字符串
     * @param locations   当前项目的令牌位置列表（用于将type+expression解析为tokenLocationId）
     * @return 用户会话列表，解析失败返回空列表
     */
    @SuppressWarnings("unchecked")
    public static List<UserSession> fromYaml(String yamlContent, List<TokenLocation> locations) {
        List<UserSession> sessions = new ArrayList<>();
        if (yamlContent == null || yamlContent.trim().isEmpty()) {
            return sessions;
        }

        // 构建type|expression到tokenLocationId的映射
        Map<String, Integer> locationKeyToId = new HashMap<>();
        for (TokenLocation loc : locations) {
            locationKeyToId.put(loc.getType().name() + "|" + loc.getExpression(), loc.getId());
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
                BurpExtender.printError("[!] 用户会话YAML格式错误：缺少user_sessions列表");
                return sessions;
            }

            List<Object> sessionList = (List<Object>) sessionsObj;
            for (Object item : sessionList) {
                if (!(item instanceof Map)) {
                    continue;
                }
                Map<String, Object> sessionMap = (Map<String, Object>) item;
                try {
                    UserSession session = parseSessionFromMap(sessionMap, locationKeyToId);
                    if (session != null) {
                        sessions.add(session);
                    }
                } catch (Exception e) {
                    BurpExtender.printError("[!] 解析YAML用户会话条目失败: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 用户会话YAML解析失败: " + e.getMessage());
        }
        return sessions;
    }

    /**
     * 从Map解析单条用户会话
     */
    @SuppressWarnings("unchecked")
    private static UserSession parseSessionFromMap(Map<String, Object> map, Map<String, Integer> locationKeyToId) {
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

        // 解析token_values
        Object tokenValuesObj = map.get("token_values");
        if (tokenValuesObj instanceof List) {
            List<Object> tvList = (List<Object>) tokenValuesObj;
            Map<Integer, String> tokenValues = new LinkedHashMap<>();
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
                    tokenValues.put(locationId, value);
                    matched++;
                } else {
                    unmatched++;
                    BurpExtender.printError("[!] 导入用户会话时未匹配的令牌位置: " + type + " [" + expression + "]");
                }
            }

            session.setTokenValues(tokenValues);

            if (unmatched > 0) {
                BurpExtender.printOutput("[*] 用户会话 '" + name + "' 导入: " + matched + " 个令牌值匹配, " + unmatched + " 个未匹配（已跳过）");
            }
        }

        return session;
    }

    /**
     * 将用户会话列表写入YAML文件（原子写入：先写临时文件再重命名）
     *
     * @param sessions  用户会话列表
     * @param locations 令牌位置列表
     * @param filePath  目标文件路径
     * @return 是否写入成功
     */
    public static boolean writeToFile(List<UserSession> sessions, List<TokenLocation> locations, String filePath) {
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
            writer.write(toYaml(sessions, locations));
            writer.flush();
        } catch (IOException e) {
            BurpExtender.printError("[!] 写入用户会话YAML临时文件失败: " + e.getMessage());
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
                BurpExtender.printError("[!] 替换用户会话YAML文件失败: " + e2.getMessage());
                tempFile.delete();
                return false;
            }
        }
    }

    /**
     * 从YAML文件读取用户会话列表
     *
     * @param filePath  YAML文件路径
     * @param locations 当前项目的令牌位置列表
     * @return 用户会话列表，读取失败返回空列表
     */
    public static List<UserSession> readFromFile(String filePath, List<TokenLocation> locations) {
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
            return fromYaml(sb.toString(), locations);
        } catch (IOException e) {
            BurpExtender.printError("[!] 读取用户会话YAML文件失败: " + e.getMessage());
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

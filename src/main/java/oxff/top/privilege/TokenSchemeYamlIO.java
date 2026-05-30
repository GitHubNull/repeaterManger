package oxff.top.privilege;

import burp.BurpExtender;
import oxff.top.privilege.model.TokenLocation;
import oxff.top.privilege.model.TokenScheme;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.*;

/**
 * 令牌方案YAML读写工具类
 * 用于令牌方案数据的导入导出功能
 *
 * 令牌位置使用type+expression作为标识（而非数据库ID），
 * 确保跨项目导入导出的可移植性
 */
public class TokenSchemeYamlIO {

    private static final String YAML_VERSION = "1";

    /**
     * 将令牌方案列表序列化为YAML字符串
     *
     * @param schemes   令牌方案列表
     * @param locations 令牌位置列表（用于将tokenLocationId解析为type+expression）
     * @return YAML格式字符串
     */
    public static String toYaml(List<TokenScheme> schemes, List<TokenLocation> locations) {
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

        List<Map<String, Object>> schemeList = new ArrayList<>();
        for (TokenScheme scheme : schemes) {
            Map<String, Object> schemeMap = new LinkedHashMap<>();
            schemeMap.put("name", scheme.getName() != null ? scheme.getName() : "");
            schemeMap.put("description", scheme.getDescription() != null ? scheme.getDescription() : "");
            schemeMap.put("persistToGlobal", scheme.isPersistToGlobal());
            schemeMap.put("enabled", scheme.isEnabled());

            // 序列化令牌位置引用：将ID解析为type+expression
            List<Map<String, Object>> tokenLocList = new ArrayList<>();
            for (int locId : scheme.getTokenLocationIds()) {
                TokenLocation loc = locationMap.get(locId);
                if (loc != null) {
                    Map<String, Object> locMap = new LinkedHashMap<>();
                    locMap.put("type", loc.getType().name());
                    locMap.put("expression", loc.getExpression());
                    tokenLocList.add(locMap);
                }
            }
            schemeMap.put("token_locations", tokenLocList);

            schemeList.add(schemeMap);
        }
        root.put("token_schemes", schemeList);

        return yaml.dump(root);
    }

    /**
     * 从YAML字符串反序列化令牌方案列表
     *
     * @param yamlContent YAML格式字符串
     * @param locations   当前项目的令牌位置列表（用于将type+expression解析为tokenLocationId）
     * @return 令牌方案列表，解析失败返回空列表
     */
    @SuppressWarnings("unchecked")
    public static List<TokenScheme> fromYaml(String yamlContent, List<TokenLocation> locations) {
        List<TokenScheme> schemes = new ArrayList<>();
        if (yamlContent == null || yamlContent.trim().isEmpty()) {
            return schemes;
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
                return schemes;
            }

            Object schemesObj = root.get("token_schemes");
            if (schemesObj == null) {
                schemesObj = root.get("schemes");
            }
            if (!(schemesObj instanceof List)) {
                BurpExtender.printError("[!] 令牌方案YAML格式错误：缺少token_schemes列表");
                return schemes;
            }

            List<Object> schemeList = (List<Object>) schemesObj;
            for (Object item : schemeList) {
                if (!(item instanceof Map)) {
                    continue;
                }
                Map<String, Object> schemeMap = (Map<String, Object>) item;
                try {
                    TokenScheme scheme = parseSchemeFromMap(schemeMap, locationKeyToId);
                    if (scheme != null) {
                        schemes.add(scheme);
                    }
                } catch (Exception e) {
                    BurpExtender.printError("[!] 解析YAML令牌方案条目失败: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 令牌方案YAML解析失败: " + e.getMessage());
        }
        return schemes;
    }

    /**
     * 从Map解析单条令牌方案
     */
    @SuppressWarnings("unchecked")
    private static TokenScheme parseSchemeFromMap(Map<String, Object> map, Map<String, Integer> locationKeyToId) {
        String name = getStringValue(map, "name", "");
        String description = getStringValue(map, "description", "");
        boolean persistToGlobal = getBooleanValue(map, "persistToGlobal", true);
        boolean enabled = getBooleanValue(map, "enabled", true);

        if (name.isEmpty()) {
            return null;
        }

        TokenScheme scheme = new TokenScheme();
        scheme.setName(name);
        scheme.setDescription(description);
        scheme.setPersistToGlobal(persistToGlobal);
        scheme.setEnabled(enabled);

        // 解析token_locations
        Object tokenLocsObj = map.get("token_locations");
        if (tokenLocsObj instanceof List) {
            List<Object> locList = (List<Object>) tokenLocsObj;
            List<Integer> locationIds = new ArrayList<>();
            int matched = 0;
            int unmatched = 0;

            for (Object locItem : locList) {
                if (!(locItem instanceof Map)) {
                    continue;
                }
                Map<String, Object> locMap = (Map<String, Object>) locItem;
                String type = getStringValue(locMap, "type", "");
                String expression = getStringValue(locMap, "expression", "");

                String key = type + "|" + expression;
                Integer locationId = locationKeyToId.get(key);
                if (locationId != null) {
                    locationIds.add(locationId);
                    matched++;
                } else {
                    unmatched++;
                    BurpExtender.printError("[!] 导入令牌方案时未匹配的令牌位置: " + type + " [" + expression + "]");
                }
            }

            scheme.setTokenLocationIds(locationIds);

            if (unmatched > 0) {
                BurpExtender.printOutput("[*] 令牌方案 '" + name + "' 导入: " + matched + " 个令牌位置匹配, " + unmatched + " 个未匹配（已跳过）");
            }
        }

        return scheme;
    }

    /**
     * 将令牌方案列表写入YAML文件（原子写入）
     */
    public static boolean writeToFile(List<TokenScheme> schemes, List<TokenLocation> locations, String filePath) {
        File targetFile = new File(filePath);
        File parentDir = targetFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            if (!parentDir.mkdirs()) {
                BurpExtender.printError("[!] 无法创建目录: " + parentDir.getAbsolutePath());
                return false;
            }
        }

        File tempFile = new File(filePath + ".tmp");
        try (Writer writer = new OutputStreamWriter(new FileOutputStream(tempFile), StandardCharsets.UTF_8)) {
            writer.write(toYaml(schemes, locations));
            writer.flush();
        } catch (IOException e) {
            BurpExtender.printError("[!] 写入令牌方案YAML临时文件失败: " + e.getMessage());
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
                BurpExtender.printError("[!] 替换令牌方案YAML文件失败: " + e2.getMessage());
                tempFile.delete();
                return false;
            }
        }
    }

    /**
     * 从YAML文件读取令牌方案列表
     */
    public static List<TokenScheme> readFromFile(String filePath, List<TokenLocation> locations) {
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
            BurpExtender.printError("[!] 读取令牌方案YAML文件失败: " + e.getMessage());
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

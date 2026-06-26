package org.oxff.repeater.privilege;

import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.privilege.model.TokenLocation;
import org.oxff.repeater.privilege.model.TokenScheme;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * 全局令牌方案管理器（单例）
 * 管理保存在 ~/.burp/repeater_manager/token_schemes.yaml 中的全局令牌方案
 * 全局令牌方案可被任何新项目自动加载
 */
public class GlobalTokenSchemeManager {
    private static GlobalTokenSchemeManager instance;

    private static final String GLOBAL_DIR_NAME = ".burp" + File.separator + "repeater_manager";
    private static final String GLOBAL_SCHEMES_FILE = "token_schemes.yaml";

    private final String globalSchemesPath;
    private List<TokenScheme> globalSchemes;

    private GlobalTokenSchemeManager() {
        String userHome = System.getProperty("user.home");
        this.globalSchemesPath = userHome + File.separator + GLOBAL_DIR_NAME + File.separator + GLOBAL_SCHEMES_FILE;
        this.globalSchemes = new ArrayList<>();
    }

    /**
     * 获取单例实例
     */
    public static synchronized GlobalTokenSchemeManager getInstance() {
        if (instance == null) {
            instance = new GlobalTokenSchemeManager();
        }
        return instance;
    }

    /**
     * 获取全局令牌方案文件路径
     */
    public String getGlobalSchemesPath() {
        return globalSchemesPath;
    }

    /**
     * 从磁盘加载全局令牌方案
     * @param locations 当前项目的令牌位置列表（用于将type+expression解析为ID）
     */
    public void loadSchemes(List<TokenLocation> locations) {
        globalSchemes = TokenSchemeYamlIO.readFromFile(globalSchemesPath, locations);
        LogManager.getInstance().printOutput("[+] 全局令牌方案已加载，共 " + globalSchemes.size() + " 条，路径: " + globalSchemesPath);
    }

    /**
     * 从磁盘加载全局令牌方案（无位置映射）
     */
    public void loadSchemes() {
        globalSchemes = TokenSchemeYamlIO.readFromFile(globalSchemesPath, new ArrayList<>());
        LogManager.getInstance().printOutput("[+] 全局令牌方案已加载，共 " + globalSchemes.size() + " 条，路径: " + globalSchemesPath);
    }

    /**
     * 保存全局令牌方案到磁盘
     * @param locations 当前项目的令牌位置列表，用于将tokenLocationId解析为type+expression
     */
    public boolean saveSchemes(List<TokenLocation> locations) {
        boolean result = TokenSchemeYamlIO.writeToFile(globalSchemes, locations, globalSchemesPath);
        if (result) {
            LogManager.getInstance().printOutput("[+] 全局令牌方案已保存，共 " + globalSchemes.size() + " 条");
        }
        return result;
    }

    /**
     * 获取所有全局令牌方案
     */
    public List<TokenScheme> getAllSchemes() {
        return new ArrayList<>(globalSchemes);
    }

    /**
     * 添加全局令牌方案（按名称去重，同名更新）
     * @param locations 当前项目的令牌位置列表，用于将tokenLocationId解析为type+expression
     */
    public void addScheme(TokenScheme scheme, List<TokenLocation> locations) {
        // 去重：如果已存在相同名称，则更新
        for (int i = 0; i < globalSchemes.size(); i++) {
            TokenScheme existing = globalSchemes.get(i);
            if (existing.getName().equals(scheme.getName())) {
                existing.setDescription(scheme.getDescription());
                existing.setPersistToGlobal(true);
                existing.setEnabled(scheme.isEnabled());
                existing.setTokenLocationIds(scheme.getTokenLocationIds());
                saveSchemes(locations);
                LogManager.getInstance().printOutput("[+] 全局令牌方案已更新: " + scheme.getName());
                return;
            }
        }
        // 新增记录
        TokenScheme newScheme = new TokenScheme();
        newScheme.setName(scheme.getName());
        newScheme.setDescription(scheme.getDescription());
        newScheme.setPersistToGlobal(true);
        newScheme.setEnabled(scheme.isEnabled());
        newScheme.setTokenLocationIds(scheme.getTokenLocationIds());
        globalSchemes.add(newScheme);
        saveSchemes(locations);
        LogManager.getInstance().printOutput("[+] 全局令牌方案已添加: " + scheme.getName());
    }

    /**
     * 移除全局令牌方案
     * @param locations 当前项目的令牌位置列表，用于将tokenLocationId解析为type+expression
     */
    public void removeScheme(String name, List<TokenLocation> locations) {
        boolean removed = globalSchemes.removeIf(s -> s.getName().equals(name));
        if (removed) {
            saveSchemes(locations);
            LogManager.getInstance().printOutput("[+] 全局令牌方案已移除: " + name);
        }
    }

    /**
     * 根据持久化标志同步令牌方案
     * persistToGlobal=true: 添加或更新到全局
     * persistToGlobal=false: 从全局中移除（如果存在）
     * @param locations 当前项目的令牌位置列表，用于将tokenLocationId解析为type+expression
     */
    public void syncScheme(TokenScheme scheme, boolean persistToGlobal, List<TokenLocation> locations) {
        if (persistToGlobal) {
            addScheme(scheme, locations);
        } else {
            removeScheme(scheme.getName(), locations);
        }
    }

    /**
     * 检查全局中是否已存在指定名称的令牌方案
     */
    public boolean containsScheme(String name) {
        for (TokenScheme s : globalSchemes) {
            if (s.getName().equals(name)) {
                return true;
            }
        }
        return false;
    }
}

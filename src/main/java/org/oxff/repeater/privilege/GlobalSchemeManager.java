package org.oxff.repeater.privilege;

import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.privilege.model.FieldDefinition;
import org.oxff.repeater.privilege.model.Scheme;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * 全局方案管理器（单例）
 * 管理保存在 ~/.burp/repeater_manager/schemes.yaml 中的全局方案
 * 全局方案可被任何新项目自动加载
 */
public class GlobalSchemeManager {
    private static GlobalSchemeManager instance;

    private static final String GLOBAL_DIR_NAME = ".burp" + File.separator + "repeater_manager";
    private static final String GLOBAL_SCHEMES_FILE = "schemes.yaml";

    private final String globalSchemesPath;
    private List<Scheme> globalSchemes;

    private GlobalSchemeManager() {
        String userHome = System.getProperty("user.home");
        this.globalSchemesPath = userHome + File.separator + GLOBAL_DIR_NAME + File.separator + GLOBAL_SCHEMES_FILE;
        this.globalSchemes = new ArrayList<>();
    }

    /**
     * 获取单例实例
     */
    public static synchronized GlobalSchemeManager getInstance() {
        if (instance == null) {
            instance = new GlobalSchemeManager();
        }
        return instance;
    }

    /**
     * 获取全局方案文件路径
     */
    public String getGlobalSchemesPath() {
        return globalSchemesPath;
    }

    /**
     * 从磁盘加载全局方案
     * @param fields 当前项目的字段定义列表（用于将type+expression解析为ID）
     */
    public void loadSchemes(List<FieldDefinition> fields) {
        globalSchemes = SchemeYamlIO.readFromFile(globalSchemesPath, fields);
        LogManager.getInstance().printOutput("[+] 全局方案已加载，共 " + globalSchemes.size() + " 条，路径: " + globalSchemesPath);
    }

    /**
     * 从磁盘加载全局方案（无字段映射）
     */
    public void loadSchemes() {
        globalSchemes = SchemeYamlIO.readFromFile(globalSchemesPath, new ArrayList<>());
        LogManager.getInstance().printOutput("[+] 全局方案已加载，共 " + globalSchemes.size() + " 条，路径: " + globalSchemesPath);
    }

    /**
     * 保存全局方案到磁盘
     * @param fields 当前项目的字段定义列表，用于将fieldId解析为type+expression
     */
    public boolean saveSchemes(List<FieldDefinition> fields) {
        boolean result = SchemeYamlIO.writeToFile(globalSchemes, fields, globalSchemesPath);
        if (result) {
            LogManager.getInstance().printOutput("[+] 全局方案已保存，共 " + globalSchemes.size() + " 条");
        }
        return result;
    }

    /**
     * 获取所有全局方案
     */
    public List<Scheme> getAllSchemes() {
        return new ArrayList<>(globalSchemes);
    }

    /**
     * 添加全局方案（按名称去重，同名更新）
     * @param fields 当前项目的字段定义列表，用于将fieldId解析为type+expression
     */
    public void addScheme(Scheme scheme, List<FieldDefinition> fields) {
        // 去重：如果已存在相同名称，则更新
        for (int i = 0; i < globalSchemes.size(); i++) {
            Scheme existing = globalSchemes.get(i);
            if (existing.getName().equals(scheme.getName())) {
                existing.setDescription(scheme.getDescription());
                existing.setPersistToGlobal(true);
                existing.setEnabled(scheme.isEnabled());
                existing.setFieldIds(scheme.getFieldIds());
                saveSchemes(fields);
                LogManager.getInstance().printOutput("[+] 全局方案已更新: " + scheme.getName());
                return;
            }
        }
        // 新增记录
        Scheme newScheme = new Scheme();
        newScheme.setName(scheme.getName());
        newScheme.setDescription(scheme.getDescription());
        newScheme.setPersistToGlobal(true);
        newScheme.setEnabled(scheme.isEnabled());
        newScheme.setFieldIds(scheme.getFieldIds());
        globalSchemes.add(newScheme);
        saveSchemes(fields);
        LogManager.getInstance().printOutput("[+] 全局方案已添加: " + scheme.getName());
    }

    /**
     * 移除全局方案
     * @param fields 当前项目的字段定义列表，用于将fieldId解析为type+expression
     */
    public void removeScheme(String name, List<FieldDefinition> fields) {
        boolean removed = globalSchemes.removeIf(s -> s.getName().equals(name));
        if (removed) {
            saveSchemes(fields);
            LogManager.getInstance().printOutput("[+] 全局方案已移除: " + name);
        }
    }

    /**
     * 根据持久化标志同步方案
     * persistToGlobal=true: 添加或更新到全局
     * persistToGlobal=false: 从全局中移除（如果存在）
     * @param fields 当前项目的字段定义列表，用于将fieldId解析为type+expression
     */
    public void syncScheme(Scheme scheme, boolean persistToGlobal, List<FieldDefinition> fields) {
        if (persistToGlobal) {
            addScheme(scheme, fields);
        } else {
            removeScheme(scheme.getName(), fields);
        }
    }

    /**
     * 检查全局中是否已存在指定名称的方案
     */
    public boolean containsScheme(String name) {
        for (Scheme s : globalSchemes) {
            if (s.getName().equals(name)) {
                return true;
            }
        }
        return false;
    }
}

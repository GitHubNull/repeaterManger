package org.oxff.repeater.privilege;

import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.privilege.model.FieldDefinition;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * 全局字段定义管理器（单例）
 * 管理保存在 ~/.burp/repeater_manager/field_definitions.yaml 中的全局字段定义
 * 全局字段定义可被任何新项目自动加载
 */
public class GlobalFieldDefinitionManager {
    private static GlobalFieldDefinitionManager instance;

    private static final String GLOBAL_DIR_NAME = ".burp" + File.separator + "repeater_manager";
    private static final String GLOBAL_FIELDS_FILE = "field_definitions.yaml";

    private final String globalFieldsPath;
    private List<FieldDefinition> globalFields;
    private GlobalFieldDefinitionManager() {
        String userHome = System.getProperty("user.home");
        this.globalFieldsPath = userHome + File.separator + GLOBAL_DIR_NAME + File.separator + GLOBAL_FIELDS_FILE;
        this.globalFields = new ArrayList<>();
    }

    /**
     * 获取单例实例
     */
    public static synchronized GlobalFieldDefinitionManager getInstance() {
        if (instance == null) {
            instance = new GlobalFieldDefinitionManager();
        }
        return instance;
    }

    /**
     * 获取全局字段定义文件路径
     */
    public String getGlobalFieldsPath() {
        return globalFieldsPath;
    }

    /**
     * 从磁盘加载全局字段定义
     */
    public void loadFields() {
        globalFields = FieldDefinitionYamlIO.readFromFile(globalFieldsPath);
        LogManager.getInstance().printOutput("[+] 全局字段定义已加载，共 " + globalFields.size() + " 条，路径: " + globalFieldsPath);
    }

    /**
     * 保存全局字段定义到磁盘
     */
    public boolean saveFields() {
        boolean result = FieldDefinitionYamlIO.writeToFile(globalFields, globalFieldsPath);
        if (result) {
            LogManager.getInstance().printOutput("[+] 全局字段定义已保存，共 " + globalFields.size() + " 条");
        }
        return result;
    }

    /**
     * 获取所有全局字段定义
     */
    public List<FieldDefinition> getAllFields() {
        return new ArrayList<>(globalFields);
    }

    /**
     * 添加全局字段定义
     */
    public void addField(FieldDefinition field) {
        // 去重：如果已存在相同 type+expression，则更新
        for (int i = 0; i < globalFields.size(); i++) {
            FieldDefinition existing = globalFields.get(i);
            if (isSameKey(existing, field)) {
                // 更新现有记录
                existing.setExpression(field.getExpression());
                existing.setDescription(field.getDescription());
                existing.setPersistToGlobal(true);
                existing.setEnabled(field.isEnabled());
                saveFields();
                LogManager.getInstance().printOutput("[+] 全局字段定义已更新: " + field.getType().name() + " - " + field.getExpression());
                return;
            }
        }
        // 新增记录
        FieldDefinition newField = new FieldDefinition(field.getType(), field.getExpression(),
                field.getDescription(), true, field.isEnabled());
        globalFields.add(newField);
        saveFields();
        LogManager.getInstance().printOutput("[+] 全局字段定义已添加: " + field.getType().name() + " - " + field.getExpression());
    }

    /**
     * 更新全局字段定义
     * 按 type+expression 匹配，如果旧键不存在则按新键添加
     *
     * @param oldType       更新前的类型
     * @param oldExpression 更新前的表达式
     * @param newField      更新后的字段定义
     */
    public void updateField(String oldType, String oldExpression, FieldDefinition newField) {
        // 先尝试按旧键查找并更新
        for (int i = 0; i < globalFields.size(); i++) {
            FieldDefinition existing = globalFields.get(i);
            if (existing.getType().name().equals(oldType) && existing.getExpression().equals(oldExpression)) {
                existing.setType(newField.getType());
                existing.setExpression(newField.getExpression());
                existing.setDescription(newField.getDescription());
                existing.setPersistToGlobal(true);
                existing.setEnabled(newField.isEnabled());
                saveFields();
                LogManager.getInstance().printOutput("[+] 全局字段定义已更新: " + newField.getType().name() + " - " + newField.getExpression());
                return;
            }
        }
        // 旧键未找到，按新键添加
        addField(newField);
    }

    /**
     * 移除全局字段定义
     *
     * @param type       字段类型名称
     * @param expression 表达式
     */
    public void removeField(String type, String expression) {
        boolean removed = globalFields.removeIf(field ->
                field.getType().name().equals(type) && field.getExpression().equals(expression));
        if (removed) {
            saveFields();
            LogManager.getInstance().printOutput("[+] 全局字段定义已移除: " + type + " - " + expression);
        }
    }

    /**
     * 根据持久化标志同步字段定义
     * persistToGlobal=true: 添加或更新到全局
     * persistToGlobal=false: 从全局中移除（如果存在）
     *
     * @param field           字段定义数据
     * @param persistToGlobal 是否持久化到全局
     */
    public void syncField(FieldDefinition field, boolean persistToGlobal) {
        if (persistToGlobal) {
            addField(field);
        } else {
            removeField(field.getType().name(), field.getExpression());
        }
    }

    /**
     * 检查全局中是否已存在指定 type+expression 的字段定义
     */
    public boolean containsField(String type, String expression) {
        for (FieldDefinition field : globalFields) {
            if (field.getType().name().equals(type) && field.getExpression().equals(expression)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断两个字段定义是否具有相同的去重键（type + expression）
     */
    private boolean isSameKey(FieldDefinition a, FieldDefinition b) {
        return a.getType().name().equals(b.getType().name()) && a.getExpression().equals(b.getExpression());
    }
}

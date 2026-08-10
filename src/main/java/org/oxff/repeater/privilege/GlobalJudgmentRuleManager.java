package org.oxff.repeater.privilege;

import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.privilege.model.JudgmentRule;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * 全局判决规则管理器（单例）
 * <p>
 * 数据库采用会话目录模式：每次插件启动都会创建新的时间戳会话目录，
 * 旧会话数据库中的规则不会自动可见。本管理器将标记为“持久化”(global=true)
 * 的判决规则保存到用户主目录下的全局 YAML 文件，插件启动时由
 * {@link JudgmentRuleManager#loadGlobalRules()} 恢复到新会话数据库，
 * 实现规则的跨会话持久化。
 * <p>
 * 存储路径：~/.burp/repeater_manager/judgment_rules.yaml
 * 与 {@link GlobalFieldDefinitionManager} 的全局持久化模式保持一致。
 */
public class GlobalJudgmentRuleManager {

    private static GlobalJudgmentRuleManager instance;

    /** 全局配置目录名（与 GlobalFieldDefinitionManager 一致） */
    private static final String GLOBAL_DIR_NAME = ".burp" + File.separator + "repeater_manager";

    /** 全局判决规则文件名 */
    private static final String GLOBAL_RULES_FILE = "judgment_rules.yaml";

    private final String globalRulesPath;

    /** 内存中的全局规则列表 */
    private List<JudgmentRule> globalRules;

    private GlobalJudgmentRuleManager() {
        String userHome = System.getProperty("user.home");
        this.globalRulesPath = userHome + File.separator + GLOBAL_DIR_NAME + File.separator + GLOBAL_RULES_FILE;
        this.globalRules = new ArrayList<>();
    }

    /**
     * 获取单例实例
     */
    public static synchronized GlobalJudgmentRuleManager getInstance() {
        if (instance == null) {
            instance = new GlobalJudgmentRuleManager();
        }
        return instance;
    }

    /**
     * 获取全局规则文件路径
     */
    public String getGlobalRulesPath() {
        return globalRulesPath;
    }

    /**
     * 从全局YAML文件加载规则到内存（启动时调用）
     */
    public void loadRules() {
        globalRules = JudgmentRuleYamlIO.readFromFile(globalRulesPath);
        LogManager.getInstance().printOutput("[+] 全局判决规则已加载，共 " + globalRules.size() + " 条，路径: " + globalRulesPath);
    }

    /**
     * 获取内存中的全局规则列表副本
     */
    public List<JudgmentRule> getAllRules() {
        return new ArrayList<>(globalRules);
    }

    /**
     * 以当前数据库中的规则为准，重建全局YAML文件（仅保留 global=true 的规则）
     * 在规则增删改后调用，保证全局存储与数据库状态一致（自动处理改名/删除/取消持久化）
     *
     * @param allRules 当前会话数据库中的全部规则
     */
    public void syncFromRules(List<JudgmentRule> allRules) {
        List<JudgmentRule> persistent = new ArrayList<>();
        if (allRules != null) {
            for (JudgmentRule rule : allRules) {
                if (rule != null && rule.isGlobal()) {
                    persistent.add(rule);
                }
            }
        }
        this.globalRules = persistent;
        boolean result = JudgmentRuleYamlIO.writeToFile(persistent, globalRulesPath);
        if (result) {
            LogManager.getInstance().printOutput("[+] 全局判决规则已保存，共 " + persistent.size() + " 条");
        }
    }
}

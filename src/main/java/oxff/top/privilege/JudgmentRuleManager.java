package oxff.top.privilege;

import burp.BurpExtender;
import oxff.top.privilege.dao.JudgmentRuleDAO;
import oxff.top.privilege.model.JudgmentRule;

import java.util.ArrayList;
import java.util.List;

/**
 * 判决规则管理器（单例）
 * 管理判决规则的 CRUD 操作，缓存已启用的规则列表
 */
public class JudgmentRuleManager {

    private static JudgmentRuleManager instance;

    private final JudgmentRuleDAO ruleDAO;

    /** 缓存的所有规则 */
    private List<JudgmentRule> cachedAllRules;

    /** 缓存的已启用规则 */
    private List<JudgmentRule> cachedEnabledRules;

    private JudgmentRuleManager() {
        this.ruleDAO = new JudgmentRuleDAO();
        this.cachedAllRules = new ArrayList<>();
        this.cachedEnabledRules = new ArrayList<>();
    }

    /**
     * 获取单例实例
     */
    public static synchronized JudgmentRuleManager getInstance() {
        if (instance == null) {
            instance = new JudgmentRuleManager();
        }
        return instance;
    }

    /**
     * 刷新缓存
     */
    public void refreshCache() {
        cachedAllRules = ruleDAO.getAllRules();
        cachedEnabledRules = ruleDAO.getEnabledRules();
        BurpExtender.printOutput("[+] 判决规则缓存已刷新: " + cachedAllRules.size() +
                "条规则, " + cachedEnabledRules.size() + "条已启用");
    }

    /**
     * 获取所有规则
     */
    public List<JudgmentRule> getAllRules() {
        if (cachedAllRules.isEmpty()) {
            refreshCache();
        }
        return cachedAllRules;
    }

    /**
     * 获取已启用的规则（按优先级排序）
     */
    public List<JudgmentRule> getEnabledRules() {
        if (cachedEnabledRules.isEmpty()) {
            refreshCache();
        }
        return cachedEnabledRules;
    }

    /**
     * 检查是否有已启用的规则
     */
    public boolean hasEnabledRules() {
        if (cachedEnabledRules.isEmpty()) {
            refreshCache();
        }
        return !cachedEnabledRules.isEmpty();
    }

    /**
     * 添加规则
     * @return 新规则ID，失败返回-1
     */
    public int addRule(JudgmentRule rule) {
        int id = ruleDAO.addRule(rule);
        if (id > 0) {
            refreshCache();
        }
        return id;
    }

    /**
     * 更新规则
     */
    public boolean updateRule(JudgmentRule rule) {
        boolean result = ruleDAO.updateRule(rule);
        if (result) {
            refreshCache();
        }
        return result;
    }

    /**
     * 删除规则
     */
    public boolean deleteRule(int id) {
        boolean result = ruleDAO.deleteRule(id);
        if (result) {
            refreshCache();
        }
        return result;
    }

    /**
     * 切换规则启用状态
     */
    public boolean toggleRuleEnabled(int id, boolean enabled) {
        JudgmentRule rule = ruleDAO.getRuleById(id);
        if (rule == null) return false;
        rule.setEnabled(enabled);
        return updateRule(rule);
    }

    /**
     * 导出所有规则为YAML字符串
     */
    public String exportRulesToYaml() {
        return JudgmentRuleYamlIO.toYaml(getAllRules());
    }

    /**
     * 从YAML导入规则（合并模式，去重）
     * @return 实际新增数量
     */
    public int importRulesMerge(List<JudgmentRule> newRules) {
        int added = 0;
        for (JudgmentRule rule : newRules) {
            // 简单去重：检查是否存在相同 target+method+expression 的规则
            boolean exists = cachedAllRules.stream()
                    .anyMatch(r -> r.getTarget() == rule.getTarget()
                            && r.getMethod() == rule.getMethod()
                            && r.getExpression().equals(rule.getExpression()));
            if (!exists) {
                int id = ruleDAO.addRule(rule);
                if (id > 0) added++;
            }
        }
        if (added > 0) {
            refreshCache();
        }
        return added;
    }

    /**
     * 从YAML导入规则（替换模式）
     */
    public void importRulesReplace(List<JudgmentRule> newRules) {
        ruleDAO.deleteAllRules();
        for (JudgmentRule rule : newRules) {
            ruleDAO.addRule(rule);
        }
        refreshCache();
    }
}

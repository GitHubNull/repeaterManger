package org.oxff.repeater.privilege;

import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.privilege.dao.JudgmentRuleDAO;
import org.oxff.repeater.privilege.model.JudgmentRule;
import org.oxff.repeater.privilege.model.RuleCondition;
import org.oxff.repeater.privilege.model.RuleMethod;
import org.oxff.repeater.privilege.model.RuleTarget;

import java.awt.Color;
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
        LogManager.getInstance().printOutput("[+] 判决规则缓存已刷新: " + cachedAllRules.size() +
                "条规则, " + cachedEnabledRules.size() + "条已启用");

        // 确保默认相似度规则存在
        ensureDefaultSimilarityRule();
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
            // 去重：基于 conditions 列表比较
            boolean exists = false;
            for (JudgmentRule existing : cachedAllRules) {
                if (conditionsEqual(rule.getEffectiveConditions(), existing.getEffectiveConditions())) {
                    exists = true;
                    break;
                }
            }
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
     * 比较两个条件列表是否相等（用于去重）
     */
    private static boolean conditionsEqual(List<RuleCondition> a, List<RuleCondition> b) {
        if (a == null && b == null) return true;
        if (a == null || b == null) return false;
        if (a.size() != b.size()) return false;
        for (int i = 0; i < a.size(); i++) {
            RuleCondition ca = a.get(i);
            RuleCondition cb = b.get(i);
            if (ca.getTarget() != cb.getTarget()
                    || ca.getMethod() != cb.getMethod()
                    || !ca.getExpression().equals(cb.getExpression())
                    || ca.getOperator() != cb.getOperator()
                    || ca.isNegate() != cb.isNegate()) {
                return false;
            }
        }
        return true;
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

    /**
     * 确保默认相似度规则存在
     * 遍历所有规则，检查是否已有包含 SIMILARITY 目标的条件；若没有则自动创建
     */
    private void ensureDefaultSimilarityRule() {
        for (JudgmentRule rule : cachedAllRules) {
            for (RuleCondition cond : rule.getEffectiveConditions()) {
                if (cond.getTarget() == RuleTarget.SIMILARITY) {
                    return; // 已有相似度规则，无需创建
                }
            }
        }

        // 创建默认相似度规则
        JudgmentRule defaultRule = new JudgmentRule();
        defaultRule.setName("默认相似度规则");
        defaultRule.setTarget(RuleTarget.SIMILARITY);
        defaultRule.setMethod(RuleMethod.GREATER_THAN);
        defaultRule.setExpression("0.90");
        defaultRule.setEnabled(true);
        defaultRule.setPriority(999);
        defaultRule.setSuccessColor(Color.RED);
        defaultRule.setSuccessNote("相似度>=90%: 响应高度相似，疑似越权");
        defaultRule.setRemark("系统自动创建的默认兜底规则，可修改或禁用");
        defaultRule.setGlobal(true);

        // 设置单条件列表
        List<RuleCondition> conditions = new ArrayList<>();
        conditions.add(new RuleCondition(RuleTarget.SIMILARITY, RuleMethod.GREATER_THAN, "0.90"));
        defaultRule.setConditions(conditions);

        int id = ruleDAO.addRule(defaultRule);
        if (id > 0) {
            LogManager.getInstance().printOutput("[+] 已自动创建默认相似度规则 (id=" + id + ", priority=999)");
            // 刷新缓存以包含新规则
            cachedAllRules = ruleDAO.getAllRules();
            cachedEnabledRules = ruleDAO.getEnabledRules();
        }
    }
}

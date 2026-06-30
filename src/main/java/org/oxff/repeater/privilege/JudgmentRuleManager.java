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
 * 判决规则管理器（单例，v13：单活跃规则集模式）
 * 管理判决规则的 CRUD 操作，缓存已启用的规则列表和活跃规则组
 */
public class JudgmentRuleManager {

    private static JudgmentRuleManager instance;

    private final JudgmentRuleDAO ruleDAO;

    /** 缓存的所有规则 */
    private List<JudgmentRule> cachedAllRules;

    /** 缓存的已启用规则 */
    private List<JudgmentRule> cachedEnabledRules;

    /** 缓存的当前活跃规则组 */
    private JudgmentRule cachedActiveRule;

    /** 批量操作模式：延迟缓存刷新 */
    private boolean batchMode = false;

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
        cachedActiveRule = ruleDAO.getActiveRule();
        LogManager.getInstance().printOutput("[+] 判决规则缓存已刷新: " + cachedAllRules.size() +
                "条规则组, " + cachedEnabledRules.size() + "条已启用, 活跃: " +
                (cachedActiveRule != null ? cachedActiveRule.getName() : "无"));

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
     * 获取已启用的规则
     */
    public List<JudgmentRule> getEnabledRules() {
        if (cachedEnabledRules.isEmpty()) {
            refreshCache();
        }
        return cachedEnabledRules;
    }

    /**
     * 获取当前活跃规则组（v13 新增）
     */
    public JudgmentRule getActiveRule() {
        if (cachedActiveRule == null) {
            refreshCache();
        }
        return cachedActiveRule;
    }

    /**
     * 检查是否有活跃规则组
     */
    public boolean hasActiveRule() {
        return getActiveRule() != null;
    }

    /**
     * 获取默认相似度规则组（按名称 "默认相似度规则" 精确匹配）
     * 用于活跃规则组未命中时作为安全网兜底
     *
     * @return 默认相似度规则组，不存在时返回 null
     */
    public JudgmentRule getDefaultSimilarityRule() {
        if (cachedAllRules.isEmpty()) {
            refreshCache();
        }
        for (JudgmentRule rule : cachedAllRules) {
            if ("默认相似度规则".equals(rule.getName())) {
                return rule;
            }
        }
        return null;
    }

    /**
     * 是否有已启用的规则（保留向后兼容）
     */
    public boolean hasEnabledRules() {
        return hasActiveRule() || !cachedEnabledRules.isEmpty();
    }

    /**
     * 在批量模式下执行操作：自动管理 batchMode，异常安全（finally 中恢复）
     * 用于规则组创建/编辑等需要多次调用 addRule/updateRule 的场景
     *
     * @param action 批操作（Runnable 或 lambda）
     */
    public void runInBatch(Runnable action) {
        batchMode = true;
        try {
            action.run();
        } finally {
            batchMode = false;
            refreshCache();
        }
    }

    /**
     * @deprecated 使用 runInBatch(Runnable) 替代，自带异常安全
     */
    @Deprecated
    public void beginBatch() {
        batchMode = true;
    }

    /**
     * @deprecated 使用 runInBatch(Runnable) 替代，自带异常安全
     */
    @Deprecated
    public void endBatch() {
        batchMode = false;
        refreshCache();
    }

    public boolean isBatchMode() {
        return batchMode;
    }

    /**
     * 设置活跃规则组（v13 新增，互斥：同一时刻仅一个组活跃）
     */
    public boolean setActiveRule(int groupId) {
        boolean result = ruleDAO.setActiveRule(groupId);
        if (result && !batchMode) {
            refreshCache();
        }
        return result;
    }

    /**
     * 添加规则
     * @return 新规则ID，失败返回-1
     */
    public int addRule(JudgmentRule rule) {
        int id = ruleDAO.addRule(rule);
        if (id > 0 && !batchMode) {
            refreshCache();
        }
        return id;
    }

    /**
     * 更新规则
     */
    public boolean updateRule(JudgmentRule rule) {
        boolean result = ruleDAO.updateRule(rule);
        if (result && !batchMode) {
            refreshCache();
        }
        return result;
    }

    /**
     * 删除规则
     */
    public boolean deleteRule(int id) {
        boolean result = ruleDAO.deleteRule(id);
        if (result && !batchMode) {
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
     * 比较两个条件列表是否相等（用于去重，v13：忽略 operator）
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
     * 确保默认相似度规则组存在（v13：创建后自动设为活跃）
     * 按名称 "默认相似度规则" 精确匹配，避免将用户自定义的含 SIMILARITY 条件的
     * 规则组误认为默认规则组而跳过创建。
     */
    private void ensureDefaultSimilarityRule() {
        // 检查是否已存在默认相似度规则组（按名称精确匹配）
        boolean hasDefaultRule = false;
        for (JudgmentRule rule : cachedAllRules) {
            if ("默认相似度规则".equals(rule.getName())) {
                hasDefaultRule = true;
                break;
            }
        }

        if (hasDefaultRule) {
            // 已有默认规则组，检查是否有活跃规则组
            if (cachedActiveRule == null && !cachedAllRules.isEmpty()) {
                // 有规则但没活跃的，自动激活第一条
                JudgmentRule first = cachedAllRules.get(0);
                ruleDAO.setActiveRule(first.getId());
                cachedActiveRule = ruleDAO.getActiveRule();
                LogManager.getInstance().printOutput("[+] 自动激活第一个规则组: " + first.getName());
            }
            return;
        }

        // 创建默认相似度规则组
        JudgmentRule defaultRule = new JudgmentRule();
        defaultRule.setName("默认相似度规则");
        defaultRule.setEnabled(true);
        defaultRule.setActive(true);
        defaultRule.setSuccessColor(Color.RED);
        defaultRule.setSuccessNote("相似度>=90%: 响应高度相似，疑似越权");
        defaultRule.setRemark("系统自动创建的默认兜底规则组，可修改或禁用");
        defaultRule.setGlobal(true);

        // 设置单条件
        List<RuleCondition> conditions = new ArrayList<>();
        RuleCondition cond = new RuleCondition(RuleTarget.SIMILARITY, RuleMethod.GREATER_THAN, "0.90");
        cond.setNegate(false);
        conditions.add(cond);
        defaultRule.setConditions(conditions);

        int id = ruleDAO.addRule(defaultRule);
        if (id > 0) {
            LogManager.getInstance().printOutput("[+] 已自动创建默认相似度规则组 (id=" + id + ") 并设为活跃");
            // 刷新缓存以包含新规则
            refreshCache();
        }
    }
}

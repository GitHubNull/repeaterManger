package org.oxff.repeater.privilege.dao;

import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.privilege.model.JudgmentRule;
import org.oxff.repeater.privilege.model.RuleCondition;

import java.util.List;

/**
 * 判决规则数据访问对象（v13 门面）
 * 委托给 JudgmentRuleGroupDAO + JudgmentRuleConditionDAO 双表操作
 * 保持对外接口不变，内部适配新的双表结构
 */
public class JudgmentRuleDAO {

    private final JudgmentRuleGroupDAO groupDAO;
    private final JudgmentRuleConditionDAO conditionDAO;

    public JudgmentRuleDAO() {
        this.groupDAO = new JudgmentRuleGroupDAO();
        this.conditionDAO = new JudgmentRuleConditionDAO();
    }

    /**
     * 获取所有判决规则（含条件）
     */
    public List<JudgmentRule> getAllRules() {
        List<JudgmentRule> groups = groupDAO.getAllGroups();
        for (JudgmentRule group : groups) {
            group.setConditions(conditionDAO.getConditionsByGroupId(group.getId()));
        }
        return groups;
    }

    /**
     * 获取所有已启用的判决规则（含条件）
     */
    public List<JudgmentRule> getEnabledRules() {
        List<JudgmentRule> groups = groupDAO.getEnabledGroups();
        for (JudgmentRule group : groups) {
            group.setConditions(conditionDAO.getConditionsByGroupId(group.getId()));
        }
        return groups;
    }

    /**
     * 获取当前活跃规则组（含条件）
     */
    public JudgmentRule getActiveRule() {
        JudgmentRule group = groupDAO.getActiveGroup();
        if (group != null) {
            group.setConditions(conditionDAO.getConditionsByGroupId(group.getId()));
        }
        return group;
    }

    /**
     * 根据ID获取规则
     */
    public JudgmentRule getRuleById(int id) {
        JudgmentRule group = groupDAO.getGroupById(id);
        if (group != null) {
            group.setConditions(conditionDAO.getConditionsByGroupId(group.getId()));
        }
        return group;
    }

    /**
     * 添加判决规则（含条件）
     * @return 新记录ID，失败返回-1
     */
    public int addRule(JudgmentRule rule) {
        // 先插入规则组
        int groupId = groupDAO.addGroup(rule);
        if (groupId <= 0) {
            return -1;
        }

        // 再插入条件
        List<RuleCondition> conditions = rule.getConditions();
        if (conditions != null && !conditions.isEmpty()) {
            int added = conditionDAO.addConditions(groupId, conditions);
            LogManager.getInstance().printOutput("[+] 规则组(id=" + groupId + ")添加 " + added + " 条条件");
        }

        return groupId;
    }

    /**
     * 更新判决规则
     */
    public boolean updateRule(JudgmentRule rule) {
        // 更新规则组元数据
        boolean groupUpdated = groupDAO.updateGroup(rule);
        if (!groupUpdated) {
            return false;
        }

        // 替换条件（先删后插）
        List<RuleCondition> conditions = rule.getConditions();
        if (conditions != null) {
            return conditionDAO.replaceConditions(rule.getId(), conditions);
        }
        return true;
    }

    /**
     * 删除判决规则（级联删除条件由 FK 保证）
     */
    public boolean deleteRule(int id) {
        return groupDAO.deleteGroup(id);
    }

    /**
     * 删除所有规则
     */
    public boolean deleteAllRules() {
        groupDAO.deleteAllGroups();
        return true;
    }

    /**
     * 设置活跃规则组
     */
    public boolean setActiveRule(int id) {
        return groupDAO.setActiveGroup(id);
    }

    /**
     * 检查是否存在包含指定目标的条件
     */
    public boolean hasConditionWithTarget(String targetName) {
        return groupDAO.hasConditionWithTarget(targetName);
    }
}

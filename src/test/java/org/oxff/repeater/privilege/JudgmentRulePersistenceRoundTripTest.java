package org.oxff.repeater.privilege;

import org.oxff.repeater.privilege.model.JudgmentRule;
import org.oxff.repeater.privilege.model.RuleCondition;
import org.oxff.repeater.privilege.model.RuleMethod;
import org.oxff.repeater.privilege.model.RuleTarget;

import java.awt.Color;
import java.io.File;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 持久化往返测试：验证 global(持久化) 标志与 operator 字段在 YAML 中正确序列化/反序列化，
 * 并模拟“全局存储过滤 + 新会话恢复去重”的跨会话持久化流程
 */
public class JudgmentRulePersistenceRoundTripTest {

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        System.out.println("=== 判决规则持久化往返测试 ===\n");

        File tmp;
        try {
            tmp = File.createTempFile("judgment_rules_test", ".yaml");
            tmp.deleteOnExit();
        } catch (Exception e) {
            System.out.println("FAIL 无法创建临时文件: " + e.getMessage());
            System.exit(1);
            return;
        }

        // 构造规则1：持久化规则（含 OR 条件）
        JudgmentRule persistent = new JudgmentRule();
        persistent.setName("持久化测试规则");
        persistent.setEnabled(true);
        persistent.setActive(true);
        persistent.setGlobal(true);
        persistent.setSuccessColor(Color.RED);
        persistent.setSuccessNote("越权");
        persistent.setFailureNote("安全");
        List<RuleCondition> conds = new ArrayList<>();
        RuleCondition c1 = new RuleCondition(RuleTarget.STATUS_CODE, RuleMethod.NUMERIC_EQUALS, "200");
        c1.setOperator(RuleCondition.LogicalOperator.AND);
        RuleCondition c2 = new RuleCondition(RuleTarget.SIMILARITY, RuleMethod.GREATER_THAN, "0.86");
        c2.setOperator(RuleCondition.LogicalOperator.OR);
        conds.add(c1);
        conds.add(c2);
        persistent.setConditions(conds);

        // 构造规则2：临时规则（不持久化）
        JudgmentRule temporary = new JudgmentRule();
        temporary.setName("临时规则");
        temporary.setEnabled(true);
        temporary.setGlobal(false);
        List<RuleCondition> conds2 = new ArrayList<>();
        conds2.add(new RuleCondition(RuleTarget.STATUS_CODE, RuleMethod.NUMERIC_EQUALS, "200"));
        temporary.setConditions(conds2);

        List<JudgmentRule> all = new ArrayList<>();
        all.add(persistent);
        all.add(temporary);

        // 1. 写入YAML（模拟会话结束时同步全局存储）
        boolean written = JudgmentRuleYamlIO.writeToFile(all, tmp.getAbsolutePath());
        check("YAML 写入成功", written);

        // 2. 读回并验证字段往返
        List<JudgmentRule> loaded = JudgmentRuleYamlIO.readFromFile(tmp.getAbsolutePath());
        check("读回 2 条规则", loaded.size() == 2);
        if (loaded.size() == 2) {
            JudgmentRule r0 = loaded.get(0);
            check("持久化标志往返 (global=true)", r0.isGlobal());
            check("名称往返", "持久化测试规则".equals(r0.getName()));
            check("活跃标志往返", r0.isActive());
            check("启用标志往返", r0.isEnabled());
            check("条件数往返", r0.getEffectiveConditions().size() == 2);
            if (r0.getEffectiveConditions().size() == 2) {
                check("operator 往返 (AND)",
                        r0.getEffectiveConditions().get(0).getOperator() == RuleCondition.LogicalOperator.AND);
                check("operator 往返 (OR)",
                        r0.getEffectiveConditions().get(1).getOperator() == RuleCondition.LogicalOperator.OR);
                check("表达式往返", "0.86".equals(r0.getEffectiveConditions().get(1).getExpression()));
            }
            JudgmentRule r1 = loaded.get(1);
            check("临时规则持久化标志往返 (global=false)", !r1.isGlobal());
        }

        // 3. 模拟全局存储过滤（syncFromRules 仅保留 global=true）
        List<JudgmentRule> persistentOnly = new ArrayList<>();
        for (JudgmentRule r : loaded) {
            if (r.isGlobal()) {
                persistentOnly.add(r);
            }
        }
        check("全局存储仅保留持久化规则 (1条)", persistentOnly.size() == 1);

        // 4. 模拟新会话恢复去重（loadGlobalRules 按名称去重）
        Set<String> existingNames = new HashSet<>();
        existingNames.add("默认相似度规则"); // 新会话已自动创建的默认规则
        int added = 0;
        for (JudgmentRule r : persistentOnly) {
            if (r.getName() != null && !existingNames.contains(r.getName())) {
                added++;
            }
        }
        check("新会话恢复 1 条持久化规则", added == 1);

        // 5. 模拟重复启动（规则已存在时不重复恢复）
        existingNames.add("持久化测试规则");
        int addedSecond = 0;
        for (JudgmentRule r : persistentOnly) {
            if (r.getName() != null && !existingNames.contains(r.getName())) {
                addedSecond++;
            }
        }
        check("二次启动不重复恢复", addedSecond == 0);

        System.out.println("\n=== 通过 " + passed + " 项, 失败 " + failed + " 项 ===");
        if (failed > 0) {
            System.exit(1);
        }
    }

    private static void check(String name, boolean ok) {
        if (ok) {
            passed++;
            System.out.println("  [PASS] " + name);
        } else {
            failed++;
            System.out.println("  [FAIL] " + name);
        }
    }
}

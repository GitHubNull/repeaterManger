package org.oxff.repeater.privilege;

import org.oxff.repeater.privilege.model.RuleCondition;
import org.oxff.repeater.privilege.model.RuleMethod;
import org.oxff.repeater.privilege.model.RuleTarget;

import java.util.ArrayList;
import java.util.List;

/**
 * 测试 AND/OR 混合逻辑运算符的正确性
 * 验证 evaluateConditions 方法对不同逻辑组合的处理
 */
public class JudgmentEngineLogicTest {

    public static void main(String[] args) {
        System.out.println("=== 测试 AND/OR 混合逻辑 ===\n");

        // 测试1: 纯 AND 逻辑 - 全部满足
        testPureAndAllMatch();

        // 测试2: 纯 AND 逻辑 - 部分不满足
        testPureAndPartialMatch();

        // 测试3: 纯 OR 逻辑 - 任一满足
        testPureOrAnyMatch();

        // 测试4: 纯 OR 逻辑 - 全部不满足
        testPureOrNoneMatch();

        // 测试5: 混合逻辑 - AND 满足 + OR 满足
        testMixedAndOrBothMatch();

        // 测试6: 混合逻辑 - AND 满足 + OR 不满足
        testMixedAndMatchOrNot();

        // 测试7: 混合逻辑 - AND 不满足 + OR 满足
        testMixedAndNotMatchOrMatch();

        System.out.println("\n=== 所有测试完成 ===");
    }

    /**
     * 测试1: 纯 AND 逻辑 - 全部满足
     * 条件1: statusCode == 200 (AND)
     * 条件2: similarity > 0.8 (AND)
     * 预期: true (两者都满足)
     */
    private static void testPureAndAllMatch() {
        System.out.println("测试1: 纯 AND 逻辑 - 全部满足");
        List<RuleCondition> conditions = new ArrayList<>();

        RuleCondition cond1 = createCondition(RuleTarget.STATUS_CODE, RuleMethod.NUMERIC_EQUALS, "200", RuleCondition.LogicalOperator.AND);
        RuleCondition cond2 = createCondition(RuleTarget.SIMILARITY, RuleMethod.GREATER_THAN, "0.8", RuleCondition.LogicalOperator.AND);
        conditions.add(cond1);
        conditions.add(cond2);

        // 模拟: statusCode=200, similarity=0.9
        boolean result = evaluateConditions(conditions, 200, null, "", 0.9, 0, null, null);
        System.out.println("  条件: statusCode==200 AND similarity>0.8");
        System.out.println("  输入: statusCode=200, similarity=0.9");
        System.out.println("  结果: " + result + " (预期: true)");
        System.out.println("  " + (result ? "✓ 通过" : "✗ 失败"));
        System.out.println();
    }

    /**
     * 测试2: 纯 AND 逻辑 - 部分不满足
     * 条件1: statusCode == 200 (AND)
     * 条件2: similarity > 0.8 (AND)
     * 预期: false (similarity 不满足)
     */
    private static void testPureAndPartialMatch() {
        System.out.println("测试2: 纯 AND 逻辑 - 部分不满足");
        List<RuleCondition> conditions = new ArrayList<>();

        RuleCondition cond1 = createCondition(RuleTarget.STATUS_CODE, RuleMethod.NUMERIC_EQUALS, "200", RuleCondition.LogicalOperator.AND);
        RuleCondition cond2 = createCondition(RuleTarget.SIMILARITY, RuleMethod.GREATER_THAN, "0.8", RuleCondition.LogicalOperator.AND);
        conditions.add(cond1);
        conditions.add(cond2);

        // 模拟: statusCode=200, similarity=0.7
        boolean result = evaluateConditions(conditions, 200, null, "", 0.7, 0, null, null);
        System.out.println("  条件: statusCode==200 AND similarity>0.8");
        System.out.println("  输入: statusCode=200, similarity=0.7");
        System.out.println("  结果: " + result + " (预期: false)");
        System.out.println("  " + (!result ? "✓ 通过" : "✗ 失败"));
        System.out.println();
    }

    /**
     * 测试3: 纯 OR 逻辑 - 任一满足
     * 条件1: statusCode == 200 (OR)
     * 条件2: similarity > 0.8 (OR)
     * 预期: true (statusCode 满足)
     */
    private static void testPureOrAnyMatch() {
        System.out.println("测试3: 纯 OR 逻辑 - 任一满足");
        List<RuleCondition> conditions = new ArrayList<>();

        RuleCondition cond1 = createCondition(RuleTarget.STATUS_CODE, RuleMethod.NUMERIC_EQUALS, "200", RuleCondition.LogicalOperator.OR);
        RuleCondition cond2 = createCondition(RuleTarget.SIMILARITY, RuleMethod.GREATER_THAN, "0.8", RuleCondition.LogicalOperator.OR);
        conditions.add(cond1);
        conditions.add(cond2);

        // 模拟: statusCode=200, similarity=0.5
        boolean result = evaluateConditions(conditions, 200, null, "", 0.5, 0, null, null);
        System.out.println("  条件: statusCode==200 OR similarity>0.8");
        System.out.println("  输入: statusCode=200, similarity=0.5");
        System.out.println("  结果: " + result + " (预期: true)");
        System.out.println("  " + (result ? "✓ 通过" : "✗ 失败"));
        System.out.println();
    }

    /**
     * 测试4: 纯 OR 逻辑 - 全部不满足
     * 条件1: statusCode == 200 (OR)
     * 条件2: similarity > 0.8 (OR)
     * 预期: false (两者都不满足)
     */
    private static void testPureOrNoneMatch() {
        System.out.println("测试4: 纯 OR 逻辑 - 全部不满足");
        List<RuleCondition> conditions = new ArrayList<>();

        RuleCondition cond1 = createCondition(RuleTarget.STATUS_CODE, RuleMethod.NUMERIC_EQUALS, "200", RuleCondition.LogicalOperator.OR);
        RuleCondition cond2 = createCondition(RuleTarget.SIMILARITY, RuleMethod.GREATER_THAN, "0.8", RuleCondition.LogicalOperator.OR);
        conditions.add(cond1);
        conditions.add(cond2);

        // 模拟: statusCode=404, similarity=0.5
        boolean result = evaluateConditions(conditions, 404, null, "", 0.5, 0, null, null);
        System.out.println("  条件: statusCode==200 OR similarity>0.8");
        System.out.println("  输入: statusCode=404, similarity=0.5");
        System.out.println("  结果: " + result + " (预期: false)");
        System.out.println("  " + (!result ? "✓ 通过" : "✗ 失败"));
        System.out.println();
    }

    /**
     * 测试5: 混合逻辑 - AND 满足 + OR 满足
     * 条件1: statusCode == 200 (AND)
     * 条件2: similarity > 0.8 (OR)
     * 条件3: responseTime < 1000 (OR)
     * 预期: true (AND满足，且OR中至少一个满足)
     */
    private static void testMixedAndOrBothMatch() {
        System.out.println("测试5: 混合逻辑 - AND 满足 + OR 满足");
        List<RuleCondition> conditions = new ArrayList<>();

        RuleCondition cond1 = createCondition(RuleTarget.STATUS_CODE, RuleMethod.NUMERIC_EQUALS, "200", RuleCondition.LogicalOperator.AND);
        RuleCondition cond2 = createCondition(RuleTarget.SIMILARITY, RuleMethod.GREATER_THAN, "0.8", RuleCondition.LogicalOperator.OR);
        RuleCondition cond3 = createCondition(RuleTarget.RESPONSE_TIME, RuleMethod.LESS_THAN, "1000", RuleCondition.LogicalOperator.OR);
        conditions.add(cond1);
        conditions.add(cond2);
        conditions.add(cond3);

        // 模拟: statusCode=200, similarity=0.9, responseTime=500
        boolean result = evaluateConditions(conditions, 200, null, "", 0.9, 500, null, null);
        System.out.println("  条件: statusCode==200 AND (similarity>0.8 OR responseTime<1000)");
        System.out.println("  输入: statusCode=200, similarity=0.9, responseTime=500");
        System.out.println("  结果: " + result + " (预期: true)");
        System.out.println("  " + (result ? "✓ 通过" : "✗ 失败"));
        System.out.println();
    }

    /**
     * 测试6: 混合逻辑 - AND 满足 + OR 不满足
     * 条件1: statusCode == 200 (AND)
     * 条件2: similarity > 0.8 (OR)
     * 条件3: responseTime < 1000 (OR)
     * 预期: false (AND满足，但OR都不满足)
     */
    private static void testMixedAndMatchOrNot() {
        System.out.println("测试6: 混合逻辑 - AND 满足 + OR 不满足");
        List<RuleCondition> conditions = new ArrayList<>();

        RuleCondition cond1 = createCondition(RuleTarget.STATUS_CODE, RuleMethod.NUMERIC_EQUALS, "200", RuleCondition.LogicalOperator.AND);
        RuleCondition cond2 = createCondition(RuleTarget.SIMILARITY, RuleMethod.GREATER_THAN, "0.8", RuleCondition.LogicalOperator.OR);
        RuleCondition cond3 = createCondition(RuleTarget.RESPONSE_TIME, RuleMethod.LESS_THAN, "1000", RuleCondition.LogicalOperator.OR);
        conditions.add(cond1);
        conditions.add(cond2);
        conditions.add(cond3);

        // 模拟: statusCode=200, similarity=0.5, responseTime=2000
        boolean result = evaluateConditions(conditions, 200, null, "", 0.5, 2000, null, null);
        System.out.println("  条件: statusCode==200 AND (similarity>0.8 OR responseTime<1000)");
        System.out.println("  输入: statusCode=200, similarity=0.5, responseTime=2000");
        System.out.println("  结果: " + result + " (预期: false)");
        System.out.println("  " + (!result ? "✓ 通过" : "✗ 失败"));
        System.out.println();
    }

    /**
     * 测试7: 混合逻辑 - AND 不满足 + OR 满足
     * 条件1: statusCode == 200 (AND)
     * 条件2: similarity > 0.8 (OR)
     * 预期: false (AND不满足，即使OR满足)
     */
    private static void testMixedAndNotMatchOrMatch() {
        System.out.println("测试7: 混合逻辑 - AND 不满足 + OR 满足");
        List<RuleCondition> conditions = new ArrayList<>();

        RuleCondition cond1 = createCondition(RuleTarget.STATUS_CODE, RuleMethod.NUMERIC_EQUALS, "200", RuleCondition.LogicalOperator.AND);
        RuleCondition cond2 = createCondition(RuleTarget.SIMILARITY, RuleMethod.GREATER_THAN, "0.8", RuleCondition.LogicalOperator.OR);
        conditions.add(cond1);
        conditions.add(cond2);

        // 模拟: statusCode=404, similarity=0.9
        boolean result = evaluateConditions(conditions, 404, null, "", 0.9, 0, null, null);
        System.out.println("  条件: statusCode==200 AND similarity>0.8");
        System.out.println("  输入: statusCode=404, similarity=0.9");
        System.out.println("  结果: " + result + " (预期: false)");
        System.out.println("  " + (!result ? "✓ 通过" : "✗ 失败"));
        System.out.println();
    }

    // ==================== 辅助方法 ====================

    private static RuleCondition createCondition(RuleTarget target, RuleMethod method, String expression, RuleCondition.LogicalOperator operator) {
        RuleCondition cond = new RuleCondition();
        cond.setTarget(target);
        cond.setMethod(method);
        cond.setExpression(expression);
        cond.setOperator(operator);
        cond.setEnabled(true);
        cond.setNegate(false);
        return cond;
    }

    /**
     * 模拟 JudgmentEngine.evaluateConditions 的核心逻辑
     * 用于验证 AND/OR 混合逻辑的正确性
     */
    private static boolean evaluateConditions(List<RuleCondition> conditions,
                                               int statusCode, String responseHeaders,
                                               String bodyStr, double similarity,
                                               long responseTimeMs,
                                               byte[] responseBody, byte[] baselineResponse) {
        if (conditions == null || conditions.isEmpty()) {
            return false;
        }

        boolean hasAnyValidCondition = false;
        boolean andResult = true;
        boolean hasOrCondition = false;
        boolean orResult = false;

        for (RuleCondition cond : conditions) {
            if (cond.getTarget() == null || cond.getMethod() == null) {
                return false;
            }
            if (cond.getExpression() == null || cond.getExpression().trim().isEmpty()) {
                continue;
            }
            if (!cond.isEnabled()) {
                continue;
            }

            hasAnyValidCondition = true;

            String targetValue = extractTargetValue(cond.getTarget(), statusCode,
                    responseHeaders, bodyStr, similarity, responseTimeMs);
            boolean condResult = matchValue(cond.getMethod(), cond.getExpression(),
                    targetValue, statusCode, responseBody, baselineResponse);

            if (cond.isNegate()) {
                condResult = !condResult;
            }

            if (cond.getOperator() == RuleCondition.LogicalOperator.OR) {
                hasOrCondition = true;
                orResult = orResult || condResult;
            } else {
                if (!condResult) {
                    andResult = false;
                }
            }
        }

        if (!hasAnyValidCondition) {
            return false;
        }

        return andResult && (!hasOrCondition || orResult);
    }

    private static String extractTargetValue(RuleTarget target, int statusCode,
                                              String responseHeaders, String responseBody,
                                              double similarity, long responseTimeMs) {
        return switch (target) {
            case STATUS_CODE -> String.valueOf(statusCode);
            case RESPONSE_HEADER -> responseHeaders != null ? responseHeaders : "";
            case RESPONSE_BODY -> responseBody != null ? responseBody : "";
            case RESPONSE_TIME -> String.valueOf(responseTimeMs);
            case SIMILARITY -> String.valueOf(similarity);
        };
    }

    private static boolean matchValue(RuleMethod method, String expression,
                                       String targetValue, int statusCode,
                                       byte[] responseBody, byte[] baselineResponse) {
        if (expression == null || expression.isEmpty()) return false;

        try {
            return switch (method) {
                case NUMERIC_EQUALS -> {
                    try {
                        yield Double.parseDouble(targetValue.trim()) == Double.parseDouble(expression.trim());
                    } catch (NumberFormatException e) {
                        yield false;
                    }
                }
                case GREATER_THAN -> {
                    try {
                        yield Double.parseDouble(targetValue.trim()) > Double.parseDouble(expression.trim());
                    } catch (NumberFormatException e) {
                        yield false;
                    }
                }
                case LESS_THAN -> {
                    try {
                        yield Double.parseDouble(targetValue.trim()) < Double.parseDouble(expression.trim());
                    } catch (NumberFormatException e) {
                        yield false;
                    }
                }
                default -> false;
            };
        } catch (Exception e) {
            return false;
        }
    }
}

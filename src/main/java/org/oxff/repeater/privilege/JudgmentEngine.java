package org.oxff.repeater.privilege;

import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.privilege.model.JudgmentResult;
import org.oxff.repeater.privilege.model.JudgmentRule;
import org.oxff.repeater.privilege.model.RuleCondition;
import org.oxff.repeater.privilege.model.RuleMethod;
import org.oxff.repeater.privilege.model.RuleTarget;

import java.awt.Color;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 判决引擎 - 无状态工具类
 * 根据判决规则对响应进行越权判断
 *
 * 判决逻辑：
 * 1. 如果有已启用的规则，按优先级逐一匹配，首个匹配成功的规则决定结果
 *    - 规则匹配成功 → ESCALATED（越权），使用 success_color + success_note
 *    - 所有规则都不匹配 → 回退到默认判决（状态码+相似度）
 * 2. 如果没有规则，回退到默认判决：状态码+相似度
 */
public class JudgmentEngine {

    /**
     * 判决结果持有者
     */
    public static class JudgmentOutcome {
        public final JudgmentResult result;
        public final Color color;
        public final String note;
        public final double similarity;
        /** 匹配到的规则名称（null表示使用默认判决） */
        public final String matchedRuleName;

        public JudgmentOutcome(JudgmentResult result, Color color, String note,
                               double similarity, String matchedRuleName) {
            this.result = result;
            this.color = color;
            this.note = note;
            this.similarity = similarity;
            this.matchedRuleName = matchedRuleName;
        }
    }

    /**
     * 使用规则判决响应
     *
     * @param statusCode        响应状态码
     * @param responseHeaders   响应头字符串
     * @param responseBody      响应体字节数组（纯响应体，不含响应头）
     * @param baselineResponse  基准用户响应体字节数组（纯响应体，用于相似度计算和LENGTH_DIFF）
     * @param baselineStatusCode 基准用户状态码
     * @param similarityThreshold 相似度阈值（已废弃，使用默认相似度规则代替）
     * @param responseTimeMs    响应时间（毫秒）
     * @return 判决结果
     */
    @SuppressWarnings("deprecation")
    public static JudgmentOutcome judge(int statusCode, String responseHeaders,
                                         byte[] responseBody, byte[] baselineResponse,
                                         int baselineStatusCode,
                                         @Deprecated double similarityThreshold,
                                         long responseTimeMs) {
        // 防护守卫：拒绝对无效基准进行判决，防止因基准响应丢失导致误判
        if (baselineResponse == null && baselineStatusCode <= 0) {
            return new JudgmentOutcome(JudgmentResult.ERROR, null,
                    "基准响应无效，无法进行判决", -1, null);
        }

        JudgmentRuleManager ruleManager = JudgmentRuleManager.getInstance();
        List<JudgmentRule> rules = ruleManager.getEnabledRules();

        // 计算相似度（使用内容感知的混合算法）
        double similarity = -1;
        if (baselineResponse != null && responseBody != null) {
            String respStr = new String(responseBody, StandardCharsets.UTF_8);
            String baseStr = new String(baselineResponse, StandardCharsets.UTF_8);
            String contentType = extractContentType(responseHeaders);
            similarity = SimilarityEngine.similarity(respStr, baseStr, contentType);
        }

        // 有规则时：按优先级匹配
        if (!rules.isEmpty()) {
            return judgeWithRules(rules, statusCode, responseHeaders, responseBody,
                    baselineResponse, baselineStatusCode, similarity, similarityThreshold, responseTimeMs);
        }

        // 无规则时：回退到默认判决
        return judgeDefault(statusCode, baselineStatusCode, similarity, similarityThreshold);
    }

    /**
     * 使用规则进行判决
     * 按优先级逐一匹配，首个匹配成功的规则返回 ESCALATED；
     * 若所有规则都不匹配，回退到默认判决
     */
    private static JudgmentOutcome judgeWithRules(List<JudgmentRule> rules, int statusCode,
                                                   String responseHeaders, byte[] responseBody,
                                                   byte[] baselineResponse,
                                                   int baselineStatusCode,
                                                   double similarity, double similarityThreshold,
                                                   long responseTimeMs) {
        String bodyStr = responseBody != null ? new String(responseBody, StandardCharsets.UTF_8) : "";

        for (JudgmentRule rule : rules) {
            if (!rule.isEnabled() || !rule.isValid()) continue;

            // 使用 getEffectiveConditions() 获取条件列表（自动处理向后兼容）
            List<RuleCondition> conditions = rule.getEffectiveConditions();
            boolean allMatched = evaluateConditions(conditions, statusCode,
                    responseHeaders, bodyStr, similarity, responseTimeMs,
                    responseBody, baselineResponse);

            if (allMatched) {
                // 规则匹配成功 → 表示越权，使用成功颜色和备注
                String note = rule.getSuccessNote();
                if (note == null || note.isEmpty()) {
                    note = "规则匹配: " + rule.getName();
                }
                return new JudgmentOutcome(JudgmentResult.ESCALATED, rule.getSuccessColor(),
                        note, similarity, rule.getName());
            }
            // 规则不匹配 → 继续检查下一条规则，不提前返回
        }

        // 所有规则都不匹配，回退到默认判决
        return judgeDefault(statusCode, baselineStatusCode, similarity, similarityThreshold);
    }

    /**
     * 默认判决逻辑：仅状态码差异兜底
     * 相似度判断已由默认相似度规则（SIMILARITY >= 0.90）处理，不再硬编码
     */
    private static JudgmentOutcome judgeDefault(int statusCode, int baselineStatusCode,
                                                 double similarity, double similarityThreshold) {
        if (statusCode != baselineStatusCode) {
            // 状态码不同 → 越权
            return new JudgmentOutcome(JudgmentResult.ESCALATED, Color.RED,
                    "状态码不同: 基准=" + baselineStatusCode + ", 当前=" + statusCode,
                    similarity, null);
        }

        if (similarity < 0) {
            // 无法计算相似度 → 挂起，需人工确认
            return new JudgmentOutcome(JudgmentResult.PENDING, Color.YELLOW,
                    "无法计算相似度", similarity, null);
        }

        // 所有规则均不匹配，且状态码相同 → 需人工确认
        return new JudgmentOutcome(JudgmentResult.PENDING, Color.YELLOW,
                "所有规则均不匹配，需人工确认", similarity, null);
    }

    /**
     * 条件组合求值（AND/OR/NOT 逻辑）
     * 按条件列表顺序从左到右求值，无括号优先级
     *
     * @param conditions       条件列表
     * @param statusCode       响应状态码
     * @param responseHeaders  响应头
     * @param bodyStr          响应体字符串
     * @param similarity       与基准的相似度
     * @param responseTimeMs   响应时间
     * @param responseBody     当前响应体
     * @param baselineResponse 基准响应体
     * @return 条件组合是否满足
     */
    private static boolean evaluateConditions(List<RuleCondition> conditions,
                                               int statusCode, String responseHeaders,
                                               String bodyStr, double similarity,
                                               long responseTimeMs,
                                               byte[] responseBody, byte[] baselineResponse) {
        if (conditions == null || conditions.isEmpty()) return false;

        boolean result = true;  // 初始值为 true（单位元）
        for (RuleCondition cond : conditions) {
            if (!cond.isValid()) continue;

            // 1. 计算当前条件的原始匹配结果
            String targetValue = extractTargetValue(cond.getTarget(), statusCode,
                    responseHeaders, bodyStr, similarity, responseTimeMs);
            boolean condResult = matchValue(cond.getMethod(), cond.getExpression(),
                    targetValue, statusCode, responseBody, baselineResponse);

            // 2. 应用 NOT（取反）
            if (cond.isNegate()) {
                condResult = !condResult;
            }

            // 3. 按运算符与累积结果组合
            if (cond.getOperator() == RuleCondition.LogicalOperator.AND) {
                result = result && condResult;
            } else {  // OR
                result = result || condResult;
            }
        }
        return result;
    }

    /**
     * 从响应头字符串中提取 Content-Type 值
     *
     * @param responseHeaders 响应头字符串（多行格式）
     * @return Content-Type 值，未找到时返回 null
     */
    private static String extractContentType(String responseHeaders) {
        if (responseHeaders == null || responseHeaders.isEmpty()) return null;
        Pattern p = Pattern.compile("(?i)Content-Type\\s*:\\s*(.+?)(?:\r?\n|$)");
        Matcher m = p.matcher(responseHeaders);
        return m.find() ? m.group(1).trim() : null;
    }

    /**
     * 提取规则目标值
     */
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

    /**
     * 根据匹配方法判断目标值是否匹配表达式
     *
     * @param method        匹配方法
     * @param expression    匹配表达式
     * @param targetValue   目标值（字符串形式）
     * @param statusCode    响应状态码
     * @param responseBody  当前响应体字节数组（LENGTH_DIFF 使用）
     * @param baselineResponse 基准响应体字节数组（LENGTH_DIFF 使用）
     */
    private static boolean matchValue(RuleMethod method, String expression,
                                       String targetValue, int statusCode,
                                       byte[] responseBody, byte[] baselineResponse) {
        if (expression == null || expression.isEmpty()) return false;

        try {
            return switch (method) {
                case REGEX -> {
                    try {
                        Pattern pattern = Pattern.compile(expression);
                        yield pattern.matcher(targetValue).find();
                    } catch (PatternSyntaxException e) {
                        LogManager.getInstance().printError("[!] 判决规则正则表达式无效: " + expression);
                        yield false;
                    }
                }
                case CONTAINS -> targetValue.contains(expression);
                case NOT_CONTAINS -> !targetValue.contains(expression);
                case EQUALS -> targetValue.equals(expression);
                case NOT_EQUALS -> !targetValue.equals(expression);
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
                case NUMERIC_EQUALS -> {
                    try {
                        yield Double.parseDouble(targetValue.trim()) == Double.parseDouble(expression.trim());
                    } catch (NumberFormatException e) {
                        yield false;
                    }
                }
                case LENGTH_DIFF -> {
                    try {
                        int currentLen = responseBody != null ? responseBody.length : 0;
                        int baselineLen = baselineResponse != null ? baselineResponse.length : 0;
                        long diff = Math.abs((long) currentLen - (long) baselineLen);
                        yield diff > Double.parseDouble(expression.trim());
                    } catch (NumberFormatException e) {
                        yield false;
                    }
                }
            };
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] 判决规则匹配异常: " + e.getMessage());
            return false;
        }
    }
}

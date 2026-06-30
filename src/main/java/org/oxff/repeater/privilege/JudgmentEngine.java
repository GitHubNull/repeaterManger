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
 * 判决引擎 - 无状态工具类（v13：单活跃规则集 + 三层兜底）
 * 根据判决规则对响应进行越权判断
 *
 * 判决逻辑（三层）：
 * 1. 基准无效 → ERROR
 * 2. 空Body检测 → 专门判决（跳过规则匹配）
 * 3. 第2层：活跃规则组判决（有活跃规则组时优先）
 *    - getActiveRule() → evaluateConditions(纯AND)
 *    - 全部条件满足 → ESCALATED
 *    - 任一条件不满足或无活跃规则组 → 进入第3层兜底
 * 4. 第3层：兜底默认相似度判决
 *    - similarity >= threshold → ESCALATED
 *    - similarity < threshold → NOT_ESCALATED
 *    - 无法计算相似度 → 状态码判决 → PENDING
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
     * @param baselineContentType 基准用户响应的 Content-Type（优先使用，为 null 时回退到测试用户 Content-Type）
     * @param similarityThreshold 相似度阈值（0.0~1.0），默认0.7，用于区分越权与安全
     * @param responseTimeMs    响应时间（毫秒）
     * @param allTokensEmpty    当前测试用户是否所有令牌值均为空（用于未登录用户的401/403降级判决）
     * @return 判决结果
     */
    public static JudgmentOutcome judge(int statusCode, String responseHeaders,
                                         byte[] responseBody, byte[] baselineResponse,
                                         int baselineStatusCode,
                                         String baselineContentType,
                                         double similarityThreshold,
                                         long responseTimeMs,
                                         boolean allTokensEmpty) {
        // 防护守卫：拒绝对无效基准进行判决，防止因基准响应丢失导致误判
        if (baselineResponse == null) {
            if (baselineStatusCode <= 0) {
                // 完全无效：基准响应体和状态码均不可用
                return new JudgmentOutcome(JudgmentResult.ERROR, null,
                        "基准响应无效，无法进行判决", -1, null);
            }
            // 状态码合法但 body 为空（如 204 No Content）→ 走空 Body 判决
            return judgeWithEmptyBody(
                    statusCode, responseBody, null,
                    baselineStatusCode,
                    true,  // baselineBodyEmpty
                    isBodyEmpty(responseBody),
                    similarityThreshold);
        }

        JudgmentRuleManager ruleManager = JudgmentRuleManager.getInstance();

        // === 空 Body 感知预处理 ===
        boolean baselineBodyEmpty = isBodyEmpty(baselineResponse);
        boolean currentBodyEmpty = isBodyEmpty(responseBody);

        if (baselineBodyEmpty || currentBodyEmpty) {
            // 当用户配置了活跃规则组且其中有 RESPONSE_BODY 条件时，仍走规则匹配流程
            JudgmentRule activeRule = ruleManager.getActiveRule();
            boolean hasBodyRule = false;
            if (activeRule != null && activeRule.isEnabled() && activeRule.isValid()) {
                for (RuleCondition cond : activeRule.getEffectiveConditions()) {
                    if (cond.getTarget() == RuleTarget.RESPONSE_BODY) {
                        hasBodyRule = true;
                        break;
                    }
                }
            }
            if (!hasBodyRule) {
                LogManager.getInstance().judgmentDebug(String.format(
                        "[判决] 进入空Body判决: 基线body空=%b(%d字节)/测试body空=%b(%d字节), 基线状态码=%d, 测试状态码=%d",
                        baselineBodyEmpty, baselineResponse != null ? baselineResponse.length : -1,
                        currentBodyEmpty, responseBody != null ? responseBody.length : -1,
                        baselineStatusCode, statusCode));
                return judgeWithEmptyBody(statusCode, responseBody, baselineResponse,
                        baselineStatusCode, baselineBodyEmpty, currentBodyEmpty, similarityThreshold);
            }
        }

        // 计算相似度（使用内容感知的混合算法）
        double similarity = -1;
        if (baselineResponse != null && responseBody != null) {
            String respStr = new String(responseBody, StandardCharsets.UTF_8);
            String baseStr = new String(baselineResponse, StandardCharsets.UTF_8);
            // 优先使用基线 Content-Type；若不可用则回退到测试用户 Content-Type
            String effectiveContentType = baselineContentType != null
                    ? baselineContentType
                    : extractContentType(responseHeaders);
            similarity = SimilarityEngine.similarity(respStr, baseStr, effectiveContentType);
        }

        LogManager.getInstance().judgmentDebug(String.format(
                "[判决] judge() 入参: statusCode=%d, bodyLen=%d, baselineBodyLen=%d, threshold=%.2f, respTimeMs=%d, contentType=%s, similarity=%.4f",
                statusCode, responseBody != null ? responseBody.length : -1,
                baselineResponse != null ? baselineResponse.length : -1,
                similarityThreshold, responseTimeMs,
                extractContentType(responseHeaders), similarity));

        // 第2层：活跃规则组判决
        JudgmentRule activeRule = ruleManager.getActiveRule();
        if (activeRule != null && activeRule.isEnabled() && activeRule.isValid()) {
            return judgeWithActiveRule(activeRule, statusCode, responseHeaders, responseBody,
                    baselineResponse, baselineStatusCode, similarity, similarityThreshold, responseTimeMs,
                    allTokensEmpty);
        }

        // 无活跃规则组时：回退到第3层兜底
        return judgeDefault(statusCode, baselineStatusCode, similarity, similarityThreshold, allTokensEmpty);
    }

    /**
     * 使用单一活跃规则组进行判决（v13：替代原多规则迭代）
     */
    private static JudgmentOutcome judgeWithActiveRule(JudgmentRule rule, int statusCode,
                                                        String responseHeaders, byte[] responseBody,
                                                        byte[] baselineResponse,
                                                        int baselineStatusCode,
                                                        double similarity, double similarityThreshold,
                                                        long responseTimeMs,
                                                        boolean allTokensEmpty) {
        String bodyStr = responseBody != null ? new String(responseBody, StandardCharsets.UTF_8) : "";

        LogManager.getInstance().judgmentDebug(String.format(
                "[判决] 活跃规则组评估: name='%s'", rule.getName()));

        List<RuleCondition> conditions = rule.getEffectiveConditions();
        boolean allMatched = evaluateConditions(conditions, statusCode,
                responseHeaders, bodyStr, similarity, responseTimeMs,
                responseBody, baselineResponse);

        if (allMatched) {
            LogManager.getInstance().judgmentDebug(String.format(
                    "[判决] 规则组命中: '%s' → ESCALATED", rule.getName()));
            String note = rule.getSuccessNote();
            if (note == null || note.isEmpty()) {
                note = "规则匹配: " + rule.getName();
            }
            return new JudgmentOutcome(JudgmentResult.ESCALATED, rule.getSuccessColor(),
                    note, similarity, rule.getName());
        }

        // 活跃规则组未命中 → 尝试默认相似度规则组作为安全网兜底
        LogManager.getInstance().judgmentDebug(String.format(
                "[判决] 规则组未命中: '%s' → 尝试默认相似度规则组作为安全网", rule.getName()));

        JudgmentRule defaultRule = JudgmentRuleManager.getInstance().getDefaultSimilarityRule();
        if (defaultRule != null && defaultRule != rule
                && defaultRule.isEnabled() && defaultRule.isValid()) {
            LogManager.getInstance().judgmentDebug(String.format(
                    "[判决] 默认相似度规则组评估: name='%s'", defaultRule.getName()));

            List<RuleCondition> defaultConditions = defaultRule.getEffectiveConditions();
            boolean defaultAllMatched = evaluateConditions(defaultConditions, statusCode,
                    responseHeaders, bodyStr, similarity, responseTimeMs,
                    responseBody, baselineResponse);

            if (defaultAllMatched) {
                LogManager.getInstance().judgmentDebug(String.format(
                        "[判决] 默认规则组命中: '%s' → ESCALATED", defaultRule.getName()));
                String defaultNote = defaultRule.getSuccessNote();
                if (defaultNote == null || defaultNote.isEmpty()) {
                    defaultNote = "默认规则匹配: " + defaultRule.getName();
                }
                return new JudgmentOutcome(JudgmentResult.ESCALATED, defaultRule.getSuccessColor(),
                        defaultNote, similarity, defaultRule.getName());
            }

            LogManager.getInstance().judgmentDebug(String.format(
                    "[判决] 默认规则组未命中: '%s' → 回退默认判决", defaultRule.getName()));
        }

        return judgeDefault(statusCode, baselineStatusCode, similarity, similarityThreshold, allTokensEmpty);
    }

    /**
     * 默认判决逻辑：基于相似度阈值 + 状态码差异进行多段式判决
     * 
     * 判决语义（优先级从高到低）：
     * - 相似度 >= 阈值 → ESCALATED（响应高度相似，低权限用户拿到了高权限数据）
     * - 相似度 < 阈值 && 状态码显著差异(2xx vs 401/403) && allTokensEmpty → NOT_ESCALATED（未登录被正确拒绝）
     * - 相似度 < 阈值 && 状态码显著差异(2xx vs 401/403) && !allTokensEmpty → PENDING（疑似令牌配置错误）
     * - 0 <= 相似度 < 阈值 && 状态码无明显差异 → NOT_ESCALATED（响应差异显著但非权限相关）
     * - 相似度 < 0（无法计算）→ 回退到状态码检查，状态码不同 → PENDING
     */
    private static JudgmentOutcome judgeDefault(int statusCode, int baselineStatusCode,
                                                 double similarity, double similarityThreshold,
                                                 boolean allTokensEmpty) {
        // 能够计算相似度时，以相似度为主要判决依据
        if (similarity >= 0) {
            if (similarity >= similarityThreshold) {
                LogManager.getInstance().judgmentDebug(String.format(
                        "[判决] 默认判决: similarity=%.4f >= threshold=%.2f → ESCALATED", similarity, similarityThreshold));
                // 相似度高于阈值：低权限用户响应与基准高度相似 → 越权
                return new JudgmentOutcome(JudgmentResult.ESCALATED, Color.RED,
                        String.format("相似度%.1f%% >= 阈值%.1f%%，疑似越权", similarity * 100, similarityThreshold * 100),
                        similarity, null);
            }

            // === 状态码差异检测：相似度低但状态码显著不同的情况 ===
            // 当基准返回2xx(成功)而测试用户返回401/403(认证/授权失败)时，
            // 这通常意味着令牌未配置或权限不足，不应简单标记为"安全"
            boolean baselineSuccess = (baselineStatusCode >= 200 && baselineStatusCode < 300);
            boolean testAuthFailure = (statusCode == 401 || statusCode == 403);
            boolean testOther4xx = (statusCode >= 400 && statusCode < 500 && !testAuthFailure);

            if (baselineSuccess && testAuthFailure) {
                // 区分：令牌全部为空（游客/未登录）→ 预期被拒绝，安全；否则可能是令牌配置错误 → 需确认
                if (allTokensEmpty) {
                    LogManager.getInstance().judgmentDebug(String.format(
                            "[判决] 默认判决: similarity=%.4f < threshold=%.2f, baseline=%d(成功) vs test=%d(认证失败), allTokensEmpty=true → NOT_ESCALATED(未登录被正确拒绝)",
                            similarity, similarityThreshold, baselineStatusCode, statusCode));
                    return new JudgmentOutcome(JudgmentResult.NOT_ESCALATED, new Color(0, 130, 0),
                            String.format("未登录用户被正确拒绝访问 (%d)", statusCode),
                            similarity, null);
                }
                LogManager.getInstance().judgmentDebug(String.format(
                        "[判决] 默认判决: similarity=%.4f < threshold=%.2f, baseline=%d(成功) vs test=%d(认证失败) → PENDING",
                        similarity, similarityThreshold, baselineStatusCode, statusCode));
                return new JudgmentOutcome(JudgmentResult.PENDING, new Color(255, 140, 0),
                        String.format("状态码差异: 基准=%d(成功) → 测试=%d(认证失败)，疑似令牌未配置或无权限",
                                baselineStatusCode, statusCode),
                        similarity, null);
            }

            if (baselineSuccess && testOther4xx) {
                LogManager.getInstance().judgmentDebug(String.format(
                        "[判决] 默认判决: similarity=%.4f < threshold=%.2f, baseline=%d(成功) vs test=%d(客户端错误) → 需关注",
                        similarity, similarityThreshold, baselineStatusCode, statusCode));
                // 基准成功但测试返回4xx（404/405等），也可能是权限相关，标记为需关注
                return new JudgmentOutcome(JudgmentResult.PENDING, new Color(255, 200, 0),
                        String.format("状态码差异: 基准=%d(成功) → 测试=%d(客户端错误)，请检查响应内容",
                                baselineStatusCode, statusCode),
                        similarity, null);
            }

            LogManager.getInstance().judgmentDebug(String.format(
                    "[判决] 默认判决: similarity=%.4f < threshold=%.2f → NOT_ESCALATED", similarity, similarityThreshold));
            // 相似度低于阈值且状态码无显著权限差异 → 安全
            return new JudgmentOutcome(JudgmentResult.NOT_ESCALATED, new Color(0, 130, 0),
                    String.format("相似度%.1f%% < 阈值%.1f%%，响应差异显著", similarity * 100, similarityThreshold * 100),
                    similarity, null);
        }

        // 无法计算相似度时，回退到状态码检查
        if (statusCode != baselineStatusCode) {
            LogManager.getInstance().judgmentDebug(String.format(
                    "[判决] 默认判决: similarity<0, statusCode=%d != baselineStatusCode=%d → PENDING", statusCode, baselineStatusCode));
            return new JudgmentOutcome(JudgmentResult.PENDING, Color.YELLOW,
                    "状态码不同但无法计算相似度: 基准=" + baselineStatusCode + ", 当前=" + statusCode,
                    similarity, null);
        }

        LogManager.getInstance().judgmentDebug("[判决] 默认判决: similarity<0, 状态码相同, 无法计算 → PENDING");
        // 无法计算相似度且状态码相同 → 挂起，需人工确认
        return new JudgmentOutcome(JudgmentResult.PENDING, Color.YELLOW,
                "无法计算相似度", similarity, null);
    }

    /**
     * 条件求值（v13：纯 AND 语义）
     *
     * 组内所有有效条件必须全部满足才算命中，任一条件不满足即短路退出。
     * 后续版本如需引入 OR 支持，需补全 operator 持久化链路（Schema/DAO/YAML/UI）。
     *
     * @param conditions       条件列表
     * @param statusCode       响应状态码
     * @param responseHeaders  响应头
     * @param bodyStr          响应体字符串
     * @param similarity       与基准的相似度
     * @param responseTimeMs   响应时间
     * @param responseBody     当前响应体
     * @param baselineResponse 基准响应体
     * @return 全部有效条件满足时返回 true
     */
    private static boolean evaluateConditions(List<RuleCondition> conditions,
                                               int statusCode, String responseHeaders,
                                               String bodyStr, double similarity,
                                               long responseTimeMs,
                                               byte[] responseBody, byte[] baselineResponse) {
        if (conditions == null || conditions.isEmpty()) {
            LogManager.getInstance().judgmentDebug("[判决] evaluateConditions: 条件列表为空 → false");
            return false;
        }

        boolean hasAnyValidCondition = false;

        for (RuleCondition cond : conditions) {
            if (!cond.isValid()) {
                LogManager.getInstance().judgmentDebug("[判决]   条件无效,跳过");
                continue;
            }

            hasAnyValidCondition = true;

            // 计算当前条件的原始匹配结果
            String targetValue = extractTargetValue(cond.getTarget(), statusCode,
                    responseHeaders, bodyStr, similarity, responseTimeMs);
            boolean condResult = matchValue(cond.getMethod(), cond.getExpression(),
                    targetValue, statusCode, responseBody, baselineResponse);

            // 应用 NOT（取反）
            boolean beforeNegate = condResult;
            if (cond.isNegate()) {
                condResult = !condResult;
            }

            // 截断用于日志展示的 value（避免大响应体撑爆日志）
            String displayValue = targetValue != null && targetValue.length() > 200
                    ? targetValue.substring(0, 200) + "...(截断)" : targetValue;

            LogManager.getInstance().judgmentDebug(String.format(
                    "[判决]   target=%s, method=%s, expr='%s', value='%s' → rawMatch=%b, negate=%b(→%b)",
                    cond.getTarget().name(), cond.getMethod().name(), cond.getExpression(),
                    displayValue, beforeNegate, cond.isNegate(), condResult));

            // 纯 AND：任一条件不满足即短路退出
            if (!condResult) {
                LogManager.getInstance().judgmentDebug("[判决]   → AND短路: 条件不满足, 最终结果=false");
                return false;
            }
        }

        if (!hasAnyValidCondition) {
            LogManager.getInstance().judgmentDebug("[判决]   → 所有条件无效");
            return false;
        }

        LogManager.getInstance().judgmentDebug("[判决]   → 全部条件满足, 最终结果=true");
        return true;
    }

    /**
     * 从响应头字符串中提取 Content-Type 值
     *
     * @param responseHeaders 响应头字符串（多行格式）
     * @return Content-Type 值，未找到时返回 null
     */
    static String extractContentType(String responseHeaders) {
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

    // ==================== 空 Body 判决 ====================

    /**
     * 判断 body 是否为空（null 或长度=0）
     */
    private static boolean isBodyEmpty(byte[] body) {
        return body == null || body.length == 0;
    }

    /**
     * 空 Body 场景的专门判决逻辑
     * <p>
     * 当基线或测试响应体为空时,body 相似度无意义,
     * 转而通过状态码 + body 有无的组合来推断越权风险。
     *
     * @param statusCode         测试用户响应状态码
     * @param responseBody       测试用户响应体
     * @param baselineResponse   基准用户响应体
     * @param baselineStatusCode 基准用户状态码
     * @param baselineBodyEmpty  基准 body 是否为空
     * @param currentBodyEmpty   测试 body 是否为空
     * @param threshold          相似度阈值(此处仅用于日志)
     */
    private static JudgmentOutcome judgeWithEmptyBody(int statusCode, byte[] responseBody,
                                                       byte[] baselineResponse,
                                                       int baselineStatusCode,
                                                       boolean baselineBodyEmpty,
                                                       boolean currentBodyEmpty,
                                                       double threshold) {
        if (baselineBodyEmpty && currentBodyEmpty) {
            // 双方 body 均为空
            if (statusCode == baselineStatusCode) {
                LogManager.getInstance().printOutput(String.format(
                        "[*] 空Body判决: 双方body均为空, 状态码相同(%d) → 安全(被同等限制)", statusCode));
                return new JudgmentOutcome(JudgmentResult.NOT_ESCALATED, new Color(0, 130, 0),
                        String.format("双方body均为空,状态码相同(%d),被同等限制", statusCode), -1, null);
            } else {
                LogManager.getInstance().printOutput(String.format(
                        "[*] 空Body判决: 双方body均为空, 状态码不同(基准=%d,测试=%d) → 待确认",
                        baselineStatusCode, statusCode));
                return new JudgmentOutcome(JudgmentResult.PENDING, Color.YELLOW,
                        String.format("双方body均为空,状态码不同(基准=%d,测试=%d),需人工确认",
                                baselineStatusCode, statusCode), -1, null);
            }
        }

        if (baselineBodyEmpty && !currentBodyEmpty) {
            // 基线空, 测试有内容 → 测试用户拿到了数据!
            if (statusCode >= 200 && statusCode < 400) {
                LogManager.getInstance().printOutput(String.format(
                        "[*] 空Body判决: 基线body空,测试body非空(%d字节),状态码=%d → 越权! 拿到了不该拿的数据",
                        responseBody != null ? responseBody.length : 0, statusCode));
                return new JudgmentOutcome(JudgmentResult.ESCALATED, Color.RED,
                        String.format("基线body为空但测试返回%d字节,状态码%d,疑似越权",
                                responseBody != null ? responseBody.length : 0, statusCode),
                        -1, null);
            } else {
                LogManager.getInstance().printOutput(String.format(
                        "[*] 空Body判决: 基线body空,测试body非空(%d字节),状态码=%d → 安全(被拒绝)",
                        responseBody != null ? responseBody.length : 0, statusCode));
                return new JudgmentOutcome(JudgmentResult.NOT_ESCALATED, new Color(0, 130, 0),
                        String.format("基线body为空,测试状态码%d,无越权迹象", statusCode), -1, null);
            }
        }

        if (!baselineBodyEmpty && currentBodyEmpty) {
            // 基线有内容, 测试空
            if (statusCode >= 400 && statusCode < 500) {
                LogManager.getInstance().printOutput(String.format(
                        "[*] 空Body判决: 基线body非空(%d字节),测试body空,状态码=%d → 安全(正确被拒绝)",
                        baselineResponse != null ? baselineResponse.length : 0, statusCode));
                return new JudgmentOutcome(JudgmentResult.NOT_ESCALATED, new Color(0, 130, 0),
                        String.format("测试被拒绝(状态码%d),无越权迹象", statusCode), -1, null);
            } else if (statusCode >= 200 && statusCode < 300) {
                LogManager.getInstance().printOutput(String.format(
                        "[*] 空Body判决: 基线body非空(%d字节),测试body空,状态码=%d → 安全(如204等)",
                        baselineResponse != null ? baselineResponse.length : 0, statusCode));
                return new JudgmentOutcome(JudgmentResult.NOT_ESCALATED, new Color(0, 130, 0),
                        String.format("测试状态码%d但body为空(如204),无越权迹象", statusCode), -1, null);
            } else {
                LogManager.getInstance().printOutput(String.format(
                        "[*] 空Body判决: 基线body非空(%d字节),测试body空,状态码=%d → 待确认",
                        baselineResponse != null ? baselineResponse.length : 0, statusCode));
                return new JudgmentOutcome(JudgmentResult.PENDING, Color.YELLOW,
                        String.format("测试body为空,状态码%d,需人工确认", statusCode), -1, null);
            }
        }

        // 兜底: 不应到达这里
        return new JudgmentOutcome(JudgmentResult.PENDING, Color.YELLOW,
                "空Body判决逻辑异常", -1, null);
    }
}

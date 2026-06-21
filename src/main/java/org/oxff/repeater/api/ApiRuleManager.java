package org.oxff.repeater.api;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * API提取规则管理器（单例）
 * 三源合并：项目SQLite + 全局YAML + 内存临时规则
 * 缓存已启用的提取规则，避免每次请求都查询数据源
 */
public class ApiRuleManager {
    private static ApiRuleManager instance;
    private final ApiExtractionRuleDAO ruleDAO;
    private List<ApiExtractionRule> cachedActiveRules;
    private long lastRefreshTime = 0;
    private static final long REFRESH_INTERVAL = 30 * 1000; // 30秒刷新缓存

    // 内存临时规则列表（非持久化、非全局的规则，重启后丢失）
    private final List<ApiExtractionRule> tempRules = new ArrayList<>();
    private int tempIdGenerator = -100000; // 临时规则ID，从-100000开始，避免与全局规则负数ID冲突

    private ApiRuleManager() {
        this.ruleDAO = new ApiExtractionRuleDAO();
        this.cachedActiveRules = new ArrayList<>();
    }

    /**
     * 获取单例实例
     */
    public static synchronized ApiRuleManager getInstance() {
        if (instance == null) {
            instance = new ApiRuleManager();
        }
        return instance;
    }

    /**
     * 获取所有已启用的规则（带缓存）
     * 三源合并：项目SQLite + 全局YAML + 内存临时规则
     * 基于 source + method + expression 去重
     * 按优先级升序排列
     */
    public List<ApiExtractionRule> getActiveRules() {
        long now = System.currentTimeMillis();
        if (cachedActiveRules.isEmpty() || (now - lastRefreshTime) > REFRESH_INTERVAL) {
            refreshCache();
        }
        return cachedActiveRules;
    }

    /**
     * 获取所有规则（包含禁用的），用于UI显示
     * 三源合并：项目SQLite + 全局YAML + 内存临时规则
     */
    public List<ApiExtractionRule> getAllRulesForDisplay() {
        List<ApiExtractionRule> allRules = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>(); // 去重键：source|method|expression

        // 1. 项目SQLite规则（最高优先级，先加入）
        List<ApiExtractionRule> projectRules = ruleDAO.getAllRules();
        for (ApiExtractionRule rule : projectRules) {
            String key = dedupKey(rule);
            if (seen.add(key)) {
                allRules.add(rule);
            }
        }

        // 2. 全局YAML规则（与项目规则去重）
        List<ApiExtractionRule> globalRules = GlobalRuleManager.getInstance().getAllRules();
        for (ApiExtractionRule rule : globalRules) {
            String key = dedupKey(rule);
            if (seen.add(key)) {
                allRules.add(rule);
            }
        }

        // 3. 内存临时规则（与前两者去重）
        synchronized (tempRules) {
            for (ApiExtractionRule rule : tempRules) {
                String key = dedupKey(rule);
                if (seen.add(key)) {
                    allRules.add(rule);
                }
            }
        }

        // 按优先级排序
        allRules.sort((a, b) -> {
            int cmp = Integer.compare(a.getPriority(), b.getPriority());
            return cmp != 0 ? cmp : Integer.compare(a.getId(), b.getId());
        });

        return allRules;
    }

    /**
     * 强制刷新缓存
     */
    public void refreshCache() {
        List<ApiExtractionRule> allRules = getAllRulesForDisplay();
        List<ApiExtractionRule> activeRules = new ArrayList<>();
        for (ApiExtractionRule rule : allRules) {
            if (rule.isEnabled() && rule.isValid()) {
                activeRules.add(rule);
            }
        }
        cachedActiveRules = activeRules;
        lastRefreshTime = System.currentTimeMillis();
    }

    /**
     * 添加规则（路由到正确的存储）
     *
     * @param rule 规则对象（persistent/global字段决定存储位置）
     * @return 规则ID，失败返回-1
     */
    public int addRule(ApiExtractionRule rule) {
        int id = -1;

        if (rule.isPersistent()) {
            // 持久化到项目SQLite
            id = ruleDAO.saveRule(rule);
            if (id > 0) {
                rule.setId(id);
            }
        }

        if (rule.isGlobal()) {
            // 持久化到全局YAML
            int globalId = GlobalRuleManager.getInstance().addRule(rule);
            if (id == -1) {
                id = globalId;
            }
        }

        if (!rule.isPersistent() && !rule.isGlobal()) {
            // 内存临时规则
            synchronized (tempRules) {
                rule.setId(tempIdGenerator--);
                tempRules.add(rule);
                id = rule.getId();
            }
        }

        refreshCache();
        return id;
    }

    /**
     * 更新规则（路由到正确的存储，处理存储位置变更）
     *
     * @param oldRule 编辑前的规则（用于判断存储位置变更）
     * @param newRule 编辑后的规则
     */
    public boolean updateRule(ApiExtractionRule oldRule, ApiExtractionRule newRule) {
        boolean success = false;
        newRule.setId(oldRule.getId());

        // 处理项目SQLite持久化变更
        boolean wasPersistent = oldRule.isPersistent();
        boolean isPersistent = newRule.isPersistent();

        if (wasPersistent && isPersistent) {
            // 仍然是项目持久化，更新SQLite
            success = ruleDAO.updateRule(newRule);
        } else if (wasPersistent && !isPersistent) {
            // 从项目持久化变为非持久化，从SQLite删除
            ruleDAO.deleteRule(oldRule.getId());
        } else if (!wasPersistent && isPersistent) {
            // 从非持久化变为项目持久化，插入SQLite
            int newId = ruleDAO.saveRule(newRule);
            if (newId > 0) {
                newRule.setId(newId);
                success = true;
            }
        }

        // 处理全局YAML持久化变更
        boolean wasGlobal = oldRule.isGlobal();
        boolean isGlobal = newRule.isGlobal();

        if (wasGlobal && isGlobal) {
            // 仍然是全局，更新全局YAML
            GlobalRuleManager.getInstance().updateRule(newRule);
            success = true;
        } else if (wasGlobal && !isGlobal) {
            // 从全局变为非全局，从全局YAML删除
            GlobalRuleManager.getInstance().deleteRule(oldRule.getId());
        } else if (!wasGlobal && isGlobal) {
            // 从非全局变为全局，添加到全局YAML
            GlobalRuleManager.getInstance().addRule(newRule);
            success = true;
        }

        // 处理临时规则变更
        if (!wasPersistent && !isPersistent && !wasGlobal && !isGlobal) {
            // 仍然是临时规则，在内存中更新
            synchronized (tempRules) {
                for (int i = 0; i < tempRules.size(); i++) {
                    if (tempRules.get(i).getId() == oldRule.getId()) {
                        tempRules.set(i, newRule);
                        success = true;
                        break;
                    }
                }
            }
        } else if (!wasPersistent && !wasGlobal) {
            // 从临时规则移出，删除内存中的规则
            synchronized (tempRules) {
                tempRules.removeIf(r -> r.getId() == oldRule.getId());
            }
        }

        // 如果规则新状态是临时，需要加入临时列表
        if (!isPersistent && !isGlobal && (wasPersistent || wasGlobal)) {
            synchronized (tempRules) {
                newRule.setId(tempIdGenerator--);
                tempRules.add(newRule);
                success = true;
            }
        }

        refreshCache();
        return success;
    }

    /**
     * 删除规则（从所有存储位置删除）
     */
    public boolean deleteRule(int id) {
        boolean success = false;

        // 尝试从项目SQLite删除
        if (id > 0) {
            success = ruleDAO.deleteRule(id);
        }

        // 尝试从全局YAML删除
        if (GlobalRuleManager.getInstance().getRuleById(id) != null) {
            success = GlobalRuleManager.getInstance().deleteRule(id) || success;
        }

        // 尝试从内存临时规则删除
        synchronized (tempRules) {
            success = tempRules.removeIf(r -> r.getId() == id) || success;
        }

        refreshCache();
        return success;
    }

    /**
     * 根据ID获取规则（从所有数据源查找）
     */
    public ApiExtractionRule getRuleById(int id) {
        // 1. 尝试从项目SQLite获取
        if (id > 0) {
            ApiExtractionRule rule = ruleDAO.getRuleById(id);
            if (rule != null) return rule;
        }

        // 2. 尝试从全局YAML获取
        ApiExtractionRule globalRule = GlobalRuleManager.getInstance().getRuleById(id);
        if (globalRule != null) return globalRule;

        // 3. 尝试从内存临时规则获取
        synchronized (tempRules) {
            for (ApiExtractionRule rule : tempRules) {
                if (rule.getId() == id) {
                    return rule;
                }
            }
        }

        return null;
    }

    /**
     * 删除所有规则（从所有存储位置）
     */
    public boolean deleteAllRules() {
        boolean success = true;

        // 清空项目SQLite
        success = ruleDAO.deleteAllRules() && success;

        // 清空全局YAML
        success = GlobalRuleManager.getInstance().deleteAllRules() && success;

        // 清空内存临时规则
        synchronized (tempRules) {
            tempRules.clear();
        }

        refreshCache();
        return success;
    }

    /**
     * 导出所有规则为YAML格式
     * 包含所有来源的规则（含禁用的）
     */
    public String exportAllRulesToYaml() {
        List<ApiExtractionRule> allRules = getAllRulesForDisplay();
        return ApiRuleYamlIO.toYaml(allRules);
    }

    /**
     * 从YAML导入规则（合并模式）
     * 基于 source + method + expression 去重
     *
     * @return 实际新增的规则数量
     */
    public int importRulesMerge(List<ApiExtractionRule> newRules) {
        int added = 0;
        Set<String> existingKeys = new LinkedHashSet<>();

        // 收集所有现有规则的去重键
        for (ApiExtractionRule rule : getAllRulesForDisplay()) {
            existingKeys.add(dedupKey(rule));
        }

        for (ApiExtractionRule newRule : newRules) {
            String key = dedupKey(newRule);
            if (!existingKeys.contains(key)) {
                addRule(newRule);
                existingKeys.add(key);
                added++;
            }
        }

        refreshCache();
        return added;
    }

    /**
     * 从YAML导入规则（替换模式）
     * 清除所有现有规则，用新规则替换
     */
    public void importRulesReplace(List<ApiExtractionRule> newRules) {
        // 清空所有存储
        ruleDAO.deleteAllRules();
        GlobalRuleManager.getInstance().deleteAllRules();
        synchronized (tempRules) {
            tempRules.clear();
        }

        // 添加新规则（默认全部持久化到项目和全局）
        for (ApiExtractionRule rule : newRules) {
            rule.setPersistent(true);
            rule.setGlobal(true);
            addRule(rule);
        }

        refreshCache();
    }

    /**
     * 生成去重键
     */
    private String dedupKey(ApiExtractionRule rule) {
        return rule.getSource().toDbValue() + "|" + rule.getMethod().toDbValue() + "|" + rule.getExpression();
    }
}

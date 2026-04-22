package oxff.top.api;

import java.util.ArrayList;
import java.util.List;

/**
 * API提取规则管理器（单例）
 * 缓存已启用的提取规则，避免每次请求都查询数据库
 */
public class ApiRuleManager {
    private static ApiRuleManager instance;
    private final ApiExtractionRuleDAO ruleDAO;
    private List<ApiExtractionRule> cachedActiveRules;
    private long lastRefreshTime = 0;
    private static final long REFRESH_INTERVAL = 30 * 1000; // 30秒刷新缓存

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
     * 强制刷新缓存
     */
    public void refreshCache() {
        List<ApiExtractionRule> allRules = ruleDAO.getAllRules();
        List<ApiExtractionRule> activeRules = new ArrayList<>();
        for (ApiExtractionRule rule : allRules) {
            if (rule.isEnabled() && rule.isValid()) {
                activeRules.add(rule);
            }
        }
        cachedActiveRules = activeRules;
        lastRefreshTime = System.currentTimeMillis();
    }
}

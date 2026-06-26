package org.oxff.repeater.privilege;

import burp.BurpExtender;
import org.oxff.repeater.privilege.dao.SessionDAO;
import org.oxff.repeater.privilege.model.ReplayConfig;
import org.oxff.repeater.privilege.model.TokenLocation;
import org.oxff.repeater.privilege.model.TokenLocationType;
import org.oxff.repeater.privilege.model.TokenScheme;
import org.oxff.repeater.privilege.model.UserSession;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 会话管理器（单例）
 * 管理令牌位置、令牌方案和用户会话的CRUD操作，缓存已启用的会话列表
 */
public class SessionManager {

    private static SessionManager instance;

    private final SessionDAO sessionDAO;

    /** 缓存的令牌位置列表 */
    private List<TokenLocation> cachedTokenLocations;

    /** 缓存的令牌方案列表 */
    private List<TokenScheme> cachedTokenSchemes;

    /** 缓存的用户会话列表 */
    private List<UserSession> cachedUserSessions;

    /** 缓存的已启用用户会话列表 */
    private List<UserSession> cachedEnabledSessions;

    /** 全局重放配置 */
    private final ReplayConfig replayConfig;

    private SessionManager() {
        this.sessionDAO = new SessionDAO();
        this.cachedTokenLocations = new ArrayList<>();
        this.cachedTokenSchemes = new ArrayList<>();
        this.cachedUserSessions = new ArrayList<>();
        this.cachedEnabledSessions = new ArrayList<>();
        this.replayConfig = new ReplayConfig();
    }

    /**
     * 获取单例实例
     */
    public static synchronized SessionManager getInstance() {
        if (instance == null) {
            instance = new SessionManager();
        }
        return instance;
    }

    /**
     * 刷新缓存，从数据库重新加载
     */
    public void refreshCache() {
        cachedTokenLocations = sessionDAO.getAllTokenLocations();
        cachedTokenSchemes = sessionDAO.getAllTokenSchemes();
        cachedUserSessions = sessionDAO.getAllUserSessions();
        cachedEnabledSessions = sessionDAO.getEnabledUserSessions();
        BurpExtender.printOutput("[+] 会话缓存已刷新: " + cachedTokenLocations.size() +
                "个令牌位置, " + cachedTokenSchemes.size() + "个令牌方案, " +
                cachedUserSessions.size() + "个用户会话, " +
                cachedEnabledSessions.size() + "个已启用");
    }

    // ==================== TokenLocation 操作 ====================

    public List<TokenLocation> getTokenLocations() {
        if (cachedTokenLocations.isEmpty()) {
            refreshCache();
        }
        return cachedTokenLocations;
    }

    public int addTokenLocation(TokenLocationType type, String expression, String description,
                                boolean persistToGlobal, boolean enabled) {
        int id = sessionDAO.addTokenLocation(type, expression, description, persistToGlobal, enabled);
        if (id > 0) {
            refreshCache();
            // 同步到全局YAML
            if (persistToGlobal) {
                TokenLocation loc = new TokenLocation(type, expression, description, true, enabled);
                GlobalTokenLocationManager.getInstance().addLocation(loc);
            }
        }
        return id;
    }

    public boolean updateTokenLocation(int id, TokenLocationType type, String expression, String description,
                                       boolean persistToGlobal, boolean enabled) {
        // 先获取旧的令牌位置（用于全局YAML更新时的旧键匹配）
        TokenLocation oldLocation = null;
        for (TokenLocation loc : cachedTokenLocations) {
            if (loc.getId() == id) {
                oldLocation = loc;
                break;
            }
        }

        boolean result = sessionDAO.updateTokenLocation(id, type, expression, description, persistToGlobal, enabled);
        if (result) {
            refreshCache();
            // 同步到全局YAML
            TokenLocation newLocation = new TokenLocation(type, expression, description, persistToGlobal, enabled);
            GlobalTokenLocationManager globalMgr = GlobalTokenLocationManager.getInstance();
            if (oldLocation != null) {
                if (persistToGlobal) {
                    globalMgr.updateLocation(oldLocation.getType().name(), oldLocation.getExpression(), newLocation);
                } else {
                    // 取消持久化：从全局中移除旧记录
                    globalMgr.removeLocation(oldLocation.getType().name(), oldLocation.getExpression());
                }
            } else {
                globalMgr.syncLocation(newLocation, persistToGlobal);
            }
        }
        return result;
    }

    public boolean deleteTokenLocation(int id) {
        // 先获取被删除的令牌位置（用于全局YAML同步）
        TokenLocation toDelete = null;
        for (TokenLocation loc : cachedTokenLocations) {
            if (loc.getId() == id) {
                toDelete = loc;
                break;
            }
        }

        boolean result = sessionDAO.deleteTokenLocation(id);
        if (result) {
            refreshCache();
            // 从全局YAML中移除
            if (toDelete != null && toDelete.isPersistToGlobal()) {
                GlobalTokenLocationManager.getInstance().removeLocation(
                        toDelete.getType().name(), toDelete.getExpression());
            }
        }
        return result;
    }

    /**
     * 获取引用指定令牌位置的方案数量
     */
    public int getSchemeReferenceCountByTokenLocation(int tokenLocationId) {
        return sessionDAO.getSchemeReferenceCountByTokenLocation(tokenLocationId);
    }

    // ==================== TokenScheme 操作 ====================

    public List<TokenScheme> getTokenSchemes() {
        if (cachedTokenSchemes.isEmpty()) {
            refreshCache();
        }
        return cachedTokenSchemes;
    }

    public List<TokenScheme> getEnabledTokenSchemes() {
        if (cachedTokenSchemes.isEmpty()) {
            refreshCache();
        }
        List<TokenScheme> enabled = new ArrayList<>();
        for (TokenScheme scheme : cachedTokenSchemes) {
            if (scheme.isEnabled()) {
                enabled.add(scheme);
            }
        }
        return enabled;
    }

    public TokenScheme getTokenSchemeById(int id) {
        for (TokenScheme scheme : cachedTokenSchemes) {
            if (scheme.getId() == id) {
                return scheme;
            }
        }
        return null;
    }

    public int addTokenScheme(String name, String description, boolean enabled, boolean persistToGlobal, List<Integer> tokenLocationIds) {
        int id = sessionDAO.addTokenScheme(name, description, persistToGlobal, enabled);
        if (id > 0 && tokenLocationIds != null && !tokenLocationIds.isEmpty()) {
            sessionDAO.saveSchemeTokenLocations(id, tokenLocationIds);
        }
        if (id > 0) {
            refreshCache();
            // 同步到全局
            syncSchemeToGlobal(id, persistToGlobal);
        }
        return id;
    }

    public boolean updateTokenScheme(int id, String name, String description, boolean enabled, boolean persistToGlobal) {
        boolean result = sessionDAO.updateTokenScheme(id, name, description, persistToGlobal, enabled);
        if (result) {
            refreshCache();
            // 同步到全局
            syncSchemeToGlobal(id, persistToGlobal);
        }
        return result;
    }

    public boolean deleteTokenScheme(int id) {
        // 先获取被删除的方案（用于全局YAML同步）
        TokenScheme toDelete = null;
        for (TokenScheme scheme : cachedTokenSchemes) {
            if (scheme.getId() == id) {
                toDelete = scheme;
                break;
            }
        }
        boolean result = sessionDAO.deleteTokenScheme(id);
        if (result) {
            refreshCache();
            // 从全局YAML中移除
            if (toDelete != null && toDelete.isPersistToGlobal()) {
                GlobalTokenSchemeManager.getInstance().removeScheme(toDelete.getName());
            }
        }
        return result;
    }

    /**
     * 将方案同步到全局YAML（添加或移除）
     */
    private void syncSchemeToGlobal(int schemeId, boolean persistToGlobal) {
        TokenScheme scheme = getTokenSchemeById(schemeId);
        if (scheme == null) return;

        if (persistToGlobal) {
            GlobalTokenSchemeManager.getInstance().addScheme(scheme);
        } else {
            GlobalTokenSchemeManager.getInstance().removeScheme(scheme.getName());
        }
    }

    public boolean saveSchemeTokenLocations(int schemeId, List<Integer> tokenLocationIds) {
        boolean result = sessionDAO.saveSchemeTokenLocations(schemeId, tokenLocationIds);
        if (result) {
            refreshCache();
        }
        return result;
    }

    /**
     * 获取引用指定方案的会话数量
     */
    public int getSessionReferenceCountByScheme(int schemeId) {
        return sessionDAO.getSessionReferenceCountByScheme(schemeId);
    }

    /**
     * 根据方案ID获取关联的令牌位置列表
     * 如果方案不存在或方案无关联位置，返回所有令牌位置作为回退
     */
    public List<TokenLocation> getTokenLocationsByScheme(Integer schemeId) {
        if (schemeId == null) {
            // 未关联方案时，回退到所有令牌位置
            return getTokenLocations();
        }

        TokenScheme scheme = getTokenSchemeById(schemeId);
        if (scheme == null || scheme.getTokenLocationIds().isEmpty()) {
            // 方案不存在或方案无关联位置，回退到所有令牌位置
            return getTokenLocations();
        }

        // 根据方案中的令牌位置ID筛选
        List<TokenLocation> allLocations = getTokenLocations();
        List<TokenLocation> filtered = new ArrayList<>();
        for (TokenLocation loc : allLocations) {
            if (scheme.getTokenLocationIds().contains(loc.getId())) {
                filtered.add(loc);
            }
        }
        return filtered;
    }

    // ==================== UserSession 操作 ====================

    public List<UserSession> getUserSessions() {
        if (cachedUserSessions.isEmpty()) {
            refreshCache();
        }
        return cachedUserSessions;
    }

    public List<UserSession> getEnabledSessions() {
        if (cachedEnabledSessions.isEmpty()) {
            refreshCache();
        }
        return cachedEnabledSessions;
    }

    /**
     * 检查是否有已启用的用户会话
     */
    public boolean hasEnabledSessions() {
        if (cachedEnabledSessions.isEmpty()) {
            refreshCache();
        }
        return !cachedEnabledSessions.isEmpty();
    }

    public int addUserSession(String name, String colorHex, boolean enabled, Integer schemeId) {
        int id = sessionDAO.addUserSession(name, colorHex, enabled, schemeId,
                replayConfig.getRequestTimeout(), replayConfig.getMaxConcurrent(),
                replayConfig.getRetryCount(), replayConfig.getRetryDelay(), replayConfig.getReplayDelay());
        if (id > 0) {
            refreshCache();
        }
        return id;
    }

    public boolean updateUserSession(int id, String name, String colorHex, boolean enabled, Integer schemeId) {
        boolean result = sessionDAO.updateUserSession(id, name, colorHex, enabled, schemeId,
                replayConfig.getRequestTimeout(), replayConfig.getMaxConcurrent(),
                replayConfig.getRetryCount(), replayConfig.getRetryDelay(), replayConfig.getReplayDelay());
        if (result) {
            refreshCache();
        }
        return result;
    }

    public boolean deleteUserSession(int id) {
        boolean result = sessionDAO.deleteUserSession(id);
        if (result) {
            refreshCache();
        }
        return result;
    }

    public boolean saveTokenValues(int userSessionId, Map<Integer, String> tokenValues) {
        boolean result = sessionDAO.saveTokenValues(userSessionId, tokenValues);
        if (result) {
            refreshCache();
        }
        return result;
    }

    /**
     * 合并导入用户会话（按name去重，同名跳过）
     *
     * @param newSessions 要导入的用户会话列表
     * @return 实际导入的数量
     */
    public int importUserSessionsMerge(List<UserSession> newSessions) {
        // 收集已有会话名称
        Set<String> existingNames = new java.util.HashSet<>();
        for (UserSession existing : getUserSessions()) {
            existingNames.add(existing.getName());
        }

        int imported = 0;
        for (UserSession session : newSessions) {
            if (existingNames.contains(session.getName())) {
                continue;
            }
            int id = sessionDAO.addUserSession(session.getName(), session.getColorHex(), session.isEnabled(),
                    session.getSchemeId(), session.getRequestTimeout(), session.getMaxConcurrent(),
                    session.getRetryCount(), session.getRetryDelay(), session.getReplayDelay());
            if (id > 0) {
                if (!session.getTokenValues().isEmpty()) {
                    sessionDAO.saveTokenValues(id, session.getTokenValues());
                }
                imported++;
            }
        }

        if (imported > 0) {
            refreshCache();
        }
        return imported;
    }

    /**
     * 替换导入用户会话（清空所有现有会话后导入）
     *
     * @param newSessions 要导入的用户会话列表
     * @return 实际导入的数量
     */
    public int importUserSessionsReplace(List<UserSession> newSessions) {
        sessionDAO.deleteAllUserSessions();

        int imported = 0;
        for (UserSession session : newSessions) {
            int id = sessionDAO.addUserSession(session.getName(), session.getColorHex(), session.isEnabled(),
                    session.getSchemeId(), session.getRequestTimeout(), session.getMaxConcurrent(),
                    session.getRetryCount(), session.getRetryDelay(), session.getReplayDelay());
            if (id > 0) {
                if (!session.getTokenValues().isEmpty()) {
                    sessionDAO.saveTokenValues(id, session.getTokenValues());
                }
                imported++;
            }
        }

        refreshCache();
        return imported;
    }

    // ==================== 全局令牌位置加载 ====================

    /**
     * 从全局YAML加载令牌位置到项目数据库
     * 启动时调用，自动去重（按 type+expression）
     */
    public void loadGlobalTokenLocations() {
        GlobalTokenLocationManager globalMgr = GlobalTokenLocationManager.getInstance();
        List<TokenLocation> globalLocations = globalMgr.getAllLocations();
        if (globalLocations.isEmpty()) {
            return;
        }

        // 获取当前项目数据库中已有的令牌位置，用于去重
        List<TokenLocation> existingLocations = getTokenLocations();
        Set<String> existingKeys = new java.util.HashSet<>();
        for (TokenLocation loc : existingLocations) {
            existingKeys.add(loc.getType().name() + "|" + loc.getExpression());
        }

        // 插入不存在于项目数据库的全局令牌位置
        int added = 0;
        for (TokenLocation globalLoc : globalLocations) {
            String key = globalLoc.getType().name() + "|" + globalLoc.getExpression();
            if (!existingKeys.contains(key)) {
                int id = sessionDAO.addTokenLocation(globalLoc.getType(), globalLoc.getExpression(),
                        globalLoc.getDescription(), true, globalLoc.isEnabled());
                if (id > 0) {
                    added++;
                }
            }
        }

        if (added > 0) {
            refreshCache();
            BurpExtender.printOutput("[+] 从全局加载了 " + added + " 条令牌位置到项目数据库");
        }
    }

    // ==================== 全局令牌方案加载 ====================

    /**
     * 从全局YAML加载令牌方案到项目数据库
     * 启动时调用，自动去重（按 name）
     */
    public void loadGlobalTokenSchemes() {
        GlobalTokenSchemeManager globalMgr = GlobalTokenSchemeManager.getInstance();
        // 先加载全局YAML到内存
        globalMgr.loadSchemes(getTokenLocations());
        List<TokenScheme> globalSchemes = globalMgr.getAllSchemes();
        if (globalSchemes.isEmpty()) {
            return;
        }

        // 获取当前项目数据库中已有的令牌方案，用于去重
        List<TokenScheme> existingSchemes = getTokenSchemes();
        Set<String> existingNames = new java.util.HashSet<>();
        for (TokenScheme scheme : existingSchemes) {
            existingNames.add(scheme.getName());
        }

        // 插入不存在于项目数据库的全局令牌方案
        int added = 0;
        for (TokenScheme globalScheme : globalSchemes) {
            if (!existingNames.contains(globalScheme.getName())) {
                int id = sessionDAO.addTokenScheme(globalScheme.getName(), globalScheme.getDescription(),
                        globalScheme.isPersistToGlobal(), globalScheme.isEnabled());
                if (id > 0) {
                    // 保存关联的令牌位置
                    List<Integer> locationIds = globalScheme.getTokenLocationIds();
                    if (locationIds != null && !locationIds.isEmpty()) {
                        sessionDAO.saveSchemeTokenLocations(id, locationIds);
                    }
                    added++;
                }
            }
        }

        if (added > 0) {
            refreshCache();
            BurpExtender.printOutput("[+] 从全局加载了 " + added + " 条令牌方案到项目数据库");
        }
    }

    // ==================== 重放配置 ====================

    public ReplayConfig getReplayConfig() {
        return replayConfig;
    }

    public boolean isRealtimeMode() {
        return replayConfig.isRealtimeMode();
    }

    public void setRealtimeMode(boolean realtimeMode) {
        replayConfig.setRealtimeMode(realtimeMode);
    }

    public double getSimilarityThreshold() {
        return replayConfig.getSimilarityThreshold();
    }

    public void setSimilarityThreshold(double similarityThreshold) {
        replayConfig.setSimilarityThreshold(similarityThreshold);
    }

    public int getRequestTimeout() {
        return replayConfig.getRequestTimeout();
    }

    public void setRequestTimeout(int requestTimeout) {
        replayConfig.setRequestTimeout(requestTimeout);
    }

    public int getMaxConcurrent() {
        return replayConfig.getMaxConcurrent();
    }

    public void setMaxConcurrent(int maxConcurrent) {
        replayConfig.setMaxConcurrent(maxConcurrent);
    }

    public int getRetryCount() {
        return replayConfig.getRetryCount();
    }

    public void setRetryCount(int retryCount) {
        replayConfig.setRetryCount(retryCount);
    }

    public int getRetryDelay() {
        return replayConfig.getRetryDelay();
    }

    public void setRetryDelay(int retryDelay) {
        replayConfig.setRetryDelay(retryDelay);
    }

    public int getReplayDelay() {
        return replayConfig.getReplayDelay();
    }

    public void setReplayDelay(int replayDelay) {
        replayConfig.setReplayDelay(replayDelay);
    }
}

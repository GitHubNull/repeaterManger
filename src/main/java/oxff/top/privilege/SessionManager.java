package oxff.top.privilege;

import burp.BurpExtender;
import oxff.top.privilege.dao.SessionDAO;
import oxff.top.privilege.model.TokenLocation;
import oxff.top.privilege.model.TokenLocationType;
import oxff.top.privilege.model.UserSession;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 会话管理器（单例）
 * 管理令牌位置和用户会话的CRUD操作，缓存已启用的会话列表
 */
public class SessionManager {

    private static SessionManager instance;

    private final SessionDAO sessionDAO;

    /** 缓存的令牌位置列表 */
    private List<TokenLocation> cachedTokenLocations;

    /** 缓存的用户会话列表 */
    private List<UserSession> cachedUserSessions;

    /** 缓存的已启用用户会话列表 */
    private List<UserSession> cachedEnabledSessions;

    /** 重放模式：true=实时重放，false=批量重放 */
    private boolean realtimeMode = true;

    /** API去重开关 */
    private boolean dedupEnabled = true;

    /** 相似度阈值 */
    private double similarityThreshold = 0.7;

    private SessionManager() {
        this.sessionDAO = new SessionDAO();
        this.cachedTokenLocations = new ArrayList<>();
        this.cachedUserSessions = new ArrayList<>();
        this.cachedEnabledSessions = new ArrayList<>();
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
        cachedUserSessions = sessionDAO.getAllUserSessions();
        cachedEnabledSessions = sessionDAO.getEnabledUserSessions();
        BurpExtender.printOutput("[+] 会话缓存已刷新: " + cachedTokenLocations.size() +
                "个令牌位置, " + cachedUserSessions.size() + "个用户会话, " +
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

    public int addUserSession(String name, String colorHex, boolean enabled) {
        int id = sessionDAO.addUserSession(name, colorHex, enabled);
        if (id > 0) {
            refreshCache();
        }
        return id;
    }

    public boolean updateUserSession(int id, String name, String colorHex, boolean enabled) {
        boolean result = sessionDAO.updateUserSession(id, name, colorHex, enabled);
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

    // ==================== 重放配置 ====================

    public boolean isRealtimeMode() {
        return realtimeMode;
    }

    public void setRealtimeMode(boolean realtimeMode) {
        this.realtimeMode = realtimeMode;
    }

    public boolean isDedupEnabled() {
        return dedupEnabled;
    }

    public void setDedupEnabled(boolean dedupEnabled) {
        this.dedupEnabled = dedupEnabled;
    }

    public double getSimilarityThreshold() {
        return similarityThreshold;
    }

    public void setSimilarityThreshold(double similarityThreshold) {
        this.similarityThreshold = similarityThreshold;
    }
}

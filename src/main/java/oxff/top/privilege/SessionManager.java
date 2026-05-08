package oxff.top.privilege;

import burp.BurpExtender;
import oxff.top.privilege.dao.SessionDAO;
import oxff.top.privilege.model.TokenLocation;
import oxff.top.privilege.model.TokenLocationType;
import oxff.top.privilege.model.UserSession;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

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

    public int addTokenLocation(TokenLocationType type, String expression, String description) {
        int id = sessionDAO.addTokenLocation(type, expression, description);
        if (id > 0) {
            refreshCache();
        }
        return id;
    }

    public boolean updateTokenLocation(int id, TokenLocationType type, String expression, String description) {
        boolean result = sessionDAO.updateTokenLocation(id, type, expression, description);
        if (result) {
            refreshCache();
        }
        return result;
    }

    public boolean deleteTokenLocation(int id) {
        boolean result = sessionDAO.deleteTokenLocation(id);
        if (result) {
            refreshCache();
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

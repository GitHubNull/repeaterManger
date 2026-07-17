package org.oxff.repeater.privilege;

import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.privilege.dao.SessionDAO;
import org.oxff.repeater.privilege.dao.UserInfoDAO;
import org.oxff.repeater.privilege.model.ReplayConfig;
import org.oxff.repeater.privilege.model.FieldDefinition;
import org.oxff.repeater.privilege.model.FieldType;
import org.oxff.repeater.privilege.model.Scheme;
import org.oxff.repeater.privilege.model.UserInfo;
import org.oxff.repeater.privilege.model.UserSession;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 会话管理器（单例）
 * 管理字段、方案和用户会话的CRUD操作，缓存已启用的会话列表
 */
public class SessionManager {

    private static SessionManager instance;

    private final SessionDAO sessionDAO;
    private final UserInfoDAO userInfoDAO;

    /** 缓存的字段列表 */
    private List<FieldDefinition> cachedFields;

    /** 缓存的方案列表 */
    private List<Scheme> cachedSchemes;

    /** 缓存的用户会话列表 */
    private List<UserSession> cachedUserSessions;

    /** 缓存的已启用用户会话列表 */
    private List<UserSession> cachedEnabledSessions;

    /** 缓存的用户信息（sessionId → UserInfo） */
    private Map<Integer, UserInfo> cachedUserInfo;

    /** 全局重放配置 */
    private final ReplayConfig replayConfig;

    private SessionManager() {
        this.sessionDAO = new SessionDAO();
        this.userInfoDAO = new UserInfoDAO();
        this.cachedFields = new ArrayList<>();
        this.cachedSchemes = new ArrayList<>();
        this.cachedUserSessions = new ArrayList<>();
        this.cachedEnabledSessions = new ArrayList<>();
        this.cachedUserInfo = new HashMap<>();
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
        cachedFields = sessionDAO.getAllFieldDefinitions();
        cachedSchemes = sessionDAO.getAllSchemes();
        cachedUserSessions = sessionDAO.getAllUserSessions();
        cachedEnabledSessions = sessionDAO.getEnabledUserSessions();
        // 同步刷新用户信息缓存
        cachedUserInfo.clear();
        for (UserInfo info : userInfoDAO.getAll()) {
            cachedUserInfo.put(info.getSessionId(), info);
        }
        LogManager.getInstance().printOutput("[+] 会话缓存已刷新: " + cachedFields.size() +
                "个字段, " + cachedSchemes.size() + "个方案, " +
                cachedUserSessions.size() + "个用户会话, " +
                cachedEnabledSessions.size() + "个已启用, " +
                cachedUserInfo.size() + "条用户信息");
    }

    // ==================== FieldDefinition 操作 ====================

    public List<FieldDefinition> getFieldDefinitions() {
        if (cachedFields.isEmpty()) {
            refreshCache();
        }
        return cachedFields;
    }

    public int addFieldDefinition(FieldType type, String expression, String description,
                                boolean persistToGlobal, boolean enabled) {
        int id = sessionDAO.addFieldDefinition(type, expression, description, persistToGlobal, enabled);
        if (id > 0) {
            refreshCache();
            // 同步到全局YAML
            if (persistToGlobal) {
                FieldDefinition loc = new FieldDefinition(type, expression, description, true, enabled);
                GlobalFieldDefinitionManager.getInstance().addField(loc);
            }
        }
        return id;
    }

    public boolean updateFieldDefinition(int id, FieldType type, String expression, String description,
                                       boolean persistToGlobal, boolean enabled) {
        // 先获取旧的字段定义（用于全局YAML更新时的旧键匹配）
        FieldDefinition oldLocation = null;
        for (FieldDefinition loc : cachedFields) {
            if (loc.getId() == id) {
                oldLocation = loc;
                break;
            }
        }

        boolean result = sessionDAO.updateFieldDefinition(id, type, expression, description, persistToGlobal, enabled);
        if (result) {
            refreshCache();
            // 同步到全局YAML
            FieldDefinition newLocation = new FieldDefinition(type, expression, description, persistToGlobal, enabled);
            GlobalFieldDefinitionManager globalMgr = GlobalFieldDefinitionManager.getInstance();
            if (oldLocation != null) {
                if (persistToGlobal) {
                    globalMgr.updateField(oldLocation.getType().name(), oldLocation.getExpression(), newLocation);
                } else {
                    // 取消持久化：从全局中移除旧记录
                    globalMgr.removeField(oldLocation.getType().name(), oldLocation.getExpression());
                }
            } else {
                globalMgr.syncField(newLocation, persistToGlobal);
            }
        }
        return result;
    }

    public boolean deleteFieldDefinition(int id) {
        // 先获取被删除的字段定义（用于全局YAML同步）
        FieldDefinition toDelete = null;
        for (FieldDefinition loc : cachedFields) {
            if (loc.getId() == id) {
                toDelete = loc;
                break;
            }
        }

        boolean result = sessionDAO.deleteFieldDefinition(id);
        if (result) {
            refreshCache();
            // 从全局YAML中移除
            if (toDelete != null && toDelete.isPersistToGlobal()) {
                GlobalFieldDefinitionManager.getInstance().removeField(
                        toDelete.getType().name(), toDelete.getExpression());
            }
        }
        return result;
    }

    /**
     * 获取引用指定字段定义的方案数量
     */
    public int getSchemeReferenceCountByField(int fieldId) {
        return sessionDAO.getSchemeReferenceCountByField(fieldId);
    }

    // ==================== Scheme 操作 ====================

    public List<Scheme> getSchemes() {
        if (cachedSchemes.isEmpty()) {
            refreshCache();
        }
        return cachedSchemes;
    }

    public List<Scheme> getEnabledSchemes() {
        if (cachedSchemes.isEmpty()) {
            refreshCache();
        }
        List<Scheme> enabled = new ArrayList<>();
        for (Scheme scheme : cachedSchemes) {
            if (scheme.isEnabled()) {
                enabled.add(scheme);
            }
        }
        return enabled;
    }

    public Scheme getSchemeById(int id) {
        for (Scheme scheme : cachedSchemes) {
            if (scheme.getId() == id) {
                return scheme;
            }
        }
        return null;
    }

    public int addScheme(String name, String description, boolean enabled, boolean persistToGlobal, List<Integer> fieldIds) {
        int id = sessionDAO.addScheme(name, description, persistToGlobal, enabled);
        if (id > 0 && fieldIds != null && !fieldIds.isEmpty()) {
            sessionDAO.saveSchemeFields(id, fieldIds);
        }
        if (id > 0) {
            refreshCache();
            // 同步到全局
            syncSchemeToGlobal(id, persistToGlobal);
        }
        return id;
    }

    public boolean updateScheme(int id, String name, String description, boolean enabled, boolean persistToGlobal) {
        boolean result = sessionDAO.updateScheme(id, name, description, persistToGlobal, enabled);
        if (result) {
            refreshCache();
            // 同步到全局
            syncSchemeToGlobal(id, persistToGlobal);
        }
        return result;
    }

    public boolean deleteScheme(int id) {
        // 先获取被删除的方案（用于全局YAML同步）
        Scheme toDelete = null;
        for (Scheme scheme : cachedSchemes) {
            if (scheme.getId() == id) {
                toDelete = scheme;
                break;
            }
        }
        boolean result = sessionDAO.deleteScheme(id);
        if (result) {
            refreshCache();
            // 从全局YAML中移除
            if (toDelete != null && toDelete.isPersistToGlobal()) {
                GlobalSchemeManager.getInstance().removeScheme(toDelete.getName(), getFieldDefinitions());
            }
        }
        return result;
    }

    /**
     * 将方案同步到全局YAML（添加或移除）
     */
    private void syncSchemeToGlobal(int schemeId, boolean persistToGlobal) {
        Scheme scheme = getSchemeById(schemeId);
        if (scheme == null) return;

        List<FieldDefinition> locations = getFieldDefinitions();
        if (persistToGlobal) {
            GlobalSchemeManager.getInstance().addScheme(scheme, locations);
        } else {
            GlobalSchemeManager.getInstance().removeScheme(scheme.getName(), locations);
        }
    }

    public boolean saveSchemeFields(int schemeId, List<Integer> fieldIds) {
        boolean result = sessionDAO.saveSchemeFields(schemeId, fieldIds);
        if (result) {
            refreshCache();
            // 如果方案持久化到全局，同步更新全局YAML中的位置关联
            Scheme scheme = getSchemeById(schemeId);
            if (scheme != null && scheme.isPersistToGlobal()) {
                GlobalSchemeManager.getInstance().addScheme(scheme, getFieldDefinitions());
            }
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
     * 根据方案ID获取关联的字段定义列表
     * 如果方案不存在或方案无关联字段，返回所有字段作为回退
     */
    public List<FieldDefinition> getFieldDefinitionsByScheme(Integer schemeId) {
        if (schemeId == null) {
            // 未关联方案时，回退到所有字段
            return getFieldDefinitions();
        }

        Scheme scheme = getSchemeById(schemeId);
        if (scheme == null || scheme.getFieldIds().isEmpty()) {
            // 方案不存在或方案无关联位置，回退到所有字段
            return getFieldDefinitions();
        }

        // 根据方案中的字段ID筛选
        List<FieldDefinition> allLocations = getFieldDefinitions();
        List<FieldDefinition> filtered = new ArrayList<>();
        for (FieldDefinition loc : allLocations) {
            if (scheme.getFieldIds().contains(loc.getId())) {
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

    public boolean saveFieldValues(int userSessionId, Map<Integer, String> fieldValues) {
        boolean result = sessionDAO.saveFieldValues(userSessionId, fieldValues);
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
                if (!session.getFieldValues().isEmpty()) {
                    sessionDAO.saveFieldValues(id, session.getFieldValues());
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
                if (!session.getFieldValues().isEmpty()) {
                    sessionDAO.saveFieldValues(id, session.getFieldValues());
                }
                imported++;
            }
        }

        refreshCache();
        return imported;
    }

    // ==================== 全局字段定义加载 ====================

    /**
     * 从全局YAML加载字段定义到项目数据库
     * 启动时调用，自动去重（按 type+expression）
     */
    public void loadGlobalFieldDefinitions() {
        GlobalFieldDefinitionManager globalMgr = GlobalFieldDefinitionManager.getInstance();
        List<FieldDefinition> globalLocations = globalMgr.getAllFields();
        if (globalLocations.isEmpty()) {
            return;
        }

        // 获取当前项目数据库中已有的字段定义，用于去重
        List<FieldDefinition> existingLocations = getFieldDefinitions();
        Set<String> existingKeys = new java.util.HashSet<>();
        for (FieldDefinition loc : existingLocations) {
            existingKeys.add(loc.getType().name() + "|" + loc.getExpression());
        }

        // 插入不存在于项目数据库的全局字段
        int added = 0;
        for (FieldDefinition globalLoc : globalLocations) {
            String key = globalLoc.getType().name() + "|" + globalLoc.getExpression();
            if (!existingKeys.contains(key)) {
                int id = sessionDAO.addFieldDefinition(globalLoc.getType(), globalLoc.getExpression(),
                        globalLoc.getDescription(), true, globalLoc.isEnabled());
                if (id > 0) {
                    added++;
                }
            }
        }

        if (added > 0) {
            refreshCache();
            LogManager.getInstance().printOutput("[+] 从全局加载了 " + added + " 条字段到项目数据库");
        }
    }

    // ==================== 全局方案加载 ====================

    /**
     * 从全局YAML加载方案到项目数据库
     * 启动时调用，自动去重（按 name）
     */
    public void loadGlobalSchemes() {
        GlobalSchemeManager globalMgr = GlobalSchemeManager.getInstance();
        // 先加载全局YAML到内存
        globalMgr.loadSchemes(getFieldDefinitions());
        List<Scheme> globalSchemes = globalMgr.getAllSchemes();
        if (globalSchemes.isEmpty()) {
            return;
        }

        // 获取当前项目数据库中已有的方案，用于去重
        List<Scheme> existingSchemes = getSchemes();
        Set<String> existingNames = new java.util.HashSet<>();
        for (Scheme scheme : existingSchemes) {
            existingNames.add(scheme.getName());
        }

        // 插入不存在于项目数据库的全局方案
        int added = 0;
        for (Scheme globalScheme : globalSchemes) {
            if (!existingNames.contains(globalScheme.getName())) {
                int id = sessionDAO.addScheme(globalScheme.getName(), globalScheme.getDescription(),
                        globalScheme.isPersistToGlobal(), globalScheme.isEnabled());
                if (id > 0) {
                    // 保存关联的字段
                    List<Integer> locationIds = globalScheme.getFieldIds();
                    if (locationIds != null && !locationIds.isEmpty()) {
                        sessionDAO.saveSchemeFields(id, locationIds);
                    }
                    added++;
                }
            }
        }

        if (added > 0) {
            refreshCache();
            LogManager.getInstance().printOutput("[+] 从全局加载了 " + added + " 条方案到项目数据库");
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

    // ==================== UserInfo 操作 ====================

    /**
     * 获取指定会话的用户信息（从缓存获取）
     * <p><b>注意：返回的是缓存中的对象引用，禁止修改返回对象的字段。</b>
     * 如需修改，请使用 {@link #saveUserInfo(UserInfo)} 写入新数据。</p>
     */
    public UserInfo getUserInfo(int sessionId) {
        return cachedUserInfo.get(sessionId);
    }

    /**
     * 保存用户信息（写入数据库并更新缓存）
     */
    public boolean saveUserInfo(UserInfo info) {
        boolean result = userInfoDAO.save(info);
        if (result) {
            cachedUserInfo.put(info.getSessionId(), info);
        }
        return result;
    }

    /**
     * 删除指定会话的用户信息。
     *
     * @param sessionId 会话ID
     * @return true 表示成功删除，false 表示未找到或出错
     */
    public boolean deleteUserInfo(int sessionId) {
        int affected = userInfoDAO.deleteBySessionId(sessionId);
        // 无论是否找到记录，都清理缓存，确保一致性
        cachedUserInfo.remove(sessionId);
        return affected > 0;
    }
}

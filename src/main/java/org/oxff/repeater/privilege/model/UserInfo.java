package org.oxff.repeater.privilege.model;

import java.util.ArrayList;
import java.util.List;

/**
 * 用户信息模型
 * 关联 UserSession，存储被测用户的身份信息与权限证明截图
 */
public class UserInfo {
    private int id;
    private int sessionId;
    private String role;
    private String username;
    private boolean isAnonymous;
    /** 截图文件的绝对路径列表 */
    private List<String> screenshotPaths;
    private long createdAt;

    public UserInfo() {
        this.role = "";
        this.username = "";
        this.isAnonymous = false;
        this.screenshotPaths = new ArrayList<>();
        this.createdAt = System.currentTimeMillis();
    }

    public UserInfo(int sessionId, String role, String username, boolean isAnonymous, List<String> screenshotPaths) {
        this.sessionId = sessionId;
        this.role = role != null ? role : "";
        this.username = username != null ? username : "";
        this.isAnonymous = isAnonymous;
        this.screenshotPaths = screenshotPaths != null ? screenshotPaths : new ArrayList<>();
        this.createdAt = System.currentTimeMillis();
    }

    // Getters and Setters

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getSessionId() {
        return sessionId;
    }

    public void setSessionId(int sessionId) {
        this.sessionId = sessionId;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role != null ? role : "";
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username != null ? username : "";
    }

    public boolean isAnonymous() {
        return isAnonymous;
    }

    public void setAnonymous(boolean anonymous) {
        isAnonymous = anonymous;
    }

    public List<String> getScreenshotPaths() {
        return screenshotPaths;
    }

    public void setScreenshotPaths(List<String> screenshotPaths) {
        this.screenshotPaths = screenshotPaths != null ? screenshotPaths : new ArrayList<>();
    }

    /**
     * 获取截图数量
     */
    public int getScreenshotCount() {
        return screenshotPaths != null ? screenshotPaths.size() : 0;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public String toString() {
        return String.format("UserInfo{id=%d, sessionId=%d, role='%s', username='%s', isAnonymous=%s, screenshotCount=%d}",
                id, sessionId, role, username, isAnonymous, getScreenshotCount());
    }
}

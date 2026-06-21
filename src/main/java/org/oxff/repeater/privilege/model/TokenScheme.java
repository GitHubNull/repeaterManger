package org.oxff.repeater.privilege.model;

import java.util.ArrayList;
import java.util.List;

/**
 * 令牌方案模型
 * 定义一组令牌位置的组合，作为令牌位置与用户会话之间的中间层
 * 不同方案对应不同的安全测试目标（如仅测试Bearer认证、仅测试Cookie认证等）
 */
public class TokenScheme {

    private int id;
    private String name;
    private String description;
    private boolean enabled;
    /** 是否持久化到全局（默认true） */
    private boolean persistToGlobal = true;
    /** 关联的令牌位置ID列表 */
    private List<Integer> tokenLocationIds;
    private long createdAt;

    public TokenScheme() {
        this.name = "";
        this.description = "";
        this.enabled = true;
        this.persistToGlobal = true;
        this.tokenLocationIds = new ArrayList<>();
        this.createdAt = System.currentTimeMillis();
    }

    public TokenScheme(String name, String description, boolean enabled) {
        this.name = name;
        this.description = description != null ? description : "";
        this.enabled = enabled;
        this.persistToGlobal = true;
        this.tokenLocationIds = new ArrayList<>();
        this.createdAt = System.currentTimeMillis();
    }

    public TokenScheme(int id, String name, String description, boolean enabled) {
        this.id = id;
        this.name = name;
        this.description = description != null ? description : "";
        this.enabled = enabled;
        this.persistToGlobal = true;
        this.tokenLocationIds = new ArrayList<>();
        this.createdAt = System.currentTimeMillis();
    }

    // Getters and Setters

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isPersistToGlobal() {
        return persistToGlobal;
    }

    public void setPersistToGlobal(boolean persistToGlobal) {
        this.persistToGlobal = persistToGlobal;
    }

    public List<Integer> getTokenLocationIds() {
        return tokenLocationIds;
    }

    public void setTokenLocationIds(List<Integer> tokenLocationIds) {
        this.tokenLocationIds = tokenLocationIds != null ? tokenLocationIds : new ArrayList<>();
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    /**
     * 获取关联令牌位置的数量
     */
    public int getTokenLocationCount() {
        return tokenLocationIds != null ? tokenLocationIds.size() : 0;
    }

    @Override
    public String toString() {
        return String.format("TokenScheme{id=%d, name='%s', enabled=%s, locationCount=%d}",
                id, name, enabled, getTokenLocationCount());
    }
}

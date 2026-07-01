package org.oxff.repeater.privilege.model;

import java.util.ArrayList;
import java.util.List;

/**
 * 方案模型
 * 定义一组字段的集合，作为"字段定义"与"用户会话"之间的中间层
 */
public class Scheme {

    private int id;
    private String name;
    private String description;
    private boolean enabled;
    /** 是否持久化到全局（默认true） */
    private boolean persistToGlobal = true;
    /** 关联的字段ID列表 */
    private List<Integer> fieldIds;
    private long createdAt;

    public Scheme() {
        this.name = "";
        this.description = "";
        this.enabled = true;
        this.persistToGlobal = true;
        this.fieldIds = new ArrayList<>();
        this.createdAt = System.currentTimeMillis();
    }

    public Scheme(String name, String description, boolean enabled) {
        this.name = name;
        this.description = description != null ? description : "";
        this.enabled = enabled;
        this.persistToGlobal = true;
        this.fieldIds = new ArrayList<>();
        this.createdAt = System.currentTimeMillis();
    }

    public Scheme(int id, String name, String description, boolean enabled) {
        this.id = id;
        this.name = name;
        this.description = description != null ? description : "";
        this.enabled = enabled;
        this.persistToGlobal = true;
        this.fieldIds = new ArrayList<>();
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

    public List<Integer> getFieldIds() {
        return fieldIds;
    }

    public void setFieldIds(List<Integer> fieldIds) {
        this.fieldIds = fieldIds != null ? fieldIds : new ArrayList<>();
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    /**
     * 获取关联字段的数量
     */
    public int getFieldCount() {
        return fieldIds != null ? fieldIds.size() : 0;
    }

    @Override
    public String toString() {
        return String.format("Scheme{id=%d, name='%s', enabled=%s, fieldCount=%d}",
                id, name, enabled, getFieldCount());
    }
}

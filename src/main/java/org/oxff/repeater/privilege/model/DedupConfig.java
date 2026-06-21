package org.oxff.repeater.privilege.model;

import java.util.Objects;

/**
 * API去重配置模型
 * 支持多配置优先级链式匹配，包含策略、表达式、保留策略、优先级和存储类型
 */
public class DedupConfig {

    /**
     * 存储类型枚举
     */
    public enum StorageType {
        /** 全局持久化：存储到 ~/.burp/repeater_manager/dedup_configs.yaml */
        GLOBAL("全局持久化"),
        /** 会话级：仅内存存储，插件卸载即失效 */
        SESSION("会话级");

        private final String displayName;

        StorageType(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }

        public static StorageType fromString(String text) {
            if (text == null) return GLOBAL;
            for (StorageType type : values()) {
                if (type.name().equalsIgnoreCase(text)) {
                    return type;
                }
            }
            return GLOBAL;
        }
    }

    private int id;
    private DedupStrategy strategy;
    private String expression;
    private DedupKeepPolicy keepPolicy;
    private int priority;
    private boolean enabled;
    private StorageType storageType;

    public DedupConfig() {
        this.strategy = DedupStrategy.PATH;
        this.expression = "";
        this.keepPolicy = DedupKeepPolicy.FIRST;
        this.priority = 10;
        this.enabled = true;
        this.storageType = StorageType.GLOBAL;
    }

    public DedupConfig(DedupStrategy strategy, String expression, DedupKeepPolicy keepPolicy,
                       int priority, boolean enabled, StorageType storageType) {
        this.strategy = strategy;
        this.expression = expression != null ? expression : "";
        this.keepPolicy = keepPolicy;
        this.priority = priority;
        this.enabled = enabled;
        this.storageType = storageType;
    }

    // ==================== Getters & Setters ====================

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public DedupStrategy getStrategy() {
        return strategy;
    }

    public void setStrategy(DedupStrategy strategy) {
        this.strategy = strategy;
    }

    public String getExpression() {
        return expression;
    }

    public void setExpression(String expression) {
        this.expression = expression != null ? expression : "";
    }

    public DedupKeepPolicy getKeepPolicy() {
        return keepPolicy;
    }

    public void setKeepPolicy(DedupKeepPolicy keepPolicy) {
        this.keepPolicy = keepPolicy;
    }

    public int getPriority() {
        return priority;
    }

    public void setPriority(int priority) {
        this.priority = priority;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public StorageType getStorageType() {
        return storageType;
    }

    public void setStorageType(StorageType storageType) {
        this.storageType = storageType;
    }

    // ==================== equals/hashCode ====================

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DedupConfig that = (DedupConfig) o;
        return id == that.id && priority == that.priority && enabled == that.enabled
                && strategy == that.strategy && Objects.equals(expression, that.expression)
                && keepPolicy == that.keepPolicy && storageType == that.storageType;
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, strategy, expression, keepPolicy, priority, enabled, storageType);
    }

    @Override
    public String toString() {
        return "DedupConfig{" +
                "id=" + id +
                ", strategy=" + strategy +
                ", expression='" + expression + '\'' +
                ", keepPolicy=" + keepPolicy +
                ", priority=" + priority +
                ", enabled=" + enabled +
                ", storageType=" + storageType +
                '}';
    }
}

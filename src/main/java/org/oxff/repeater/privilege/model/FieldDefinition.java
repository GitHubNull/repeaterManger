package org.oxff.repeater.privilege.model;

/**
 * 字段定义模型，描述凭证字段在HTTP请求中的位置和表达式。
 * <p>
 * 每个字段定义包含字段类型（Header/Cookie/Body/URL参数等）、
 * 提取表达式（如JSON路径、XML路径或正则表达式）、以及描述信息。
 * 支持持久化到全局配置，供所有权限测试方案复用。
 *
 * @see FieldType
 */
public class FieldDefinition {

    /** 数据库主键ID */
    private int id;

    /** 字段类型（Header/Body/URL参数等） */
    private FieldType type;

    /** 字段提取表达式（如JSON路径、XML路径或正则表达式） */
    private String expression;

    /** 字段描述信息 */
    private String description;

    /** 是否持久化到全局字段定义库 */
    private boolean persistToGlobal;

    /** 是否启用 */
    private boolean enabled;

    /** 创建时间戳（毫秒） */
    private long createdAt;

    /**
     * 默认构造函数，创建一个空的Header类型字段定义
     */
    public FieldDefinition() {
        this(FieldType.HEADER, "", "");
    }

    /**
     * 创建字段定义
     *
     * @param type        字段类型
     * @param expression  字段提取表达式
     * @param description 字段描述
     */
    public FieldDefinition(FieldType type, String expression, String description) {
        this(type, expression, description, true, true);
    }

    /**
     * 创建字段定义（含持久化和启用控制）
     *
     * @param type            字段类型
     * @param expression      字段提取表达式
     * @param description     字段描述
     * @param persistToGlobal 是否持久化到全局
     * @param enabled         是否启用
     */
    public FieldDefinition(FieldType type, String expression, String description,
                           boolean persistToGlobal, boolean enabled) {
        this(0, type, expression, description, persistToGlobal, enabled);
    }

    /**
     * 创建带ID的字段定义
     *
     * @param id          数据库主键ID
     * @param type        字段类型
     * @param expression  字段提取表达式
     * @param description 字段描述
     */
    public FieldDefinition(int id, FieldType type, String expression, String description) {
        this(id, type, expression, description, true, true);
    }

    /**
     * 完整构造函数
     *
     * @param id              数据库主键ID
     * @param type            字段类型
     * @param expression      字段提取表达式
     * @param description     字段描述
     * @param persistToGlobal 是否持久化到全局
     * @param enabled         是否启用
     */
    public FieldDefinition(int id, FieldType type, String expression, String description,
                           boolean persistToGlobal, boolean enabled) {
        this.id = id;
        this.type = type;
        this.expression = expression;
        this.description = description != null ? description : "";
        this.persistToGlobal = persistToGlobal;
        this.enabled = enabled;
        this.createdAt = System.currentTimeMillis();
    }

    // ==================== Getters and Setters ====================

    /** @return 数据库主键ID */
    public int getId() {
        return id;
    }

    /** @param id 数据库主键ID */
    public void setId(int id) {
        this.id = id;
    }

    /** @return 字段类型 */
    public FieldType getType() {
        return type;
    }

    /** @param type 字段类型 */
    public void setType(FieldType type) {
        this.type = type;
    }

    /** @return 字段提取表达式 */
    public String getExpression() {
        return expression;
    }

    /** @param expression 字段提取表达式 */
    public void setExpression(String expression) {
        this.expression = expression;
    }

    /** @return 字段描述信息 */
    public String getDescription() {
        return description;
    }

    /** @param description 字段描述信息 */
    public void setDescription(String description) {
        this.description = description;
    }

    /** @return 是否持久化到全局字段定义库 */
    public boolean isPersistToGlobal() {
        return persistToGlobal;
    }

    /** @param persistToGlobal 是否持久化到全局 */
    public void setPersistToGlobal(boolean persistToGlobal) {
        this.persistToGlobal = persistToGlobal;
    }

    /** @return 是否启用 */
    public boolean isEnabled() {
        return enabled;
    }

    /** @param enabled 是否启用 */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /** @return 创建时间戳（毫秒） */
    public long getCreatedAt() {
        return createdAt;
    }

    /** @param createdAt 创建时间戳（毫秒） */
    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public String toString() {
        return String.format("FieldDefinition{id=%d, type=%s, expression='%s'}", id, type, expression);
    }
}

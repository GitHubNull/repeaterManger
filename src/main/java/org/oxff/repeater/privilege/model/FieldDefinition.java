package org.oxff.repeater.privilege.model;

/**
 * 字段定义模型
 * 定义凭证字段在HTTP请求中的位置和表达式
 */
public class FieldDefinition {
    private int id;
    private FieldType type;
    private String expression;
    private String description;
    private boolean persistToGlobal;
    private boolean enabled;

    public FieldDefinition() {
        this.type = FieldType.HEADER;
        this.expression = "";
        this.description = "";
        this.persistToGlobal = true;
        this.enabled = true;
    }

    public FieldDefinition(FieldType type, String expression, String description) {
        this.type = type;
        this.expression = expression;
        this.description = description != null ? description : "";
        this.persistToGlobal = true;
        this.enabled = true;
    }

    public FieldDefinition(FieldType type, String expression, String description,
                           boolean persistToGlobal, boolean enabled) {
        this.type = type;
        this.expression = expression;
        this.description = description != null ? description : "";
        this.persistToGlobal = persistToGlobal;
        this.enabled = enabled;
    }

    public FieldDefinition(int id, FieldType type, String expression, String description) {
        this.id = id;
        this.type = type;
        this.expression = expression;
        this.description = description != null ? description : "";
        this.persistToGlobal = true;
        this.enabled = true;
    }

    public FieldDefinition(int id, FieldType type, String expression, String description,
                           boolean persistToGlobal, boolean enabled) {
        this.id = id;
        this.type = type;
        this.expression = expression;
        this.description = description != null ? description : "";
        this.persistToGlobal = persistToGlobal;
        this.enabled = enabled;
    }

    // Getters and Setters

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public FieldType getType() {
        return type;
    }

    public void setType(FieldType type) {
        this.type = type;
    }

    public String getExpression() {
        return expression;
    }

    public void setExpression(String expression) {
        this.expression = expression;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isPersistToGlobal() {
        return persistToGlobal;
    }

    public void setPersistToGlobal(boolean persistToGlobal) {
        this.persistToGlobal = persistToGlobal;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public String toString() {
        return String.format("FieldDefinition{id=%d, type=%s, expression='%s'}", id, type, expression);
    }
}

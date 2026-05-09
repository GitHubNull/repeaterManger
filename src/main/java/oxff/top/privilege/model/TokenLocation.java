package oxff.top.privilege.model;

/**
 * 令牌位置模型
 * 定义会话令牌在HTTP请求中的具体位置
 * 所有用户会话共享同一组令牌位置定义，每个用户为每个位置提供不同的值
 */
public class TokenLocation {
    private int id;
    private TokenLocationType type;
    private String expression;
    private String description;
    private boolean persistToGlobal;
    private boolean enabled;

    public TokenLocation() {
        this.type = TokenLocationType.HEADER;
        this.expression = "";
        this.description = "";
        this.persistToGlobal = true;
        this.enabled = true;
    }

    public TokenLocation(TokenLocationType type, String expression, String description) {
        this.type = type;
        this.expression = expression;
        this.description = description != null ? description : "";
        this.persistToGlobal = true;
        this.enabled = true;
    }

    public TokenLocation(TokenLocationType type, String expression, String description,
                         boolean persistToGlobal, boolean enabled) {
        this.type = type;
        this.expression = expression;
        this.description = description != null ? description : "";
        this.persistToGlobal = persistToGlobal;
        this.enabled = enabled;
    }

    public TokenLocation(int id, TokenLocationType type, String expression, String description) {
        this.id = id;
        this.type = type;
        this.expression = expression;
        this.description = description != null ? description : "";
        this.persistToGlobal = true;
        this.enabled = true;
    }

    public TokenLocation(int id, TokenLocationType type, String expression, String description,
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

    public TokenLocationType getType() {
        return type;
    }

    public void setType(TokenLocationType type) {
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
        return String.format("TokenLocation{id=%d, type=%s, expression='%s'}", id, type, expression);
    }
}

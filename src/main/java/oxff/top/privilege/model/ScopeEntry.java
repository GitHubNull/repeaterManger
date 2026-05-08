package oxff.top.privilege.model;

/**
 * Scope条目模型
 * 表示自动化测试的范围条目（URL匹配规则）
 *
 * 支持两种来源：
 * - 用户自定义：从 scope_entries 表加载
 * - Burp Suite Scope：直接使用 Burp 的 Target Scope
 */
public class ScopeEntry {

    private int id;
    private String name;
    private String urlPattern;    // URL匹配模式（支持通配符，如 *.example.com/api/*）
    private boolean enabled = true;
    private String description;

    public ScopeEntry() {
    }

    public ScopeEntry(String name, String urlPattern, boolean enabled, String description) {
        this.name = name;
        this.urlPattern = urlPattern;
        this.enabled = enabled;
        this.description = description;
    }

    // ==================== Getters & Setters ====================

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

    public String getUrlPattern() {
        return urlPattern;
    }

    public void setUrlPattern(String urlPattern) {
        this.urlPattern = urlPattern;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * 检查给定URL是否匹配此Scope条目
     * 支持通配符 * 匹配
     */
    public boolean matches(String url) {
        if (urlPattern == null || url == null) return false;
        String regex = urlPattern
                .replace(".", "\\.")
                .replace("*", ".*")
                .replace("?", ".");
        return url.matches(regex);
    }
}

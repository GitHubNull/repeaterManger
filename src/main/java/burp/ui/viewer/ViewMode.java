package burp.ui.viewer;

/**
 * 定义HTTP消息查看模式
 */
public enum ViewMode {
    PRETTY("美化"),   // 美化模式，带语法高亮
    RAW("原始"),      // 原始文本模式
    HEX("hex");      // 十六进制模式
    
    private final String displayName;
    
    ViewMode(String displayName) {
        this.displayName = displayName;
    }
    
    public String getDisplayName() {
        return displayName;
    }
    
    @Override
    public String toString() {
        return displayName;
    }
} 
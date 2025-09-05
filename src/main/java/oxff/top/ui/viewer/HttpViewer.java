package oxff.top.ui.viewer;

/**
 * HTTP查看器接口，定义了HTTP消息显示组件的基本行为
 */
public interface HttpViewer {
    /**
     * 设置视图模式
     * 
     * @param mode 视图模式（美化、原始、hex）
     */
    void setViewMode(ViewMode mode);
    
    /**
     * 获取当前视图模式
     * 
     * @return 当前视图模式
     */
    ViewMode getViewMode();
    
    /**
     * 设置HTTP消息内容（字节数组）
     * 
     * @param data HTTP消息的字节数组
     */
    void setData(byte[] data);
    
    /**
     * 设置HTTP消息内容（字符串）
     * 
     * @param text HTTP消息的字符串表示
     */
    void setText(String text);
    
    /**
     * 获取当前显示的文本内容
     * 
     * @return 当前HTTP消息的文本表示
     */
    String getText();
    
    /**
     * 清除当前内容
     */
    void clear();
} 
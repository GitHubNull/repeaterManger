package burp.ui.layout;

import javax.swing.*;
import java.awt.*;

/**
 * 布局管理器 - 负责处理UI布局切换
 */
public class LayoutManager {
    public enum LayoutType {
        HORIZONTAL,  // 水平布局(左右排列)
        VERTICAL     // 垂直布局(上下排列)
    }
    
    private final JSplitPane splitPane;
    private LayoutType currentLayout;
    private Component leftComponent;
    private Component rightComponent;
    private boolean showingRequestOnly = false;
    private boolean showingResponseOnly = false;
    
    /**
     * 创建布局管理器
     *
     * @param splitPane 要管理的分割面板
     * @param initialLayout 初始布局类型
     */
    public LayoutManager(JSplitPane splitPane, LayoutType initialLayout) {
        this.splitPane = splitPane;
        this.currentLayout = initialLayout;
        
        // 保存原始的组件引用
        this.leftComponent = splitPane.getLeftComponent();
        this.rightComponent = splitPane.getRightComponent();
        
        // 设置初始布局
        applySplitPaneLayout(initialLayout);
    }
    
    /**
     * 切换布局
     */
    public void toggleLayout() {
        if (showingRequestOnly || showingResponseOnly) {
            // 如果当前是单组件模式，切换回普通模式
            restoreComponents();
            setLayout(currentLayout);
            return;
        }
        
        if (currentLayout == LayoutType.HORIZONTAL) {
            setLayout(LayoutType.VERTICAL);
        } else {
            setLayout(LayoutType.HORIZONTAL);
        }
    }
    
    /**
     * 设置布局类型
     */
    public void setLayout(LayoutType layoutType) {
        // 如果当前是单组件模式，恢复两个组件
        if (showingRequestOnly || showingResponseOnly) {
            restoreComponents();
        }
        
        currentLayout = layoutType;
        applySplitPaneLayout(layoutType);
        
        showingRequestOnly = false;
        showingResponseOnly = false;
    }
    
    /**
     * 设置仅显示请求布局
     */
    public void setLayoutRequestOnly() {
        // 保存当前组件
        if (!showingRequestOnly && !showingResponseOnly) {
            leftComponent = splitPane.getLeftComponent();
            rightComponent = splitPane.getRightComponent();
        }
        
        // 移除响应组件
        splitPane.setRightComponent(null);
        
        // 确保请求组件在可见位置
        if (showingResponseOnly) {
            splitPane.setLeftComponent(leftComponent);
        }
        
        showingRequestOnly = true;
        showingResponseOnly = false;
    }
    
    /**
     * 设置仅显示响应布局
     */
    public void setLayoutResponseOnly() {
        // 保存当前组件
        if (!showingRequestOnly && !showingResponseOnly) {
            leftComponent = splitPane.getLeftComponent();
            rightComponent = splitPane.getRightComponent();
        }
        
        // 移除请求组件并将响应组件放到左侧可见位置
        if (showingRequestOnly || !showingResponseOnly) {
            splitPane.setLeftComponent(rightComponent);
        }
        splitPane.setRightComponent(null);
        
        showingRequestOnly = false;
        showingResponseOnly = true;
    }
    
    /**
     * 恢复显示所有组件
     */
    private void restoreComponents() {
        splitPane.setLeftComponent(leftComponent);
        splitPane.setRightComponent(rightComponent);
    }
    
    /**
     * 应用分割面板布局
     */
    private void applySplitPaneLayout(LayoutType layoutType) {
        // 如果是单组件模式，先退出
        if (showingRequestOnly || showingResponseOnly) {
            restoreComponents();
            showingRequestOnly = false;
            showingResponseOnly = false;
        }
        
        // 保存当前组件
        Component left = splitPane.getLeftComponent();
        Component right = splitPane.getRightComponent();
        
        // 保存当前分隔位置比例
        double proportionValue = 0.5;
        try {
            int totalSize = (layoutType == LayoutType.HORIZONTAL) ? 
                          splitPane.getWidth() : splitPane.getHeight();
                          
            if (totalSize > 0) {
                proportionValue = (double) splitPane.getDividerLocation() / totalSize;
            }
        } catch (Exception e) {
            // 忽略可能的异常，使用默认值
        }
        
        // 创建一个最终变量用于lambda表达式
        final double proportion = proportionValue;
        
        // 设置新的方向
        int newOrientation = (layoutType == LayoutType.HORIZONTAL) ? 
                        JSplitPane.HORIZONTAL_SPLIT : JSplitPane.VERTICAL_SPLIT;
        splitPane.setOrientation(newOrientation);
        
        // 恢复组件顺序
        splitPane.setLeftComponent(left);
        splitPane.setRightComponent(right);
        
        // 根据新方向设置分隔位置
        SwingUtilities.invokeLater(() -> {
            int size = (layoutType == LayoutType.HORIZONTAL) ? 
                      splitPane.getWidth() : splitPane.getHeight();
                      
            if (size > 0) {
                splitPane.setDividerLocation((int)(size * proportion));
            } else {
                splitPane.setDividerLocation(0.5);
            }
        });
    }
    
    /**
     * 获取当前布局类型
     */
    public LayoutType getCurrentLayout() {
        return currentLayout;
    }
    
    /**
     * 是否正在显示仅请求模式
     */
    public boolean isShowingRequestOnly() {
        return showingRequestOnly;
    }
    
    /**
     * 是否正在显示仅响应模式
     */
    public boolean isShowingResponseOnly() {
        return showingResponseOnly;
    }
} 
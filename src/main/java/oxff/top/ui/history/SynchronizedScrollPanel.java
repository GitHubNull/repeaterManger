package oxff.top.ui.history;

import javax.swing.*;
import java.awt.*;
import java.awt.event.AdjustmentListener;

/**
 * 同步滚动面板 - 包含两个JScrollPane，滚动时同步联动
 * 支持临时禁用同步和重新设置内容
 * 支持直接接受 DiffPane 组件（提取其内部 JScrollPane 进行同步）
 */
public class SynchronizedScrollPanel extends JPanel {
    private static final long serialVersionUID = 1L;

    private final JScrollPane leftScrollPane;
    private final JScrollPane rightScrollPane;
    private boolean syncEnabled = true;
    private boolean isSyncing = false;

    // DiffPane 引用（用于 DiffNavigator 访问）
    private DiffPane leftDiffPane;
    private DiffPane rightDiffPane;

    /**
     * 创建同步滚动面板（通用：接受任意 Component）
     *
     * @param leftContent  左侧内容组件
     * @param rightContent 右侧内容组件
     */
    public SynchronizedScrollPanel(Component leftContent, Component rightContent) {
        setLayout(new BorderLayout());

        leftScrollPane = new JScrollPane(leftContent);
        rightScrollPane = new JScrollPane(rightContent);

        leftScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        rightScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        setupSyncListeners();

        // 使用JSplitPane水平分割
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftScrollPane, rightScrollPane);
        splitPane.setResizeWeight(0.5);
        splitPane.setDividerLocation(0.5);
        splitPane.setOneTouchExpandable(true);

        add(splitPane, BorderLayout.CENTER);
    }

    /**
     * 创建同步滚动面板（接受 DiffPane，提取其内部 JScrollPane 进行同步）
     * DiffPane 自身已包含 JScrollPane 和行号，不需要外层再包一层
     *
     * @param leftDiffPane  左侧差异面板
     * @param rightDiffPane 右侧差异面板
     */
    public SynchronizedScrollPanel(DiffPane leftDiffPane, DiffPane rightDiffPane) {
        this.leftDiffPane = leftDiffPane;
        this.rightDiffPane = rightDiffPane;

        setLayout(new BorderLayout());

        // 提取 DiffPane 内部的 JScrollPane
        leftScrollPane = leftDiffPane.getScrollPane();
        rightScrollPane = rightDiffPane.getScrollPane();

        leftScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        rightScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        setupSyncListeners();

        // 使用JSplitPane水平分割
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftDiffPane, rightDiffPane);
        splitPane.setResizeWeight(0.5);
        splitPane.setDividerLocation(0.5);
        splitPane.setOneTouchExpandable(true);

        add(splitPane, BorderLayout.CENTER);
    }

    /**
     * 设置同步滚动监听器
     */
    private void setupSyncListeners() {
        AdjustmentListener leftListener = e -> {
            if (!isSyncing && syncEnabled) {
                isSyncing = true;
                syncScroll(leftScrollPane, rightScrollPane);
                isSyncing = false;
            }
        };

        AdjustmentListener rightListener = e -> {
            if (!isSyncing && syncEnabled) {
                isSyncing = true;
                syncScroll(rightScrollPane, leftScrollPane);
                isSyncing = false;
            }
        };

        leftScrollPane.getVerticalScrollBar().addAdjustmentListener(leftListener);
        rightScrollPane.getVerticalScrollBar().addAdjustmentListener(rightListener);
    }

    /**
     * 同步滚动：按比例同步对方滚动条
     */
    private void syncScroll(JScrollPane source, JScrollPane target) {
        JScrollBar sourceBar = source.getVerticalScrollBar();
        JScrollBar targetBar = target.getVerticalScrollBar();

        if (sourceBar.getMaximum() > 0 && targetBar.getMaximum() > 0) {
            double ratio = (double) sourceBar.getValue() / sourceBar.getMaximum();
            int targetValue = (int) (ratio * targetBar.getMaximum());
            targetBar.setValue(targetValue);
        }
    }

    /**
     * 设置是否启用同步滚动
     */
    public void setSyncEnabled(boolean enabled) {
        this.syncEnabled = enabled;
    }

    /**
     * 获取左侧滚动面板
     */
    public JScrollPane getLeftScrollPane() {
        return leftScrollPane;
    }

    /**
     * 获取右侧滚动面板
     */
    public JScrollPane getRightScrollPane() {
        return rightScrollPane;
    }

    /**
     * 获取左侧 DiffPane（仅 DiffPane 构造函数创建时有值）
     */
    public DiffPane getLeftDiffPane() {
        return leftDiffPane;
    }

    /**
     * 获取右侧 DiffPane（仅 DiffPane 构造函数创建时有值）
     */
    public DiffPane getRightDiffPane() {
        return rightDiffPane;
    }
}

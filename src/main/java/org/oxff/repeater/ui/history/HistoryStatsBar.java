package org.oxff.repeater.ui.history;

import org.oxff.repeater.i18n.I18nManager;
import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.db.history.HistoryStatsDAO;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.DecimalFormat;

/**
 * 历史记录状态栏组件
 * 显示在HistoryPanel底部，展示重放历史的统计信息
 * 默认收缩显示精简信息，双击展开显示完整统计
 */
public class HistoryStatsBar extends JPanel {
    private static final long serialVersionUID = 1L;

    // 颜色定义
    private static final Color COLOR_SUCCESS = new Color(0, 130, 0);
    private static final Color COLOR_FAILURE = Color.RED;
    private static final Color COLOR_RETRY = new Color(0, 95, 170);
    private static final Color COLOR_TITLE = new Color(80, 80, 80);
    private static final Color COLOR_HINT = Color.GRAY;
    private static final Color COLOR_TOP_BORDER = Color.LIGHT_GRAY;

    // 字体定义
    private static final Font FONT_TITLE = new Font("Dialog", Font.BOLD, 11);
    private static final Font FONT_VALUE = new Font("Dialog", Font.PLAIN, 11);
    private static final Font FONT_HINT = new Font("Dialog", Font.PLAIN, 10);

    // 高度定义
    private static final int HEIGHT_COLLAPSED = 28;
    private static final int HEIGHT_EXPANDED = 56;
    private static final int ANIMATION_DURATION_MS = 150;

    // 数值格式化
    private static final DecimalFormat DECIMAL_FMT = new DecimalFormat("0.00");

    // 状态
    private boolean isExpanded = false;
    private int currentRequestId = -1; // -1表示全局统计

    // DAO
    private final HistoryStatsDAO statsDAO;

    // CardLayout面板
    private final JPanel cardPanel;
    private final CardLayout cardLayout;

    // 收缩视图标签（独立实例）
    private JLabel cTotalCount;
    private JLabel cSuccessCount;
    private JLabel cFailureCount;
    private JLabel cRetryCount;
    private JLabel cMaxTime;
    private JLabel cMinTime;

    // 展开视图标签（独立实例）
    private JLabel eTotalCount;
    private JLabel eSuccessCount;
    private JLabel eFailureCount;
    private JLabel eRetryCount;
    private JLabel eMaxTime;
    private JLabel eMinTime;
    private JLabel eAvgTime;
    private JLabel eVariance;
    private JLabel eModeTime;
    private JLabel eMedianTime;
    private JLabel eRequestCount;

    // 动画Timer
    private Timer animationTimer;

    // 标题标签与资源键的映射（语言切换时刷新）
    private final java.util.List<TitleLabelRef> titleLabels = new java.util.ArrayList<>();
    private JLabel hintLabel;

    /**
     * 标题标签引用（持有资源键以便刷新）
     */
    private static class TitleLabelRef {
        final JLabel label;
        final String key;
        TitleLabelRef(JLabel label, String key) {
            this.label = label;
            this.key = key;
        }
    }

    public HistoryStatsBar() {
        this.statsDAO = new HistoryStatsDAO();

        setLayout(new BorderLayout());
        setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, COLOR_TOP_BORDER));
        // 注意：禁止使用 Integer.MAX_VALUE 作为首选宽度。
        // 本组件位于 mainSplitPane 左组件的 SOUTH 区域，BorderLayout 会自动将其横向拉伸填满父容器，
        // 无需声明超大首选宽度。Integer.MAX_VALUE 会导致 JSplitPane 布局计算发生整数溢出
        // （left 组件首选宽度变为负数），造成主分割线无法拖动。
        setPreferredSize(new Dimension(0, HEIGHT_COLLAPSED));
        setMaximumSize(new Dimension(Integer.MAX_VALUE, HEIGHT_EXPANDED));

        // 初始化收缩视图标签
        initCollapsedLabels();
        // 初始化展开视图标签
        initExpandedLabels();

        // 创建CardLayout面板
        cardLayout = new CardLayout();
        cardPanel = new JPanel(cardLayout);
        cardPanel.setOpaque(false);

        // 创建收缩视图
        JPanel collapsedView = createCollapsedView();
        cardPanel.add(collapsedView, "collapsed");

        // 创建展开视图
        JPanel expandedView = createExpandedView();
        cardPanel.add(expandedView, "expanded");

        add(cardPanel, BorderLayout.CENTER);

        // 添加双击监听器（递归到所有子组件）
        addDoubleClickListener(this);

        // 初始加载数据
        refreshStats();

        // 注册语言变更监听
        I18nManager.getInstance().addLocaleChangeListener(this::refreshTexts);
    }

    /**
     * 语言变更时刷新文本
     */
    private void refreshTexts() {
        for (TitleLabelRef ref : titleLabels) {
            ref.label.setText(I18nManager.tr(ref.key));
        }
        if (hintLabel != null) {
            hintLabel.setText(I18nManager.tr("history.stats.expand"));
        }
        revalidate();
        repaint();
    }

    /**
     * 初始化收缩视图标签
     */
    private void initCollapsedLabels() {
        cTotalCount = createValueLabel("0");
        cSuccessCount = createValueLabel("0", COLOR_SUCCESS);
        cFailureCount = createValueLabel("0", COLOR_FAILURE);
        cRetryCount = createValueLabel("0", COLOR_RETRY);
        cMaxTime = createValueLabel("0");
        cMinTime = createValueLabel("0");
    }

    /**
     * 初始化展开视图标签
     */
    private void initExpandedLabels() {
        eTotalCount = createValueLabel("0");
        eSuccessCount = createValueLabel("0", COLOR_SUCCESS);
        eFailureCount = createValueLabel("0", COLOR_FAILURE);
        eRetryCount = createValueLabel("0", COLOR_RETRY);
        eMaxTime = createValueLabel("0");
        eMinTime = createValueLabel("0");
        eAvgTime = createValueLabel("0");
        eVariance = createValueLabel("0");
        eModeTime = createValueLabel("0");
        eMedianTime = createValueLabel("0");
        eRequestCount = createValueLabel("0");
    }

    /**
     * 创建收缩视图（单行精简信息）
     */
    private JPanel createCollapsedView() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        panel.setOpaque(false);

        panel.add(createTitleLabel("history.stats.total"));
        panel.add(cTotalCount);

        panel.add(createSeparator());
        panel.add(createTitleLabel("history.stats.success"));
        panel.add(cSuccessCount);

        panel.add(createSeparator());
        panel.add(createTitleLabel("history.stats.failure"));
        panel.add(cFailureCount);

        panel.add(createSeparator());
        panel.add(createTitleLabel("history.stats.retry"));
        panel.add(cRetryCount);

        panel.add(createSeparator());
        panel.add(createTitleLabel("history.stats.max"));
        panel.add(cMaxTime);
        panel.add(createUnitLabel("ms"));

        panel.add(createSeparator());
        panel.add(createTitleLabel("history.stats.min"));
        panel.add(cMinTime);
        panel.add(createUnitLabel("ms"));

        // 右侧提示
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 4));
        rightPanel.setOpaque(false);
        hintLabel = new JLabel(I18nManager.tr("history.stats.expand"));
        hintLabel.setFont(FONT_HINT);
        hintLabel.setForeground(COLOR_HINT);
        rightPanel.add(hintLabel);

        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setOpaque(false);
        wrapper.add(panel, BorderLayout.WEST);
        wrapper.add(rightPanel, BorderLayout.EAST);

        return wrapper;
    }

    /**
     * 创建展开视图（两行完整信息）
     */
    private JPanel createExpandedView() {
        JPanel panel = new JPanel(new GridLayout(2, 1, 0, 2));
        panel.setOpaque(false);
        panel.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));

        // 第一行：数量统计
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        row1.setOpaque(false);

        row1.add(createTitleLabel("history.stats.totalFull"));
        row1.add(eTotalCount);

        row1.add(createSeparator());
        row1.add(createTitleLabel("history.stats.success"));
        row1.add(eSuccessCount);

        row1.add(createSeparator());
        row1.add(createTitleLabel("history.stats.failure"));
        row1.add(eFailureCount);

        row1.add(createSeparator());
        row1.add(createTitleLabel("history.stats.retry"));
        row1.add(eRetryCount);

        row1.add(createSeparator());
        row1.add(createTitleLabel("history.stats.baseline"));
        row1.add(eRequestCount);

        // 第二行：性能统计
        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        row2.setOpaque(false);

        row2.add(createTitleLabel("history.stats.avg"));
        row2.add(eAvgTime);
        row2.add(createUnitLabel("ms"));

        row2.add(createSeparator());
        row2.add(createTitleLabel("history.stats.stddev"));
        row2.add(eVariance);

        row2.add(createSeparator());
        row2.add(createTitleLabel("history.stats.mode"));
        row2.add(eModeTime);
        row2.add(createUnitLabel("ms"));

        row2.add(createSeparator());
        row2.add(createTitleLabel("history.stats.median"));
        row2.add(eMedianTime);
        row2.add(createUnitLabel("ms"));

        row2.add(createSeparator());
        row2.add(createTitleLabel("history.stats.range"));
        row2.add(eMinTime);
        row2.add(createUnitLabel("ms"));
        JLabel tildeLabel = new JLabel("~");
        tildeLabel.setFont(FONT_TITLE);
        tildeLabel.setForeground(COLOR_TITLE);
        row2.add(tildeLabel);
        row2.add(eMaxTime);
        row2.add(createUnitLabel("ms"));

        panel.add(row1);
        panel.add(row2);

        return panel;
    }

    /**
     * 创建标题标签（按资源键，注册以便语言切换刷新）
     */
    private JLabel createTitleLabel(String resourceKey) {
        JLabel label = new JLabel(I18nManager.tr(resourceKey));
        label.setFont(FONT_TITLE);
        label.setForeground(COLOR_TITLE);
        titleLabels.add(new TitleLabelRef(label, resourceKey));
        return label;
    }

    /**
     * 创建数值标签
     */
    private JLabel createValueLabel(String text) {
        return createValueLabel(text, null);
    }

    private JLabel createValueLabel(String text, Color color) {
        JLabel label = new JLabel(text);
        label.setFont(FONT_VALUE);
        if (color != null) {
            label.setForeground(color);
        }
        return label;
    }

    /**
     * 创建单位标签
     */
    private JLabel createUnitLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(FONT_HINT);
        label.setForeground(COLOR_HINT);
        return label;
    }

    /**
     * 创建分隔符
     */
    private JLabel createSeparator() {
        JLabel sep = new JLabel("|");
        sep.setFont(FONT_HINT);
        sep.setForeground(COLOR_HINT);
        return sep;
    }

    /**
     * 递归添加双击监听器到所有组件
     */
    private void addDoubleClickListener(Component component) {
        MouseAdapter adapter = new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    toggleExpand();
                }
            }
        };

        component.addMouseListener(adapter);

        if (component instanceof Container) {
            for (Component child : ((Container) component).getComponents()) {
                addDoubleClickListener(child);
            }
        }
    }

    /**
     * 切换展开/收缩状态
     */
    private void toggleExpand() {
        isExpanded = !isExpanded;

        if (isExpanded) {
            cardLayout.show(cardPanel, "expanded");
            animateHeight(HEIGHT_COLLAPSED, HEIGHT_EXPANDED);
        } else {
            cardLayout.show(cardPanel, "collapsed");
            animateHeight(HEIGHT_EXPANDED, HEIGHT_COLLAPSED);
        }
    }

    /**
     * 高度动画（cubic ease-out）
     */
    private void animateHeight(int fromHeight, int toHeight) {
        if (animationTimer != null && animationTimer.isRunning()) {
            animationTimer.stop();
        }

        final int steps = 15;
        final int delay = ANIMATION_DURATION_MS / steps;
        final int[] currentStep = {0};

        animationTimer = new Timer(delay, e -> {
            currentStep[0]++;
            double progress = (double) currentStep[0] / steps;
            // cubic ease-out: 1 - (1 - t)^3
            double eased = 1.0 - Math.pow(1.0 - progress, 3);
            int newHeight = (int) (fromHeight + (toHeight - fromHeight) * eased);

            // 与构造函数保持一致：宽度由父布局拉伸，避免 Integer.MAX_VALUE 引发 JSplitPane 布局溢出
            setPreferredSize(new Dimension(0, newHeight));
            revalidate();
            repaint();

            if (currentStep[0] >= steps) {
                ((Timer) e.getSource()).stop();
                setPreferredSize(new Dimension(0, toHeight));
                revalidate();
            }
        });

        animationTimer.start();
    }

    /**
     * 刷新全局统计（所有历史记录）
     */
    public void refreshStats() {
        refreshStats(-1);
    }

    /**
     * 刷新统计（指定requestId，-1表示全局）
     * 在后台线程执行查询，EDT更新UI
     */
    public void refreshStats(int requestId) {
        this.currentRequestId = requestId;

        new Thread(() -> {
            try {
                HistoryStatsData data;
                if (requestId <= 0) {
                    data = statsDAO.getGlobalStats();
                } else {
                    data = statsDAO.getStatsByRequestId(requestId);
                }

                SwingUtilities.invokeLater(() -> updateLabels(data));
            } catch (Exception e) {
                LogManager.getInstance().printError(I18nManager.tr("log.stats.refresh.failed", e.getMessage()));
            }
        }).start();
    }

    /**
     * 更新所有标签显示
     */
    private void updateLabels(HistoryStatsData data) {
        if (data == null) {
            return;
        }

        String totalCount = String.valueOf(data.getTotalCount());
        String successCount = String.valueOf(data.getSuccessCount());
        String failureCount = String.valueOf(data.getFailureCount());
        String retryCount = String.valueOf(data.getRetryCount());
        String maxTime = String.valueOf(data.getMaxResponseTime());
        String minTime = String.valueOf(data.getMinResponseTime());
        String avgTime = DECIMAL_FMT.format(data.getAvgResponseTime());
        String stdDev = DECIMAL_FMT.format(Math.sqrt(data.getVariance()));
        String modeTime = String.valueOf(data.getModeResponseTime());
        String medianTime = DECIMAL_FMT.format(data.getMedianResponseTime());
        String requestCount = String.valueOf(data.getRequestCount());

        // 更新收缩视图标签
        cTotalCount.setText(totalCount);
        cSuccessCount.setText(successCount);
        cFailureCount.setText(failureCount);
        cRetryCount.setText(retryCount);
        cMaxTime.setText(maxTime);
        cMinTime.setText(minTime);

        // 更新展开视图标签
        eTotalCount.setText(totalCount);
        eSuccessCount.setText(successCount);
        eFailureCount.setText(failureCount);
        eRetryCount.setText(retryCount);
        eMaxTime.setText(maxTime);
        eMinTime.setText(minTime);
        eAvgTime.setText(avgTime);
        eVariance.setText(stdDev);
        eModeTime.setText(modeTime);
        eMedianTime.setText(medianTime);
        eRequestCount.setText(requestCount);

        revalidate();
        repaint();
    }

    /**
     * 获取当前是否展开
     */
    public boolean isExpanded() {
        return isExpanded;
    }

    /**
     * 获取当前关联的requestId
     */
    public int getCurrentRequestId() {
        return currentRequestId;
    }
}

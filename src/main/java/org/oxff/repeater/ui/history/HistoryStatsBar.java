package org.oxff.repeater.ui.history;

import burp.BurpExtender;
import org.oxff.repeater.db.history.HistoryStatsDAO;

import javax.swing.*;
import javax.swing.border.Border;
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

    // 共享标签引用（收缩和展开视图共用）
    private JLabel lblTotalCount;
    private JLabel lblSuccessCount;
    private JLabel lblFailureCount;
    private JLabel lblRetryCount;
    private JLabel lblMaxTime;
    private JLabel lblMinTime;
    private JLabel lblAvgTime;
    private JLabel lblVariance;
    private JLabel lblModeTime;
    private JLabel lblMedianTime;
    private JLabel lblRequestCount;

    // 动画Timer
    private Timer animationTimer;

    public HistoryStatsBar() {
        this.statsDAO = new HistoryStatsDAO();

        setLayout(new BorderLayout());
        setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, COLOR_TOP_BORDER));
        setPreferredSize(new Dimension(Integer.MAX_VALUE, HEIGHT_COLLAPSED));
        setMaximumSize(new Dimension(Integer.MAX_VALUE, HEIGHT_EXPANDED));

        // 初始化共享标签
        initSharedLabels();

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
    }

    /**
     * 初始化共享标签
     */
    private void initSharedLabels() {
        lblTotalCount = createValueLabel("0");
        lblSuccessCount = createValueLabel("0", COLOR_SUCCESS);
        lblFailureCount = createValueLabel("0", COLOR_FAILURE);
        lblRetryCount = createValueLabel("0", COLOR_RETRY);
        lblMaxTime = createValueLabel("0");
        lblMinTime = createValueLabel("0");
        lblAvgTime = createValueLabel("0");
        lblVariance = createValueLabel("0");
        lblModeTime = createValueLabel("0");
        lblMedianTime = createValueLabel("0");
        lblRequestCount = createValueLabel("0");
    }

    /**
     * 创建收缩视图（单行精简信息）
     */
    private JPanel createCollapsedView() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        panel.setOpaque(false);

        panel.add(createTitleLabel("历史:"));
        panel.add(lblTotalCount);

        panel.add(createSeparator());
        panel.add(createTitleLabel("成功:"));
        panel.add(lblSuccessCount);

        panel.add(createSeparator());
        panel.add(createTitleLabel("失败:"));
        panel.add(lblFailureCount);

        panel.add(createSeparator());
        panel.add(createTitleLabel("重试:"));
        panel.add(lblRetryCount);

        panel.add(createSeparator());
        panel.add(createTitleLabel("最高:"));
        panel.add(lblMaxTime);
        panel.add(createUnitLabel("ms"));

        panel.add(createSeparator());
        panel.add(createTitleLabel("最低:"));
        panel.add(lblMinTime);
        panel.add(createUnitLabel("ms"));

        // 右侧提示
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 4));
        rightPanel.setOpaque(false);
        JLabel hintLabel = new JLabel("(双击展开)");
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

        row1.add(createTitleLabel("历史总数:"));
        row1.add(lblTotalCount);

        row1.add(createSeparator());
        row1.add(createTitleLabel("成功:"));
        row1.add(lblSuccessCount);

        row1.add(createSeparator());
        row1.add(createTitleLabel("失败:"));
        row1.add(lblFailureCount);

        row1.add(createSeparator());
        row1.add(createTitleLabel("重试:"));
        row1.add(lblRetryCount);

        row1.add(createSeparator());
        row1.add(createTitleLabel("基准请求:"));
        row1.add(lblRequestCount);

        // 第二行：性能统计
        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        row2.setOpaque(false);

        row2.add(createTitleLabel("平均:"));
        row2.add(lblAvgTime);
        row2.add(createUnitLabel("ms"));

        row2.add(createSeparator());
        row2.add(createTitleLabel("方差:"));
        row2.add(lblVariance);

        row2.add(createSeparator());
        row2.add(createTitleLabel("众数:"));
        row2.add(lblModeTime);
        row2.add(createUnitLabel("ms"));

        row2.add(createSeparator());
        row2.add(createTitleLabel("中位数:"));
        row2.add(lblMedianTime);
        row2.add(createUnitLabel("ms"));

        row2.add(createSeparator());
        row2.add(createTitleLabel("范围:"));
        row2.add(lblMinTime);
        row2.add(createUnitLabel("ms"));
        row2.add(createTitleLabel("~"));
        row2.add(lblMaxTime);
        row2.add(createUnitLabel("ms"));

        panel.add(row1);
        panel.add(row2);

        return panel;
    }

    /**
     * 创建标题标签
     */
    private JLabel createTitleLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(FONT_TITLE);
        label.setForeground(COLOR_TITLE);
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

            setPreferredSize(new Dimension(Integer.MAX_VALUE, newHeight));
            revalidate();
            repaint();

            if (currentStep[0] >= steps) {
                ((Timer) e.getSource()).stop();
                setPreferredSize(new Dimension(Integer.MAX_VALUE, toHeight));
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
                BurpExtender.printError("[!] 刷新统计失败: " + e.getMessage());
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

        lblTotalCount.setText(String.valueOf(data.getTotalCount()));
        lblSuccessCount.setText(String.valueOf(data.getSuccessCount()));
        lblFailureCount.setText(String.valueOf(data.getFailureCount()));
        lblRetryCount.setText(String.valueOf(data.getRetryCount()));
        lblMaxTime.setText(String.valueOf(data.getMaxResponseTime()));
        lblMinTime.setText(String.valueOf(data.getMinResponseTime()));
        lblAvgTime.setText(DECIMAL_FMT.format(data.getAvgResponseTime()));
        lblVariance.setText(DECIMAL_FMT.format(data.getVariance()));
        lblModeTime.setText(String.valueOf(data.getModeResponseTime()));
        lblMedianTime.setText(DECIMAL_FMT.format(data.getMedianResponseTime()));
        lblRequestCount.setText(String.valueOf(data.getRequestCount()));

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

package org.oxff.repeater.ui.history;

import org.oxff.repeater.http.RequestResponseRecord;
import org.oxff.repeater.i18n.I18nManager;

import javax.swing.*;
import java.awt.*;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * 报文比对对话框 - 支持字符串级(含行内字符级差异)和字节级(hex)比对
 * 双Tab模式：请求比对Tab / 响应比对Tab（左右同步滚动，左原始右会话）
 * 四面板模式：田字格2x2布局，支持上下布局(按原始/会话分行)和左右布局(按请求/响应分行)
 * 支持最大化/全屏/手动拉大，默认占屏幕90%
 * 支持差异导航(上一个/下一个差异)和每个面板独立搜索(Ctrl+F)
 */
public class ComparisonDialog extends JDialog {
    private static final long serialVersionUID = 1L;

    private final RequestResponseRecord originalRecord;
    private final RequestResponseRecord sessionRecord;

    private boolean isHexMode = false;
    private boolean isFourPaneMode = false;
    private boolean isVerticalSubLayout = true; // true=上下布局, false=左右布局
    private boolean isMaximized = false; // 最大化状态（与显示文本解耦）

    private JToggleButton stringModeBtn;
    private JToggleButton hexModeBtn;
    private JToggleButton fourPaneToggleBtn;
    private JButton maximizeBtn;
    private JButton prevDiffBtn;
    private JButton nextDiffBtn;
    private JLabel diffCountLabel;
    private JToggleButton verticalLayoutBtn;
    private JToggleButton horizontalLayoutBtn;
    private JPanel centerPanel;

    // 双Tab模式的面板（每次刷新重建）
    private JTabbedPane dualTabPane;
    // 四面板模式的容器（每次刷新重建）
    private JSplitPane fourPaneSplit;

    // 差异导航器（每次刷新重建）
    private DiffNavigator diffNavigator;

    private double requestSimilarity;
    private double responseSimilarity;

    public ComparisonDialog(Component parent, RequestResponseRecord originalRecord, RequestResponseRecord sessionRecord) {
        super((Frame) SwingUtilities.getWindowAncestor(parent), I18nManager.tr("comparison.title"), false);
        this.originalRecord = originalRecord;
        this.sessionRecord = sessionRecord;

        // 计算相似度
        requestSimilarity = DiffEngine.computeSimilarity(
            bytesToString(originalRecord.getRequestData()),
            bytesToString(sessionRecord.getRequestData()));
        responseSimilarity = DiffEngine.computeSimilarity(
            bytesToString(originalRecord.getResponseData()),
            bytesToString(sessionRecord.getResponseData()));

        initUI();

        // 默认占屏幕90%大小
        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
        setSize((int)(screenSize.width * 0.9), (int)(screenSize.height * 0.9));
        setLocationRelativeTo(parent);
    }

    private void initUI() {
        setLayout(new BorderLayout());

        // 顶部信息面板
        add(createInfoPanel(), BorderLayout.NORTH);

        // 中间比对区域
        centerPanel = new JPanel(new BorderLayout());
        buildAndShowComparison();
        add(centerPanel, BorderLayout.CENTER);

        // 底部按钮面板
        add(createBottomPanel(), BorderLayout.SOUTH);

        // 注册 Ctrl+F 快捷键
        getRootPane().registerKeyboardAction(
            e -> toggleSearchForActivePane(),
            KeyStroke.getKeyStroke(KeyEvent.VK_F, InputEvent.CTRL_DOWN_MASK),
            JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT
        );
    }

    // ==================== 比对面板构建 ====================

    /**
     * 构建比对面板并显示到centerPanel
     */
    private void buildAndShowComparison() {
        centerPanel.removeAll();
        diffNavigator = null;

        if (isFourPaneMode) {
            // 四面板模式
            fourPaneSplit = buildFourPaneLayout();
            centerPanel.add(fourPaneSplit, BorderLayout.CENTER);
        } else {
            // 双Tab模式
            Component reqComparison = buildSingleComparison(
                originalRecord.getRequestData(), sessionRecord.getRequestData());

            Component resComparison = buildSingleComparison(
                originalRecord.getResponseData(), sessionRecord.getResponseData());

            dualTabPane = new JTabbedPane();
            dualTabPane.addTab(I18nManager.tr("comparison.request"), reqComparison);
            dualTabPane.addTab(I18nManager.tr("comparison.response"), resComparison);
            centerPanel.add(dualTabPane, BorderLayout.CENTER);
        }

        centerPanel.revalidate();
        centerPanel.repaint();
    }

    /**
     * 构建单个比对面板（双Tab模式使用）
     * 左侧=原始报文，右侧=用户会话报文，同步滚动
     */
    private Component buildSingleComparison(byte[] originalData, byte[] sessionData) {
        DiffPane origDiffPane = new DiffPane();
        DiffPane sessDiffPane = new DiffPane();

        if (isHexMode) {
            List<DiffSegment> diff = DiffEngine.computeByteDiff(originalData, sessionData);
            origDiffPane.renderHexDiffSegments(diff, true);
            sessDiffPane.renderHexDiffSegments(diff, false);
        } else {
            String origStr = bytesToString(originalData);
            String sessStr = bytesToString(sessionData);
            List<DiffLine> diff = DiffEngine.computeLineDiff(origStr, sessStr);
            origDiffPane.renderDiffLines(diff, true);
            sessDiffPane.renderDiffLines(diff, false);
        }

        SynchronizedScrollPanel syncPanel = new SynchronizedScrollPanel(origDiffPane, sessDiffPane);

        // 创建导航器
        if (diffNavigator == null) {
            diffNavigator = new DiffNavigator(origDiffPane, sessDiffPane);
        }

        return syncPanel;
    }

    /**
     * 构建四面板布局 — 田字格2x2网格
     * 上下布局: 上=原始报文(左请求右响应)，下=会话报文(左请求右响应)
     * 左右布局: 上=请求对比(左原始右会话)，下=响应对比(左原始右会话)
     */
    private JSplitPane buildFourPaneLayout() {
        DiffPane origReqPane = new DiffPane();
        DiffPane sessReqPane = new DiffPane();
        DiffPane origResPane = new DiffPane();
        DiffPane sessResPane = new DiffPane();

        if (isHexMode) {
            origReqPane.renderPlainText(originalRecord.getRequestData(), true);
            sessReqPane.renderPlainText(sessionRecord.getRequestData(), true);
            origResPane.renderPlainText(originalRecord.getResponseData(), true);
            sessResPane.renderPlainText(sessionRecord.getResponseData(), true);
        } else {
            String origReqStr = bytesToString(originalRecord.getRequestData());
            String sessReqStr = bytesToString(sessionRecord.getRequestData());
            List<DiffLine> reqDiff = DiffEngine.computeLineDiff(origReqStr, sessReqStr);
            origReqPane.renderDiffLines(reqDiff, true);
            sessReqPane.renderDiffLines(reqDiff, false);

            String origResStr = bytesToString(originalRecord.getResponseData());
            String sessResStr = bytesToString(sessionRecord.getResponseData());
            List<DiffLine> resDiff = DiffEngine.computeLineDiff(origResStr, sessResStr);
            origResPane.renderDiffLines(resDiff, true);
            sessResPane.renderDiffLines(resDiff, false);
        }

        JPanel topLeft, topRight, bottomLeft, bottomRight;

        if (isVerticalSubLayout) {
            // 上下布局: 上=原始行，下=会话行
            topLeft = createTitledDiffPanePanel(I18nManager.tr("comparison.original.request"), origReqPane);
            topRight = createTitledDiffPanePanel(I18nManager.tr("comparison.original.response"), origResPane);
            bottomLeft = createTitledDiffPanePanel(I18nManager.tr("comparison.session.request"), sessReqPane);
            bottomRight = createTitledDiffPanePanel(I18nManager.tr("comparison.session.response"), sessResPane);
        } else {
            // 左右布局: 上=请求对比行，下=响应对比行
            topLeft = createTitledDiffPanePanel(I18nManager.tr("comparison.original.request"), origReqPane);
            topRight = createTitledDiffPanePanel(I18nManager.tr("comparison.session.request"), sessReqPane);
            bottomLeft = createTitledDiffPanePanel(I18nManager.tr("comparison.original.response"), origResPane);
            bottomRight = createTitledDiffPanePanel(I18nManager.tr("comparison.session.response"), sessResPane);
        }

        // 上半行: 水平分割
        JSplitPane topSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, topLeft, topRight);
        topSplit.setResizeWeight(0.5);
        topSplit.setDividerLocation(0.5);
        topSplit.setOneTouchExpandable(true);

        // 下半行: 水平分割
        JSplitPane bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, bottomLeft, bottomRight);
        bottomSplit.setResizeWeight(0.5);
        bottomSplit.setDividerLocation(0.5);
        bottomSplit.setOneTouchExpandable(true);

        // 外层: 垂直分割（上+下）
        JSplitPane outerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topSplit, bottomSplit);
        outerSplit.setResizeWeight(0.5);
        outerSplit.setDividerLocation(0.5);
        outerSplit.setOneTouchExpandable(true);

        // 设置垂直滚动同步（原始↔会话，请求配对和响应配对）
        setupVerticalScrollSync(origReqPane.getScrollPane(), sessReqPane.getScrollPane());
        setupVerticalScrollSync(origResPane.getScrollPane(), sessResPane.getScrollPane());

        // 导航器使用请求对比对
        diffNavigator = new DiffNavigator(origReqPane, sessReqPane);

        return outerSplit;
    }

    /**
     * 创建带标题的 DiffPane 面板
     */
    private JPanel createTitledDiffPanePanel(String title, DiffPane diffPane) {
        JPanel panel = new JPanel(new BorderLayout());
        JLabel titleLabel = new JLabel(title);
        titleLabel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD));
        panel.add(titleLabel, BorderLayout.NORTH);
        panel.add(diffPane, BorderLayout.CENTER);
        return panel;
    }

    /**
     * 设置两个 JScrollPane 的垂直滚动同步
     */
    private void setupVerticalScrollSync(JScrollPane sp1, JScrollPane sp2) {
        final boolean[] syncing = {false};

        sp1.getVerticalScrollBar().addAdjustmentListener(e -> {
            if (!syncing[0]) {
                syncing[0] = true;
                JScrollBar sb1 = sp1.getVerticalScrollBar();
                JScrollBar sb2 = sp2.getVerticalScrollBar();
                if (sb1.getMaximum() > 0 && sb2.getMaximum() > 0) {
                    double ratio = (double) sb1.getValue() / sb1.getMaximum();
                    sb2.setValue((int) (ratio * sb2.getMaximum()));
                }
                syncing[0] = false;
            }
        });

        sp2.getVerticalScrollBar().addAdjustmentListener(e -> {
            if (!syncing[0]) {
                syncing[0] = true;
                JScrollBar sb1 = sp1.getVerticalScrollBar();
                JScrollBar sb2 = sp2.getVerticalScrollBar();
                if (sb1.getMaximum() > 0 && sb2.getMaximum() > 0) {
                    double ratio = (double) sb2.getValue() / sb2.getMaximum();
                    sb1.setValue((int) (ratio * sb1.getMaximum()));
                }
                syncing[0] = false;
            }
        });
    }

    // ==================== 信息面板 ====================

    private JPanel createInfoPanel() {
        JPanel infoPanel = new JPanel();
        infoPanel.setLayout(new BoxLayout(infoPanel, BoxLayout.Y_AXIS));
        infoPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        // 第一行：会话信息
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        row1.add(new JLabel(I18nManager.tr("comparison.original.prefix") + " [ID=" + originalRecord.getId() + "]"));
        row1.add(new JLabel("  |  "));
        row1.add(new JLabel(I18nManager.tr("comparison.session.prefix") + " [" + (sessionRecord.getUserSessionName() != null ? sessionRecord.getUserSessionName() : I18nManager.tr("comparison.unknown")) + "]"));
        row1.add(new JLabel("  |  "));
        JLabel reqSimLabel = new JLabel(I18nManager.tr("comparison.similarity.request", String.format("%.2f", requestSimilarity * 100)));
        reqSimLabel.setFont(reqSimLabel.getFont().deriveFont(Font.BOLD));
        row1.add(reqSimLabel);
        row1.add(new JLabel("  |  "));
        JLabel resSimLabel = new JLabel(I18nManager.tr("comparison.similarity.response", String.format("%.2f", responseSimilarity * 100)));
        resSimLabel.setFont(resSimLabel.getFont().deriveFont(Font.BOLD));
        row1.add(resSimLabel);

        if (sessionRecord.getJudgment() != null) {
            row1.add(new JLabel("  |  "));
            JLabel judgmentLabel = new JLabel(I18nManager.tr("comparison.judgment") + " " + org.oxff.repeater.privilege.model.JudgmentResult.toDisplayName(sessionRecord.getJudgment()));
            judgmentLabel.setForeground(getJudgmentColor(sessionRecord.getJudgment()));
            judgmentLabel.setFont(judgmentLabel.getFont().deriveFont(Font.BOLD, 14f));
            row1.add(judgmentLabel);
        }

        // 第二行：模式按钮 + 差异导航 + 最大化
        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));

        stringModeBtn = new JToggleButton(I18nManager.tr("comparison.mode.string"));
        stringModeBtn.setSelected(true);
        hexModeBtn = new JToggleButton(I18nManager.tr("comparison.mode.hex"));
        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(stringModeBtn);
        modeGroup.add(hexModeBtn);

        stringModeBtn.addActionListener(e -> {
            if (stringModeBtn.isSelected()) {
                isHexMode = false;
                buildAndShowComparison();
                updateDiffNavigatorStatus();
            }
        });
        hexModeBtn.addActionListener(e -> {
            if (hexModeBtn.isSelected()) {
                isHexMode = true;
                buildAndShowComparison();
                updateDiffNavigatorStatus();
            }
        });

        fourPaneToggleBtn = new JToggleButton(I18nManager.tr("comparison.mode.quad"));
        fourPaneToggleBtn.addActionListener(e -> {
            isFourPaneMode = fourPaneToggleBtn.isSelected();
            verticalLayoutBtn.setEnabled(isFourPaneMode);
            horizontalLayoutBtn.setEnabled(isFourPaneMode);
            buildAndShowComparison();
            updateDiffNavigatorStatus();
        });

        // 四面板子布局选择
        verticalLayoutBtn = new JToggleButton(I18nManager.tr("comparison.layout.vertical"));
        verticalLayoutBtn.setSelected(true);
        verticalLayoutBtn.setEnabled(false);
        verticalLayoutBtn.setToolTipText(I18nManager.tr("comparison.layout.vertical.tooltip"));

        horizontalLayoutBtn = new JToggleButton(I18nManager.tr("comparison.layout.horizontal"));
        horizontalLayoutBtn.setEnabled(false);
        horizontalLayoutBtn.setToolTipText(I18nManager.tr("comparison.layout.horizontal.tooltip"));

        ButtonGroup subLayoutGroup = new ButtonGroup();
        subLayoutGroup.add(verticalLayoutBtn);
        subLayoutGroup.add(horizontalLayoutBtn);

        verticalLayoutBtn.addActionListener(e -> {
            isVerticalSubLayout = true;
            buildAndShowComparison();
            updateDiffNavigatorStatus();
        });
        horizontalLayoutBtn.addActionListener(e -> {
            isVerticalSubLayout = false;
            buildAndShowComparison();
            updateDiffNavigatorStatus();
        });

        // 差异导航
        prevDiffBtn = new JButton(I18nManager.tr("comparison.prev.diff"));
        prevDiffBtn.setToolTipText(I18nManager.tr("comparison.prev.diff.tooltip"));
        prevDiffBtn.addActionListener(e -> {
            if (diffNavigator != null) {
                diffNavigator.prevDiff();
                updateDiffNavigatorStatus();
            }
        });

        nextDiffBtn = new JButton(I18nManager.tr("comparison.next.diff"));
        nextDiffBtn.setToolTipText(I18nManager.tr("comparison.next.diff.tooltip"));
        nextDiffBtn.addActionListener(e -> {
            if (diffNavigator != null) {
                diffNavigator.nextDiff();
                updateDiffNavigatorStatus();
            }
        });

        diffCountLabel = new JLabel(I18nManager.tr("comparison.diff.zero"));
        diffCountLabel.setFont(diffCountLabel.getFont().deriveFont(Font.BOLD));

        JButton searchBtn = new JButton(I18nManager.tr("comparison.search"));
        searchBtn.setToolTipText(I18nManager.tr("comparison.search.tooltip"));
        searchBtn.addActionListener(e -> toggleSearchForActivePane());

        maximizeBtn = new JButton(I18nManager.tr("comparison.maximize"));
        maximizeBtn.addActionListener(e -> {
            Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
            if (!isMaximized) {
                setLocation(0, 0);
                setSize(screenSize.width, screenSize.height);
                maximizeBtn.setText(I18nManager.tr("comparison.restore"));
                isMaximized = true;
            } else {
                setSize((int)(screenSize.width * 0.9), (int)(screenSize.height * 0.9));
                setLocationRelativeTo(null);
                maximizeBtn.setText(I18nManager.tr("comparison.maximize"));
                isMaximized = false;
            }
        });

        row2.add(stringModeBtn);
        row2.add(hexModeBtn);
        row2.add(fourPaneToggleBtn);
        row2.add(verticalLayoutBtn);
        row2.add(horizontalLayoutBtn);
        row2.add(Box.createHorizontalStrut(10));
        row2.add(prevDiffBtn);
        row2.add(diffCountLabel);
        row2.add(nextDiffBtn);
        row2.add(Box.createHorizontalStrut(10));
        row2.add(searchBtn);
        row2.add(maximizeBtn);

        infoPanel.add(row1);
        infoPanel.add(row2);

        return infoPanel;
    }

    /**
     * 更新差异导航状态显示
     */
    private void updateDiffNavigatorStatus() {
        if (diffNavigator != null) {
            diffCountLabel.setText(diffNavigator.getStatusText());
        } else {
            diffCountLabel.setText(I18nManager.tr("comparison.diff.zero"));
        }
    }

    // ==================== 底部面板 ====================

    private JPanel createBottomPanel() {
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));

        JLabel shortcutHint = new JLabel(I18nManager.tr("comparison.search.hint"));
        shortcutHint.setForeground(Color.GRAY);
        bottomPanel.add(shortcutHint);
        bottomPanel.add(Box.createHorizontalStrut(20));

        JButton closeBtn = new JButton(I18nManager.tr("comparison.close"));
        closeBtn.addActionListener(e -> dispose());
        bottomPanel.add(closeBtn);
        return bottomPanel;
    }

    // ==================== 搜索栏控制 ====================

    /**
     * 切换当前焦点面板的搜索栏
     */
    private void toggleSearchForActivePane() {
        DiffPane activePane = findActiveDiffPane();
        if (activePane != null) {
            activePane.toggleSearchBar();
        }
    }

    /**
     * 查找当前焦点的 DiffPane
     */
    private DiffPane findActiveDiffPane() {
        Component focusOwner = getFocusOwner();
        if (focusOwner == null) {
            // 如果没有焦点，默认返回请求区的左侧面板
            return findFirstDiffPane();
        }

        // 从焦点组件向上查找 DiffPane
        Component parent = focusOwner;
        while (parent != null) {
            if (parent instanceof DiffPane) {
                return (DiffPane) parent;
            }
            parent = parent.getParent();
        }

        // 焦点不在 DiffPane 内，返回第一个
        return findFirstDiffPane();
    }

    /**
     * 查找对话框中第一个 DiffPane
     */
    private DiffPane findFirstDiffPane() {
        if (centerPanel == null) return null;

        if (isFourPaneMode && fourPaneSplit != null) {
            return findDiffPaneInContainer(fourPaneSplit);
        } else if (dualTabPane != null) {
            Component selectedTab = dualTabPane.getSelectedComponent();
            if (selectedTab != null) {
                return findDiffPaneInContainer(selectedTab);
            }
        }
        return null;
    }

    /**
     * 在容器中递归查找 DiffPane
     */
    private DiffPane findDiffPaneInContainer(Component container) {
        if (container instanceof DiffPane) {
            return (DiffPane) container;
        }
        if (container instanceof Container) {
            for (Component child : ((Container) container).getComponents()) {
                DiffPane result = findDiffPaneInContainer(child);
                if (result != null) return result;
            }
        }
        return null;
    }

    // ==================== 辅助方法 ====================

    private String bytesToString(byte[] data) {
        if (data == null) return "";
        int bodyOffset = findBodyOffset(data);
        if (bodyOffset > 0 && bodyOffset < data.length) {
            String header = new String(data, 0, bodyOffset, StandardCharsets.ISO_8859_1);
            String body = new String(data, bodyOffset, data.length - bodyOffset, StandardCharsets.UTF_8);
            return header + body;
        }
        return new String(data, StandardCharsets.UTF_8);
    }

    private int findBodyOffset(byte[] data) {
        for (int i = 0; i < data.length - 3; i++) {
            if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n') {
                return i + 4;
            }
        }
        for (int i = 0; i < data.length - 1; i++) {
            if (data[i] == '\n' && data[i + 1] == '\n') {
                return i + 2;
            }
        }
        return -1;
    }

    private Color getJudgmentColor(String judgment) {
        if (judgment == null) return Color.BLACK;
        switch (judgment) {
            case "ESCALATED": return new Color(204, 0, 0);
            case "NOT_ESCALATED": return new Color(0, 130, 0);
            case "ERROR": return Color.ORANGE;
            default: return Color.BLACK;
        }
    }
}

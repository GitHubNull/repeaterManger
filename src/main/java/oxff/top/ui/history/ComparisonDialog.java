package oxff.top.ui.history;

import oxff.top.http.RequestResponseRecord;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * 报文比对对话框 - 支持字符串级和字节级(hex)比对
 * 双Tab模式：请求比对Tab / 响应比对Tab（左右同步滚动，左原始右会话）
 * 四面板模式：左=请求区(上原始下会话)，右=响应区(上原始下会话)，JSplitPane可拖拽
 * 支持最大化/全屏/手动拉大，默认占屏幕90%
 */
public class ComparisonDialog extends JDialog {
    private static final long serialVersionUID = 1L;

    // 差异高亮颜色
    private static final Color COLOR_ADDED = new Color(200, 255, 200);     // 绿色：新增行
    private static final Color COLOR_REMOVED = new Color(255, 200, 200);   // 红色：删除行
    private static final Color COLOR_CHANGED = new Color(255, 255, 200);   // 黄色：修改行

    private final RequestResponseRecord originalRecord;
    private final RequestResponseRecord sessionRecord;

    private boolean isHexMode = false;
    private boolean isFourPaneMode = false;

    private JToggleButton stringModeBtn;
    private JToggleButton hexModeBtn;
    private JToggleButton fourPaneToggleBtn;
    private JButton maximizeBtn;
    private JPanel centerPanel;

    // 双Tab模式的面板（每次刷新重建）
    private JTabbedPane dualTabPane;
    // 四面板模式的容器（每次刷新重建）
    private JSplitPane fourPaneSplit;

    private double requestSimilarity;
    private double responseSimilarity;

    public ComparisonDialog(Component parent, RequestResponseRecord originalRecord, RequestResponseRecord sessionRecord) {
        super((Frame) SwingUtilities.getWindowAncestor(parent), "报文比对", false);
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
    }

    // ==================== 比对面板构建 ====================

    /**
     * 构建比对面板并显示到centerPanel
     */
    private void buildAndShowComparison() {
        centerPanel.removeAll();

        // 构建请求比对面板
        Component reqComparison = buildSingleComparison(
            originalRecord.getRequestData(), sessionRecord.getRequestData(), "请求报文");

        // 构建响应比对面板
        Component resComparison = buildSingleComparison(
            originalRecord.getResponseData(), sessionRecord.getResponseData(), "响应报文");

        // 双Tab模式
        dualTabPane = new JTabbedPane();
        dualTabPane.addTab("请求报文比对", reqComparison);
        dualTabPane.addTab("响应报文比对", resComparison);

        // 四面板模式：外层水平分割(左=请求，右=响应)
        // 每侧内部垂直分割(上=原始，下=用户会话)
        fourPaneSplit = buildFourPaneLayout(reqComparison, resComparison);

        if (isFourPaneMode) {
            centerPanel.add(fourPaneSplit, BorderLayout.CENTER);
        } else {
            centerPanel.add(dualTabPane, BorderLayout.CENTER);
        }

        centerPanel.revalidate();
        centerPanel.repaint();
    }

    /**
     * 构建四面板布局
     * 左=请求区(上原始下会话)，右=响应区(上原始下会话)
     * 所有divider可拖拽
     */
    private JSplitPane buildFourPaneLayout(Component reqComparison, Component resComparison) {
        // 分别构建原始和会话的独立面板
        JTextPane origReqPane = buildSingleContentPane(originalRecord.getRequestData(), "原始请求", false);
        JTextPane sessReqPane = buildSingleContentPane(sessionRecord.getRequestData(), "会话请求", false);
        JTextPane origResPane = buildSingleContentPane(originalRecord.getResponseData(), "原始响应", false);
        JTextPane sessResPane = buildSingleContentPane(sessionRecord.getResponseData(), "会话响应", false);

        // 为每个JTextPane创建JScrollPane（保留引用用于同步滚动）
        JScrollPane origReqScroll = new JScrollPane(origReqPane);
        origReqScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        JScrollPane sessReqScroll = new JScrollPane(sessReqPane);
        sessReqScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        JScrollPane origResScroll = new JScrollPane(origResPane);
        origResScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        JScrollPane sessResScroll = new JScrollPane(sessResPane);
        sessResScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        // 请求区垂直分割：上原始下会话
        JSplitPane reqSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
            wrapWithTitle(origReqScroll, "原始请求"),
            wrapWithTitle(sessReqScroll, "用户会话请求"));
        reqSplit.setResizeWeight(0.5);
        reqSplit.setDividerLocation(0.5);
        reqSplit.setOneTouchExpandable(true);

        // 响应区垂直分割：上原始下会话
        JSplitPane resSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
            wrapWithTitle(origResScroll, "原始响应"),
            wrapWithTitle(sessResScroll, "用户会话响应"));
        resSplit.setResizeWeight(0.5);
        resSplit.setDividerLocation(0.5);
        resSplit.setOneTouchExpandable(true);

        // 同步滚动：原始↔会话 请求区/响应区内的上下面板
        setupVerticalSync(origReqScroll, sessReqScroll);
        setupVerticalSync(origResScroll, sessResScroll);

        // 外层水平分割：左=请求区，右=响应区
        JSplitPane outerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqSplit, resSplit);
        outerSplit.setResizeWeight(0.5);
        outerSplit.setDividerLocation(0.5);
        outerSplit.setOneTouchExpandable(true);

        return outerSplit;
    }

    /**
     * 为四面板模式的上下两个面板设置垂直同步滚动
     * 直接接收JScrollPane引用，避免从JPanel中按索引提取导致ClassCastException
     */
    private void setupVerticalSync(JScrollPane topScroll, JScrollPane bottomScroll) {
        final boolean[] isSyncing = {false};

        topScroll.getVerticalScrollBar().addAdjustmentListener(e -> {
            if (!isSyncing[0]) {
                isSyncing[0] = true;
                JScrollBar topBar = topScroll.getVerticalScrollBar();
                JScrollBar bottomBar = bottomScroll.getVerticalScrollBar();
                if (topBar.getMaximum() > 0 && bottomBar.getMaximum() > 0) {
                    double ratio = (double) topBar.getValue() / topBar.getMaximum();
                    bottomBar.setValue((int)(ratio * bottomBar.getMaximum()));
                }
                isSyncing[0] = false;
            }
        });

        bottomScroll.getVerticalScrollBar().addAdjustmentListener(e -> {
            if (!isSyncing[0]) {
                isSyncing[0] = true;
                JScrollBar topBar = topScroll.getVerticalScrollBar();
                JScrollBar bottomBar = bottomScroll.getVerticalScrollBar();
                if (bottomBar.getMaximum() > 0 && topBar.getMaximum() > 0) {
                    double ratio = (double) bottomBar.getValue() / bottomBar.getMaximum();
                    topBar.setValue((int)(ratio * topBar.getMaximum()));
                }
                isSyncing[0] = false;
            }
        });
    }

    /**
     * 将JScrollPane包裹在带标题的JPanel中
     */
    private JPanel wrapWithTitle(JScrollPane scrollPane, String title) {
        JPanel wrapper = new JPanel(new BorderLayout());
        JLabel titleLabel = new JLabel(title);
        titleLabel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD));
        wrapper.add(titleLabel, BorderLayout.NORTH);
        wrapper.add(scrollPane, BorderLayout.CENTER);
        return wrapper;
    }

    /**
     * 构建单个比对面板（双Tab模式使用）
     * 左侧=原始报文，右侧=用户会话报文，同步滚动
     * 左右都渲染差异高亮（左侧显示REMOVED红色行，右侧显示ADDED绿色行）
     */
    private Component buildSingleComparison(byte[] originalData, byte[] sessionData, String label) {
        if (isHexMode) {
            List<DiffEngine.DiffSegment> diff = DiffEngine.computeByteDiff(originalData, sessionData);
            JTextPane origPane = buildHexDiffPane(diff, true);   // 左侧（原始）
            JTextPane sessPane = buildHexDiffPane(diff, false);  // 右侧（会话）
            origPane.setFont(new Font("Monospaced", Font.PLAIN, 13));
            sessPane.setFont(new Font("Monospaced", Font.PLAIN, 13));
            return new SynchronizedScrollPanel(origPane, sessPane);
        } else {
            String origStr = bytesToString(originalData);
            String sessStr = bytesToString(sessionData);
            List<DiffEngine.DiffLine> diff = DiffEngine.computeLineDiff(origStr, sessStr);
            JTextPane origPane = buildStringDiffPane(diff, true);   // 左侧（原始）
            JTextPane sessPane = buildStringDiffPane(diff, false);  // 右侧（会话）
            origPane.setFont(new Font("Monospaced", Font.PLAIN, 13));
            sessPane.setFont(new Font("Monospaced", Font.PLAIN, 13));
            return new SynchronizedScrollPanel(origPane, sessPane);
        }
    }

    /**
     * 构建单侧内容面板（四面板模式使用，不做diff高亮，直接显示原始内容）
     */
    private JTextPane buildSingleContentPane(byte[] data, String label, boolean isOriginalSide) {
        JTextPane pane = new JTextPane();
        pane.setEditable(false);
        StyledDocument doc = pane.getStyledDocument();

        Style baseStyle = pane.getStyle(StyleContext.DEFAULT_STYLE);
        StyleConstants.setFontFamily(baseStyle, "Monospaced");
        StyleConstants.setFontSize(baseStyle, 13);

        try {
            if (isHexMode) {
                List<String> hexLines = DiffEngine.generateHexDump(data != null ? data : new byte[0]);
                for (String line : hexLines) {
                    doc.insertString(doc.getLength(), line + "\n", baseStyle);
                }
            } else {
                doc.insertString(doc.getLength(), bytesToString(data), baseStyle);
            }
        } catch (BadLocationException e) {
            // 忽略
        }

        return pane;
    }

    // ==================== Diff渲染 ====================

    /**
     * 构建字符串级diff面板（单侧）
     * isOriginalSide=true: 左侧（显示REMOVED行红色背景，空行占位ADDED行）
     * isOriginalSide=false: 右侧（显示ADDED行绿色背景，空行占位REMOVED行）
     */
    private JTextPane buildStringDiffPane(List<DiffEngine.DiffLine> diffLines, boolean isOriginalSide) {
        JTextPane pane = new JTextPane();
        pane.setEditable(false);
        pane.setBackground(Color.WHITE);
        StyledDocument doc = pane.getStyledDocument();

        // 定义样式
        Style defaultStyle = pane.getStyle(StyleContext.DEFAULT_STYLE);
        StyleConstants.setFontFamily(defaultStyle, "Monospaced");
        StyleConstants.setFontSize(defaultStyle, 13);

        Style unchangedStyle = doc.addStyle("unchanged", defaultStyle);
        StyleConstants.setBackground(unchangedStyle, Color.WHITE);

        Style removedStyle = doc.addStyle("removed", defaultStyle);
        StyleConstants.setBackground(removedStyle, COLOR_REMOVED);

        Style addedStyle = doc.addStyle("added", defaultStyle);
        StyleConstants.setBackground(addedStyle, COLOR_ADDED);

        Style changedStyle = doc.addStyle("changed", defaultStyle);
        StyleConstants.setBackground(changedStyle, COLOR_CHANGED);

        try {
            for (DiffEngine.DiffLine line : diffLines) {
                String lineText = line.getLineText() + "\n";
                switch (line.getDiffType()) {
                    case UNCHANGED:
                        doc.insertString(doc.getLength(), lineText, unchangedStyle);
                        break;
                    case REMOVED:
                        if (isOriginalSide) {
                            doc.insertString(doc.getLength(), lineText, removedStyle);
                        } else {
                            doc.insertString(doc.getLength(), "\n", unchangedStyle);  // 对齐空行
                        }
                        break;
                    case ADDED:
                        if (isOriginalSide) {
                            doc.insertString(doc.getLength(), "\n", unchangedStyle);  // 对齐空行
                        } else {
                            doc.insertString(doc.getLength(), lineText, addedStyle);
                        }
                        break;
                    case CHANGED:
                        if (isOriginalSide) {
                            doc.insertString(doc.getLength(), lineText, changedStyle);
                        } else {
                            doc.insertString(doc.getLength(), lineText, addedStyle);
                        }
                        break;
                }
            }
        } catch (BadLocationException e) {
            // 忽略
        }

        return pane;
    }

    /**
     * 构建hex级diff面板（单侧）
     */
    private JTextPane buildHexDiffPane(List<DiffEngine.DiffSegment> diffSegments, boolean isOriginalSide) {
        JTextPane pane = new JTextPane();
        pane.setEditable(false);
        pane.setBackground(Color.WHITE);
        StyledDocument doc = pane.getStyledDocument();

        Style defaultStyle = pane.getStyle(StyleContext.DEFAULT_STYLE);
        StyleConstants.setFontFamily(defaultStyle, "Monospaced");
        StyleConstants.setFontSize(defaultStyle, 13);

        Style unchangedStyle = doc.addStyle("unchanged", defaultStyle);
        StyleConstants.setBackground(unchangedStyle, Color.WHITE);

        Style removedStyle = doc.addStyle("removed", defaultStyle);
        StyleConstants.setBackground(removedStyle, COLOR_REMOVED);

        Style addedStyle = doc.addStyle("added", defaultStyle);
        StyleConstants.setBackground(addedStyle, COLOR_ADDED);

        try {
            for (DiffEngine.DiffSegment seg : diffSegments) {
                String lineText = String.format("%08X  %-47s  %s\n",
                    seg.getOffset(), seg.getHexData(), seg.getAsciiData());

                switch (seg.getDiffType()) {
                    case UNCHANGED:
                        doc.insertString(doc.getLength(), lineText, unchangedStyle);
                        break;
                    case REMOVED:
                        if (isOriginalSide) {
                            doc.insertString(doc.getLength(), lineText, removedStyle);
                        } else {
                            doc.insertString(doc.getLength(), "\n", unchangedStyle);
                        }
                        break;
                    case ADDED:
                        if (isOriginalSide) {
                            doc.insertString(doc.getLength(), "\n", unchangedStyle);
                        } else {
                            doc.insertString(doc.getLength(), lineText, addedStyle);
                        }
                        break;
                }
            }
        } catch (BadLocationException e) {
            // 忽略
        }

        return pane;
    }

    // ==================== 信息面板 ====================

    private JPanel createInfoPanel() {
        JPanel infoPanel = new JPanel();
        infoPanel.setLayout(new BoxLayout(infoPanel, BoxLayout.Y_AXIS));
        infoPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        // 第一行：会话信息
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        row1.add(new JLabel("原始请求 [ID=" + originalRecord.getId() + "]"));
        row1.add(new JLabel("  |  "));
        row1.add(new JLabel("用户会话 [" + (sessionRecord.getUserSessionName() != null ? sessionRecord.getUserSessionName() : "未知") + "]"));
        row1.add(new JLabel("  |  "));
        JLabel reqSimLabel = new JLabel(String.format("请求相似度: %.2f%%", requestSimilarity * 100));
        reqSimLabel.setFont(reqSimLabel.getFont().deriveFont(Font.BOLD));
        row1.add(reqSimLabel);
        row1.add(new JLabel("  |  "));
        JLabel resSimLabel = new JLabel(String.format("响应相似度: %.2f%%", responseSimilarity * 100));
        resSimLabel.setFont(resSimLabel.getFont().deriveFont(Font.BOLD));
        row1.add(resSimLabel);

        if (sessionRecord.getJudgment() != null) {
            row1.add(new JLabel("  |  "));
            JLabel judgmentLabel = new JLabel("判决: " + sessionRecord.getJudgment());
            judgmentLabel.setForeground(getJudgmentColor(sessionRecord.getJudgment()));
            judgmentLabel.setFont(judgmentLabel.getFont().deriveFont(Font.BOLD, 14f));
            row1.add(judgmentLabel);
        }

        // 第二行：模式按钮
        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        stringModeBtn = new JToggleButton("字符串模式");
        stringModeBtn.setSelected(true);
        hexModeBtn = new JToggleButton("Hex模式");
        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(stringModeBtn);
        modeGroup.add(hexModeBtn);

        stringModeBtn.addActionListener(e -> {
            if (stringModeBtn.isSelected()) {
                isHexMode = false;
                buildAndShowComparison();
            }
        });
        hexModeBtn.addActionListener(e -> {
            if (hexModeBtn.isSelected()) {
                isHexMode = true;
                buildAndShowComparison();
            }
        });

        fourPaneToggleBtn = new JToggleButton("四面板模式");
        fourPaneToggleBtn.addActionListener(e -> {
            isFourPaneMode = fourPaneToggleBtn.isSelected();
            buildAndShowComparison();
        });

        maximizeBtn = new JButton("最大化");
        maximizeBtn.addActionListener(e -> {
            Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
            if (maximizeBtn.getText().equals("最大化")) {
                // 最大化：占满屏幕
                setLocation(0, 0);
                setSize(screenSize.width, screenSize.height);
                maximizeBtn.setText("还原");
            } else {
                // 还原：90%屏幕大小
                setSize((int)(screenSize.width * 0.9), (int)(screenSize.height * 0.9));
                setLocationRelativeTo(null);
                maximizeBtn.setText("最大化");
            }
        });

        row2.add(stringModeBtn);
        row2.add(hexModeBtn);
        row2.add(fourPaneToggleBtn);
        row2.add(Box.createHorizontalStrut(20));
        row2.add(maximizeBtn);

        infoPanel.add(row1);
        infoPanel.add(row2);

        return infoPanel;
    }

    // ==================== 底部面板 ====================

    private JPanel createBottomPanel() {
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton closeBtn = new JButton("关闭");
        closeBtn.addActionListener(e -> dispose());
        bottomPanel.add(closeBtn);
        return bottomPanel;
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
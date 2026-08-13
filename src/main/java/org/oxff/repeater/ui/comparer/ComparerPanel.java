package org.oxff.repeater.ui.comparer;

import org.oxff.repeater.i18n.I18nManager;
import org.oxff.repeater.privilege.SimilarityEngine;
import org.oxff.repeater.privilege.LevenshteinCalculator;
import org.oxff.repeater.privilege.JaccardSimilarityCalculator;
import org.oxff.repeater.privilege.JsonSimilarityCalculator;
import org.oxff.repeater.privilege.XmlSimilarityCalculator;
import org.oxff.repeater.ui.SwitchButton;
import org.oxff.repeater.ui.history.DiffPane;
import org.oxff.repeater.ui.history.DiffEngine;
import org.oxff.repeater.ui.history.DiffLine;
import org.oxff.repeater.ui.history.DiffSegment;
import org.oxff.repeater.ui.history.DiffNavigator;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 报文比较面板 - 类似 Burp Comparer 的独立比较工具
 * 三层可拖拽分割布局：上下分割（表格区 vs 结果区），
 * 上半部分左右分割（两个选择表格），下半部分左右分割（两个 DiffPane）
 */
public class ComparerPanel extends JPanel {

    // ==================== 数据模型 ====================

    /** 报文项 */
    static class ComparerItem {
        int index;
        byte[] data;
        String preview;
        int length;

        ComparerItem(int index, byte[] data) {
            this.index = index;
            this.data = data;
            this.length = data != null ? data.length : 0;
            this.preview = buildPreview(data);
        }

        private static String buildPreview(byte[] data) {
            if (data == null || data.length == 0) return "";
            String text = new String(data, 0, Math.min(data.length, 120), StandardCharsets.UTF_8);
            text = text.replaceAll("[\\r\\n]+", " ").trim();
            if (text.length() > 80) {
                text = text.substring(0, 80) + "...";
            }
            return text;
        }
    }

    // ==================== 比较模式 ====================

    private static final int MODE_WORDS = 0;
    private static final int MODE_BYTES = 1;

    // ==================== 算法枚举 ====================

    private static final int ALGO_AUTO = 0;
    private static final int ALGO_LEVENSHTEIN = 1;
    private static final int ALGO_JACCARD = 2;
    private static final int ALGO_JSON = 3;
    private static final int ALGO_XML = 4;

    // ==================== UI 组件 ====================

    // 顶部工具栏
    private JButton deleteBtn;
    private JButton clearBtn;
    private JLabel wordsLabel;
    private SwitchButton modeSwitch;
    private JLabel bytesLabel;
    private JButton compareBtn;
    private JButton fullscreenBtn;
    private JComboBox<String> algorithmCombo;

    // 上半部分：双表格
    private JTable table1;
    private JTable table2;
    private DefaultTableModel tableModel1;
    private DefaultTableModel tableModel2;
    private JLabel selectLabel1;
    private JLabel selectLabel2;

    // 下半部分：比较结果
    private JLabel resultTitleLabel;
    private JLabel lengthLabel1;
    private JLabel lengthLabel2;
    private JToggleButton textModeBtn1;
    private JToggleButton hexModeBtn1;
    private JToggleButton textModeBtn2;
    private JToggleButton hexModeBtn2;
    private DiffPane diffPane1;
    private DiffPane diffPane2;
    private JCheckBox syncViewsCheckbox;
    private JSplitPane resultSplitPane;
    private JPanel resultPanel;
    private DiffNavigator diffNavigator;

    // 分割面板
    private JSplitPane topSplitPane;      // 上半部分左右分割
    private JSplitPane mainSplitPane;     // 上下分割

    // ==================== 数据 ====================

    private final List<ComparerItem> items = new ArrayList<>();
    private int nextIndex = 1;
    private int compareMode = MODE_WORDS;
    private int selectedAlgorithm = ALGO_AUTO;
    private boolean isHexMode1 = false;
    private boolean isHexMode2 = false;

    // 全屏相关
    private JDialog fullscreenDialog;
    private JPanel contentPanel; // 主内容面板（用于全屏切换）

    public ComparerPanel() {
        setLayout(new BorderLayout());
        initUI();
        I18nManager.getInstance().addLocaleChangeListener(this::refreshTexts);
    }

    private void initUI() {
        // 顶部工具栏
        add(createToolBar(), BorderLayout.NORTH);

        // 主内容面板
        contentPanel = new JPanel(new BorderLayout());

        // 上半部分：双表格
        topSplitPane = createTopSplitPane();

        // 下半部分：比较结果
        resultPanel = createResultPanel();

        // 上下分割
        mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topSplitPane, resultPanel);
        mainSplitPane.setResizeWeight(0.4);
        mainSplitPane.setOneTouchExpandable(true);
        mainSplitPane.setDividerLocation(0.4);

        contentPanel.add(mainSplitPane, BorderLayout.CENTER);
        add(contentPanel, BorderLayout.CENTER);
    }

    // ==================== 顶部工具栏 ====================

    private JPanel createToolBar() {
        JPanel toolBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        toolBar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, UIManager.getColor("Separator.foreground")),
            BorderFactory.createEmptyBorder(4, 8, 4, 8)
        ));

        deleteBtn = new JButton(I18nManager.tr("comparer.delete"));
        deleteBtn.addActionListener(e -> deleteSelectedItem());
        toolBar.add(deleteBtn);

        clearBtn = new JButton(I18nManager.tr("comparer.clear"));
        clearBtn.addActionListener(e -> clearAllItems());
        toolBar.add(clearBtn);

        toolBar.add(new JSeparator(SwingConstants.VERTICAL));

        wordsLabel = new JLabel(I18nManager.tr("comparer.words"));
        toolBar.add(wordsLabel);

        modeSwitch = new SwitchButton();
        modeSwitch.setSelected(false); // 默认单词模式
        modeSwitch.addActionListener(e -> {
            compareMode = modeSwitch.isSelected() ? MODE_BYTES : MODE_WORDS;
            refreshComparison();
        });
        toolBar.add(modeSwitch);

        bytesLabel = new JLabel(I18nManager.tr("comparer.bytes"));
        toolBar.add(bytesLabel);

        compareBtn = new JButton(I18nManager.tr("comparer.compare"));
        compareBtn.addActionListener(e -> performComparison());
        toolBar.add(compareBtn);

        fullscreenBtn = new JButton(I18nManager.tr("comparer.fullscreen"));
        fullscreenBtn.addActionListener(e -> toggleFullscreen());
        toolBar.add(fullscreenBtn);

        toolBar.add(Box.createHorizontalGlue());

        // 相似度算法下拉框
        algorithmCombo = new JComboBox<>(buildAlgorithmItems());
        algorithmCombo.setSelectedIndex(ALGO_AUTO);
        algorithmCombo.addActionListener(e -> {
            selectedAlgorithm = algorithmCombo.getSelectedIndex();
            refreshComparison();
        });
        toolBar.add(algorithmCombo);

        return toolBar;
    }

    private String[] buildAlgorithmItems() {
        return new String[]{
            I18nManager.tr("comparer.algorithm.auto"),
            I18nManager.tr("comparer.algorithm.levenshtein"),
            I18nManager.tr("comparer.algorithm.jaccard"),
            I18nManager.tr("comparer.algorithm.json"),
            I18nManager.tr("comparer.algorithm.xml")
        };
    }

    // ==================== 上半部分：双表格 ====================

    private JSplitPane createTopSplitPane() {
        // 表格1
        selectLabel1 = new JLabel(I18nManager.tr("comparer.selectItem1"));
        tableModel1 = createTableModel();
        table1 = new JTable(tableModel1);
        table1.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table1.getColumnModel().getColumn(0).setPreferredWidth(40);
        table1.getColumnModel().getColumn(0).setMaxWidth(60);
        table1.getColumnModel().getColumn(1).setPreferredWidth(60);
        table1.getColumnModel().getColumn(1).setMaxWidth(100);
        table1.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) onSelectionChanged();
        });

        JPanel panel1 = new JPanel(new BorderLayout());
        panel1.add(selectLabel1, BorderLayout.NORTH);
        panel1.add(new JScrollPane(table1), BorderLayout.CENTER);
        panel1.setMinimumSize(new Dimension(200, 80));

        // 表格2
        selectLabel2 = new JLabel(I18nManager.tr("comparer.selectItem2"));
        tableModel2 = createTableModel();
        table2 = new JTable(tableModel2);
        table2.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table2.getColumnModel().getColumn(0).setPreferredWidth(40);
        table2.getColumnModel().getColumn(0).setMaxWidth(60);
        table2.getColumnModel().getColumn(1).setPreferredWidth(60);
        table2.getColumnModel().getColumn(1).setMaxWidth(100);
        table2.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) onSelectionChanged();
        });

        JPanel panel2 = new JPanel(new BorderLayout());
        panel2.add(selectLabel2, BorderLayout.NORTH);
        panel2.add(new JScrollPane(table2), BorderLayout.CENTER);
        panel2.setMinimumSize(new Dimension(200, 80));

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, panel1, panel2);
        split.setResizeWeight(0.5);
        split.setOneTouchExpandable(true);
        split.setDividerLocation(0.5);

        return split;
    }

    private DefaultTableModel createTableModel() {
        String[] columns = {
            I18nManager.tr("comparer.col.index"),
            I18nManager.tr("comparer.col.length"),
            I18nManager.tr("comparer.col.data")
        };
        return new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
    }

    // ==================== 下半部分：比较结果 ====================

    private JPanel createResultPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        // 结果标题栏
        resultTitleLabel = new JLabel(" ");
        resultTitleLabel.setFont(resultTitleLabel.getFont().deriveFont(Font.BOLD, 13f));
        resultTitleLabel.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
        panel.add(resultTitleLabel, BorderLayout.NORTH);

        // 左侧 DiffPane
        JPanel leftPanel = new JPanel(new BorderLayout());
        JPanel leftHeader = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        lengthLabel1 = new JLabel(" ");
        leftHeader.add(lengthLabel1);
        leftHeader.add(Box.createHorizontalGlue());
        textModeBtn1 = new JToggleButton(I18nManager.tr("comparer.result.text"));
        textModeBtn1.setSelected(true);
        hexModeBtn1 = new JToggleButton(I18nManager.tr("comparer.result.hex"));
        ButtonGroup group1 = new ButtonGroup();
        group1.add(textModeBtn1);
        group1.add(hexModeBtn1);
        textModeBtn1.addActionListener(e -> { isHexMode1 = false; refreshComparison(); });
        hexModeBtn1.addActionListener(e -> { isHexMode1 = true; refreshComparison(); });
        leftHeader.add(textModeBtn1);
        leftHeader.add(hexModeBtn1);
        leftPanel.add(leftHeader, BorderLayout.NORTH);

        diffPane1 = new DiffPane();
        leftPanel.add(diffPane1, BorderLayout.CENTER);
        leftPanel.setMinimumSize(new Dimension(200, 100));

        // 右侧 DiffPane
        JPanel rightPanel = new JPanel(new BorderLayout());
        JPanel rightHeader = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        lengthLabel2 = new JLabel(" ");
        rightHeader.add(lengthLabel2);
        rightHeader.add(Box.createHorizontalGlue());
        textModeBtn2 = new JToggleButton(I18nManager.tr("comparer.result.text"));
        textModeBtn2.setSelected(true);
        hexModeBtn2 = new JToggleButton(I18nManager.tr("comparer.result.hex"));
        ButtonGroup group2 = new ButtonGroup();
        group2.add(textModeBtn2);
        group2.add(hexModeBtn2);
        textModeBtn2.addActionListener(e -> { isHexMode2 = false; refreshComparison(); });
        hexModeBtn2.addActionListener(e -> { isHexMode2 = true; refreshComparison(); });
        rightHeader.add(textModeBtn2);
        rightHeader.add(hexModeBtn2);
        rightPanel.add(rightHeader, BorderLayout.NORTH);

        diffPane2 = new DiffPane();
        rightPanel.add(diffPane2, BorderLayout.CENTER);
        rightPanel.setMinimumSize(new Dimension(200, 100));

        // 左右分割
        resultSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel);
        resultSplitPane.setResizeWeight(0.5);
        resultSplitPane.setOneTouchExpandable(true);
        resultSplitPane.setDividerLocation(0.5);
        panel.add(resultSplitPane, BorderLayout.CENTER);

        // 底部：Key 图例 + Sync views
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        bottomPanel.add(new JLabel("Key:"));
        bottomPanel.add(createKeyLabel(I18nManager.tr("comparer.result.key.modified"), new Color(255, 250, 230)));
        bottomPanel.add(createKeyLabel(I18nManager.tr("comparer.result.key.deleted"), new Color(255, 220, 220)));
        bottomPanel.add(createKeyLabel(I18nManager.tr("comparer.result.key.added"), new Color(220, 255, 220)));
        bottomPanel.add(Box.createHorizontalGlue());
        syncViewsCheckbox = new JCheckBox(I18nManager.tr("comparer.result.syncViews"));
        syncViewsCheckbox.setSelected(true);
        bottomPanel.add(syncViewsCheckbox);
        panel.add(bottomPanel, BorderLayout.SOUTH);

        // 初始化导航器
        diffNavigator = new DiffNavigator(diffPane1, diffPane2);

        return panel;
    }

    private JLabel createKeyLabel(String text, Color bgColor) {
        JLabel label = new JLabel(" " + text + " ");
        label.setOpaque(true);
        label.setBackground(bgColor);
        label.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        return label;
    }

    // ==================== 公共方法 ====================

    /**
     * 添加报文项到比较列表
     *
     * @param data   报文字节数据
     * @param source 来源描述
     */
    public void addItem(byte[] data, String source) {
        if (data == null || data.length == 0) return;

        ComparerItem item = new ComparerItem(nextIndex++, data);
        items.add(item);

        // 同步更新两个表格模型
        addRowToModel(tableModel1, item);
        addRowToModel(tableModel2, item);
    }

    private void addRowToModel(DefaultTableModel model, ComparerItem item) {
        model.addRow(new Object[]{item.index, item.length, item.preview});
    }

    /**
     * 删除选中的报文项
     */
    private void deleteSelectedItem() {
        int row1 = table1.getSelectedRow();
        int row2 = table2.getSelectedRow();

        if (row1 < 0 && row2 < 0) return;

        // 优先删除 table1 中选中的
        int deleteRow = (row1 >= 0) ? row1 : row2;
        if (deleteRow >= 0 && deleteRow < items.size()) {
            items.remove(deleteRow);
            tableModel1.removeRow(deleteRow);
            tableModel2.removeRow(deleteRow);
            clearComparisonResult();
        }
    }

    /**
     * 清空所有报文项
     */
    private void clearAllItems() {
        items.clear();
        tableModel1.setRowCount(0);
        tableModel2.setRowCount(0);
        clearComparisonResult();
    }

    // ==================== 比较逻辑 ====================

    private void onSelectionChanged() {
        // 当两个表格都选中项时自动触发比较
        int row1 = table1.getSelectedRow();
        int row2 = table2.getSelectedRow();
        if (row1 >= 0 && row2 >= 0 && row1 < items.size() && row2 < items.size()) {
            performComparison();
        }
    }

    private void performComparison() {
        int row1 = table1.getSelectedRow();
        int row2 = table2.getSelectedRow();

        if (row1 < 0 || row2 < 0 || row1 >= items.size() || row2 >= items.size()) {
            clearComparisonResult();
            return;
        }

        ComparerItem item1 = items.get(row1);
        ComparerItem item2 = items.get(row2);

        // 更新标题
        int diffCount = 0;
        if (compareMode == MODE_WORDS) {
            String text1 = bytesToString(item1.data);
            String text2 = bytesToString(item2.data);
            List<DiffLine> diffLines = DiffEngine.computeLineDiff(text1, text2);
            diffCount = countDifferences(diffLines);

            diffPane1.renderDiffLines(diffLines, true);
            diffPane2.renderDiffLines(diffLines, false);

            resultTitleLabel.setText(I18nManager.tr("comparer.result.title",
                item1.index, item2.index, diffCount));
        } else {
            List<DiffSegment> diffSegments = DiffEngine.computeByteDiff(item1.data, item2.data);
            diffCount = countByteDifferences(diffSegments);

            diffPane1.renderHexDiffSegments(diffSegments, true);
            diffPane2.renderHexDiffSegments(diffSegments, false);

            resultTitleLabel.setText(I18nManager.tr("comparer.result.title.bytes",
                item1.index, item2.index, diffCount));
        }

        // 更新长度标签
        lengthLabel1.setText(I18nManager.tr("comparer.result.length", String.format("%,d", item1.length)));
        lengthLabel2.setText(I18nManager.tr("comparer.result.length", String.format("%,d", item2.length)));

        // 计算相似度
        double similarity = computeSimilarity(item1.data, item2.data);
        String simText = String.format("%.2f%%", similarity * 100);
        resultTitleLabel.setText(resultTitleLabel.getText() + "  |  " +
            I18nManager.tr("comparer.similarity", simText));

        // 重建导航器
        diffNavigator = new DiffNavigator(diffPane1, diffPane2);

        // 同步滚动
        setupSyncScroll();
    }

    private void refreshComparison() {
        int row1 = table1.getSelectedRow();
        int row2 = table2.getSelectedRow();
        if (row1 >= 0 && row2 >= 0 && row1 < items.size() && row2 < items.size()) {
            performComparison();
        }
    }

    private void clearComparisonResult() {
        resultTitleLabel.setText(" ");
        lengthLabel1.setText(" ");
        lengthLabel2.setText(" ");
        diffPane1.renderPlainText(new byte[0], false);
        diffPane2.renderPlainText(new byte[0], false);
    }

    private double computeSimilarity(byte[] data1, byte[] data2) {
        String s1 = bytesToString(data1);
        String s2 = bytesToString(data2);

        return switch (selectedAlgorithm) {
            case ALGO_LEVENSHTEIN -> LevenshteinCalculator.similarity(s1, s2);
            case ALGO_JACCARD -> JaccardSimilarityCalculator.similarity(s1, s2);
            case ALGO_JSON -> JsonSimilarityCalculator.similarity(s1, s2);
            case ALGO_XML -> XmlSimilarityCalculator.similarity(s1, s2);
            default -> SimilarityEngine.similarity(s1, s2);
        };
    }

    private int countDifferences(List<DiffLine> diffLines) {
        int count = 0;
        for (DiffLine line : diffLines) {
            if (line.getDiffType() != org.oxff.repeater.ui.history.DiffType.UNCHANGED) {
                count++;
            }
        }
        return count;
    }

    private int countByteDifferences(List<DiffSegment> segments) {
        int count = 0;
        for (DiffSegment seg : segments) {
            if (seg.getDiffType() != org.oxff.repeater.ui.history.DiffType.UNCHANGED) {
                count++;
            }
        }
        return count;
    }

    private void setupSyncScroll() {
        JScrollPane sp1 = diffPane1.getScrollPane();
        JScrollPane sp2 = diffPane2.getScrollPane();

        // 移除旧监听器
        for (var l : sp1.getVerticalScrollBar().getAdjustmentListeners()) {
            sp1.getVerticalScrollBar().removeAdjustmentListener(l);
        }
        for (var l : sp2.getVerticalScrollBar().getAdjustmentListeners()) {
            sp2.getVerticalScrollBar().removeAdjustmentListener(l);
        }

        final boolean[] syncing = {false};

        sp1.getVerticalScrollBar().addAdjustmentListener(e -> {
            if (!syncing[0] && syncViewsCheckbox.isSelected()) {
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
            if (!syncing[0] && syncViewsCheckbox.isSelected()) {
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

    // ==================== 全屏功能 ====================

    private void toggleFullscreen() {
        if (fullscreenDialog != null && fullscreenDialog.isVisible()) {
            // 退出全屏
            exitFullscreen();
        } else {
            // 进入全屏
            enterFullscreen();
        }
    }

    private void enterFullscreen() {
        Window parentWindow = SwingUtilities.getWindowAncestor(this);
        Frame parentFrame = (parentWindow instanceof Frame) ? (Frame) parentWindow : null;

        fullscreenDialog = new JDialog(parentFrame, I18nManager.tr("comparer.title"), false);
        fullscreenDialog.setUndecorated(false);

        // 将 contentPanel 从当前面板移除并放入对话框
        remove(contentPanel);
        fullscreenDialog.setContentPane(contentPanel);

        // 设置全屏大小
        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
        fullscreenDialog.setSize(screenSize);
        fullscreenDialog.setLocation(0, 0);

        // 关闭时恢复到原面板
        fullscreenDialog.addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosing(java.awt.event.WindowEvent e) {
                exitFullscreen();
            }
        });

        fullscreenDialog.setVisible(true);
    }

    private void exitFullscreen() {
        if (fullscreenDialog != null) {
            // 将 contentPanel 从对话框移除并放回原面板
            fullscreenDialog.getContentPane().remove(contentPanel);
            fullscreenDialog.dispose();
            fullscreenDialog = null;

            add(contentPanel, BorderLayout.CENTER);
            revalidate();
            repaint();
        }
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

    // ==================== 国际化 ====================

    private void refreshTexts() {
        deleteBtn.setText(I18nManager.tr("comparer.delete"));
        clearBtn.setText(I18nManager.tr("comparer.clear"));
        wordsLabel.setText(I18nManager.tr("comparer.words"));
        bytesLabel.setText(I18nManager.tr("comparer.bytes"));
        compareBtn.setText(I18nManager.tr("comparer.compare"));
        fullscreenBtn.setText(I18nManager.tr("comparer.fullscreen"));
        selectLabel1.setText(I18nManager.tr("comparer.selectItem1"));
        selectLabel2.setText(I18nManager.tr("comparer.selectItem2"));
        textModeBtn1.setText(I18nManager.tr("comparer.result.text"));
        hexModeBtn1.setText(I18nManager.tr("comparer.result.hex"));
        textModeBtn2.setText(I18nManager.tr("comparer.result.text"));
        hexModeBtn2.setText(I18nManager.tr("comparer.result.hex"));
        syncViewsCheckbox.setText(I18nManager.tr("comparer.result.syncViews"));

        // 刷新算法下拉框
        int selectedIdx = algorithmCombo.getSelectedIndex();
        algorithmCombo.setModel(new DefaultComboBoxModel<>(buildAlgorithmItems()));
        if (selectedIdx >= 0 && selectedIdx < algorithmCombo.getItemCount()) {
            algorithmCombo.setSelectedIndex(selectedIdx);
        }

        // 刷新表格列头
        String[] columns = {
            I18nManager.tr("comparer.col.index"),
            I18nManager.tr("comparer.col.length"),
            I18nManager.tr("comparer.col.data")
        };
        tableModel1.setColumnIdentifiers(columns);
        tableModel2.setColumnIdentifiers(columns);

        revalidate();
        repaint();
    }
}

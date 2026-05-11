package oxff.top.ui;

import oxff.top.logging.LogEntry;
import oxff.top.logging.LogLevel;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 日志命令行模拟面板 - 模拟终端窗口显示彩色日志，支持搜索过滤
 */
public class LogPanel extends JPanel {

    // 颜色常量
    private static final Color BG_COLOR = new Color(30, 30, 30);
    private static final Color HIGHLIGHT_COLOR = new Color(255, 255, 0);       // 黄色 - 搜索匹配
    private static final Color CURRENT_HIGHLIGHT = new Color(255, 165, 0);     // 橙色 - 当前选中匹配
    private static final Font MONO_FONT = new Font("Monospaced", Font.PLAIN, 12);

    // 最大消息长度
    private static final int MAX_MESSAGE_LENGTH = 4096;

    // 核心UI组件
    private final JTextPane logTextPane;
    private final StyledDocument styledDoc;

    // 工具栏组件 - 第一行
    private final JComboBox<LogLevel> levelFilterCombo;
    private final JToggleButton keywordModeButton;
    private final JToggleButton regexModeButton;
    private final JTextField searchField;
    private final JButton prevMatchButton;
    private final JButton nextMatchButton;
    private final JLabel matchCountLabel;
    private final JButton clearSearchButton;
    private final JCheckBox caseSensitiveCheckbox;

    // 工具栏组件 - 第二行
    private final JButton clearButton;
    private final JCheckBox autoScrollCheckBox;
    private final JComboBox<String> maxEntriesCombo;
    private final JButton exportButton;
    private final JToggleButton pauseButton;

    // 日志缓冲
    private final LinkedList<LogEntry> entryBuffer = new LinkedList<>();
    private int maxEntries = 128;

    // 搜索状态
    private boolean isRegexMode = false;
    private final List<int[]> matchPositions = new ArrayList<>(); // [start, end] 对
    private int currentMatchIndex = -1;

    // 防抖定时器
    private Timer searchDebounceTimer;

    // 级别过滤
    private LogLevel levelFilter = null; // null 表示 ALL

    // 暂停状态
    private volatile boolean paused = false;

    // 行偏移映射：entryBuffer索引 -> styledDoc中的起始偏移量
    private final List<Integer> lineOffsets = new ArrayList<>();

    public LogPanel() {
        super(new BorderLayout());

        // ===== 创建日志显示区域 =====
        logTextPane = new JTextPane();
        logTextPane.setEditable(false);
        logTextPane.setBackground(BG_COLOR);
        logTextPane.setFont(MONO_FONT);
        logTextPane.setCaretColor(BG_COLOR); // 隐藏光标

        styledDoc = logTextPane.getStyledDocument();

        // 设置默认样式
        SimpleAttributeSet defaultAttrs = new SimpleAttributeSet();
        StyleConstants.setFontFamily(defaultAttrs, "Monospaced");
        StyleConstants.setFontSize(defaultAttrs, 12);
        styledDoc.setCharacterAttributes(0, 0, defaultAttrs, true);

        JScrollPane scrollPane = new JScrollPane(logTextPane);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);

        // ===== 创建工具栏 =====
        JPanel toolbarPanel = new JPanel();
        toolbarPanel.setLayout(new BoxLayout(toolbarPanel, BoxLayout.Y_AXIS));

        // 第一行 - 主工具栏
        JPanel mainToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));

        levelFilterCombo = new JComboBox<>();
        levelFilterCombo.addItem(null); // ALL - 使用自定义渲染
        levelFilterCombo.setModel(new DefaultComboBoxModel<LogLevel>() {{
            addElement(null);
            addElement(LogLevel.DEBUG);
            addElement(LogLevel.INFO);
            addElement(LogLevel.SUCCESS);
            addElement(LogLevel.WARN);
            addElement(LogLevel.ERROR);
        }});
        levelFilterCombo.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                          boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value == null) {
                    setText("ALL");
                } else if (value instanceof LogLevel) {
                    setText(((LogLevel) value).name());
                }
                return this;
            }
        });
        levelFilterCombo.addActionListener(e -> onLevelFilterChanged());

        keywordModeButton = new JToggleButton("关键字");
        keywordModeButton.setSelected(true);
        regexModeButton = new JToggleButton("正则");
        ButtonGroup searchModeGroup = new ButtonGroup();
        searchModeGroup.add(keywordModeButton);
        searchModeGroup.add(regexModeButton);
        keywordModeButton.addActionListener(e -> { isRegexMode = false; performSearch(); });
        regexModeButton.addActionListener(e -> { isRegexMode = true; performSearch(); });

        searchField = new JTextField(15);
        searchField.setToolTipText("输入关键字或正则表达式搜索日志");
        caseSensitiveCheckbox = new JCheckBox("Aa", false);
        caseSensitiveCheckbox.setToolTipText("区分大小写");
        caseSensitiveCheckbox.addActionListener(e -> performSearch());

        prevMatchButton = new JButton("▲");
        prevMatchButton.setToolTipText("上一个匹配");
        prevMatchButton.addActionListener(e -> navigateMatch(-1));

        nextMatchButton = new JButton("▼");
        nextMatchButton.setToolTipText("下一个匹配");
        nextMatchButton.addActionListener(e -> navigateMatch(1));

        matchCountLabel = new JLabel("0/0");
        matchCountLabel.setPreferredSize(new Dimension(60, 20));

        clearSearchButton = new JButton("✕");
        clearSearchButton.setToolTipText("清除搜索");
        clearSearchButton.addActionListener(e -> clearSearch());

        mainToolbar.add(new JLabel("级别:"));
        mainToolbar.add(levelFilterCombo);
        mainToolbar.add(keywordModeButton);
        mainToolbar.add(regexModeButton);
        mainToolbar.add(searchField);
        mainToolbar.add(caseSensitiveCheckbox);
        mainToolbar.add(prevMatchButton);
        mainToolbar.add(nextMatchButton);
        mainToolbar.add(matchCountLabel);
        mainToolbar.add(clearSearchButton);

        // 第二行 - 辅助工具栏
        JPanel auxToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));

        clearButton = new JButton("清除");
        clearButton.setToolTipText("清除所有日志");
        clearButton.addActionListener(e -> clearLog());

        autoScrollCheckBox = new JCheckBox("自动滚动", true);

        maxEntriesCombo = new JComboBox<>(new String[]{"128", "256", "512", "1024"});
        maxEntriesCombo.setToolTipText("最大显示条目数");
        maxEntriesCombo.addActionListener(e -> {
            maxEntries = Integer.parseInt((String) maxEntriesCombo.getSelectedItem());
            trimEntries();
        });

        exportButton = new JButton("导出");
        exportButton.setToolTipText("导出日志到文件");
        exportButton.addActionListener(e -> exportLog());

        pauseButton = new JToggleButton("暂停");
        pauseButton.setToolTipText("暂停/恢复日志接收");
        pauseButton.addActionListener(e -> paused = pauseButton.isSelected());

        auxToolbar.add(clearButton);
        auxToolbar.add(autoScrollCheckBox);
        auxToolbar.add(new JLabel("条目数:"));
        auxToolbar.add(maxEntriesCombo);
        auxToolbar.add(exportButton);
        auxToolbar.add(pauseButton);

        toolbarPanel.add(mainToolbar);
        toolbarPanel.add(auxToolbar);

        // ===== 组装面板 =====
        add(toolbarPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);

        // ===== 初始化搜索防抖 =====
        searchDebounceTimer = new Timer(300, e -> performSearch());
        searchDebounceTimer.setRepeats(false);

        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                searchDebounceTimer.restart();
            }

            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                searchDebounceTimer.restart();
            }

            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                searchDebounceTimer.restart();
            }
        });

        searchField.addActionListener(e -> {
            searchDebounceTimer.stop();
            performSearch();
        });
    }

    /**
     * 添加日志条目到UI
     */
    public void appendLogEntry(LogEntry entry) {
        if (paused) {
            return;
        }

        // 截断超长消息
        String text = entry.getFormattedMessage();
        if (text.length() > MAX_MESSAGE_LENGTH) {
            text = text.substring(0, MAX_MESSAGE_LENGTH) + " [truncated]";
        }

        // 级别过滤检查
        if (levelFilter != null && entry.getLevel().getLevel() < levelFilter.getLevel()) {
            // 仍然存入缓冲区，但不显示
            entryBuffer.addLast(entry);
            return;
        }

        // 添加到缓冲区
        entryBuffer.addLast(entry);

        // 记录偏移量
        int insertOffset = styledDoc.getLength();
        lineOffsets.add(insertOffset);

        // 插入带颜色的文本
        SimpleAttributeSet attrs = new SimpleAttributeSet();
        StyleConstants.setForeground(attrs, entry.getDisplayColor());
        StyleConstants.setFontFamily(attrs, "Monospaced");
        StyleConstants.setFontSize(attrs, 12);

        try {
            styledDoc.insertString(styledDoc.getLength(), text + "\n", attrs);
        } catch (BadLocationException e) {
            // 忽略
        }

        // 检查是否需要截断
        trimEntries();

        // 自动滚动
        if (autoScrollCheckBox.isSelected()) {
            logTextPane.setCaretPosition(styledDoc.getLength());
        }
    }

    /**
     * 截断超出最大条目数的旧日志
     */
    private void trimEntries() {
        while (entryBuffer.size() > maxEntries) {
            entryBuffer.removeFirst();
            if (!lineOffsets.isEmpty()) {
                int removeOffset = lineOffsets.remove(0);
                // 计算要删除的文本长度（到下一行偏移或文档末尾）
                int endOffset;
                if (!lineOffsets.isEmpty()) {
                    endOffset = lineOffsets.get(0);
                    // 更新剩余偏移量
                    int removedLength = endOffset - removeOffset;
                    for (int i = 0; i < lineOffsets.size(); i++) {
                        lineOffsets.set(i, lineOffsets.get(i) - removedLength);
                    }
                } else {
                    endOffset = styledDoc.getLength();
                }
                try {
                    if (removeOffset < endOffset && endOffset <= styledDoc.getLength()) {
                        styledDoc.remove(removeOffset, endOffset - removeOffset);
                    }
                } catch (BadLocationException e) {
                    // 截断失败，执行全量重建
                    rebuildDocument();
                    return;
                }
            }
        }
    }

    /**
     * 全量重建文档（当增量截断导致偏移错乱时使用）
     */
    private void rebuildDocument() {
        try {
            styledDoc.remove(0, styledDoc.getLength());
        } catch (BadLocationException e) {
            // ignore
        }
        lineOffsets.clear();

        for (int i = 0; i < entryBuffer.size(); i++) {
            LogEntry entry = entryBuffer.get(i);

            // 级别过滤
            if (levelFilter != null && entry.getLevel().getLevel() < levelFilter.getLevel()) {
                continue;
            }

            String text = entry.getFormattedMessage();
            if (text.length() > MAX_MESSAGE_LENGTH) {
                text = text.substring(0, MAX_MESSAGE_LENGTH) + " [truncated]";
            }

            lineOffsets.add(styledDoc.getLength());

            SimpleAttributeSet attrs = new SimpleAttributeSet();
            StyleConstants.setForeground(attrs, entry.getDisplayColor());
            StyleConstants.setFontFamily(attrs, "Monospaced");
            StyleConstants.setFontSize(attrs, 12);

            try {
                styledDoc.insertString(styledDoc.getLength(), text + "\n", attrs);
            } catch (BadLocationException e) {
                // ignore
            }
        }

        // 如果有活跃搜索，重新搜索
        String searchText = searchField.getText().trim();
        if (!searchText.isEmpty()) {
            performSearch();
        }
    }

    /**
     * 清除所有日志
     */
    public void clearLog() {
        entryBuffer.clear();
        lineOffsets.clear();
        matchPositions.clear();
        currentMatchIndex = -1;
        matchCountLabel.setText("0/0");

        try {
            styledDoc.remove(0, styledDoc.getLength());
        } catch (BadLocationException e) {
            // ignore
        }
    }

    /**
     * 级别过滤变更
     */
    private void onLevelFilterChanged() {
        LogLevel selected = (LogLevel) levelFilterCombo.getSelectedItem();
        levelFilter = selected;
        rebuildDocument();
    }

    // ========== 搜索功能 ==========

    /**
     * 执行搜索
     */
    private void performSearch() {
        String searchText = searchField.getText().trim();

        // 清除之前的高亮
        clearHighlights();

        matchPositions.clear();
        currentMatchIndex = -1;

        if (searchText.isEmpty()) {
            matchCountLabel.setText("0/0");
            searchField.setBackground(UIManager.getColor("TextField.background"));
            return;
        }

        String docText;
        try {
            docText = styledDoc.getText(0, styledDoc.getLength());
        } catch (BadLocationException e) {
            return;
        }

        boolean caseSensitive = caseSensitiveCheckbox.isSelected();

        if (isRegexMode) {
            // 正则模式
            try {
                int flags = caseSensitive ? 0 : Pattern.CASE_INSENSITIVE;
                Pattern pattern = Pattern.compile(searchText, flags);
                Matcher matcher = pattern.matcher(docText);

                while (matcher.find()) {
                    matchPositions.add(new int[]{matcher.start(), matcher.end()});
                }

                // 正则有效，清除错误提示
                searchField.setBackground(UIManager.getColor("TextField.background"));
            } catch (PatternSyntaxException e) {
                // 正则语法错误，显示红色提示
                searchField.setBackground(new Color(255, 200, 200));
                matchCountLabel.setText("0/0");
                return;
            }
        } else {
            // 关键字模式
            String searchIn = caseSensitive ? docText : docText.toLowerCase();
            String keyword = caseSensitive ? searchText : searchText.toLowerCase();

            int index = 0;
            while (index < searchIn.length()) {
                int found = searchIn.indexOf(keyword, index);
                if (found < 0) break;
                matchPositions.add(new int[]{found, found + searchText.length()});
                index = found + 1;
            }
        }

        // 应用高亮
        applySearchHighlights();

        // 更新计数
        if (matchPositions.isEmpty()) {
            matchCountLabel.setText("0/0");
            searchField.setBackground(new Color(255, 220, 220));
        } else {
            currentMatchIndex = 0;
            matchCountLabel.setText("1/" + matchPositions.size());
            searchField.setBackground(UIManager.getColor("TextField.background"));
            scrollToMatch(0);
        }
    }

    /**
     * 清除搜索高亮（恢复原始级别颜色）
     */
    private void clearHighlights() {
        if (styledDoc.getLength() == 0) return;

        // 遍历entryBuffer，重新设置每行的颜色
        for (int i = 0; i < entryBuffer.size(); i++) {
            LogEntry entry = entryBuffer.get(i);
            if (levelFilter != null && entry.getLevel().getLevel() < levelFilter.getLevel()) {
                continue;
            }

            // 找到该entry在lineOffsets中的位置
            int bufferDisplayIndex = 0;
            for (int j = 0; j < i; j++) {
                if (levelFilter != null && entryBuffer.get(j).getLevel().getLevel() < levelFilter.getLevel()) {
                    continue;
                }
                bufferDisplayIndex++;
            }

            if (bufferDisplayIndex >= lineOffsets.size()) continue;

            int startOffset = lineOffsets.get(bufferDisplayIndex);
            int endOffset;
            if (bufferDisplayIndex + 1 < lineOffsets.size()) {
                endOffset = lineOffsets.get(bufferDisplayIndex + 1);
            } else {
                endOffset = styledDoc.getLength();
            }

            SimpleAttributeSet attrs = new SimpleAttributeSet();
            StyleConstants.setForeground(attrs, entry.getDisplayColor());
            StyleConstants.setFontFamily(attrs, "Monospaced");
            StyleConstants.setFontSize(attrs, 12);

            styledDoc.setCharacterAttributes(startOffset, endOffset - startOffset, attrs, false);
        }
    }

    /**
     * 应用搜索匹配高亮
     */
    private void applySearchHighlights() {
        // 先清除
        for (int[] pos : matchPositions) {
            SimpleAttributeSet attrs = new SimpleAttributeSet();
            StyleConstants.setBackground(attrs, HIGHLIGHT_COLOR);
            styledDoc.setCharacterAttributes(pos[0], pos[1] - pos[0], attrs, false);
        }

        // 标记当前匹配
        if (currentMatchIndex >= 0 && currentMatchIndex < matchPositions.size()) {
            int[] pos = matchPositions.get(currentMatchIndex);
            SimpleAttributeSet attrs = new SimpleAttributeSet();
            StyleConstants.setBackground(attrs, CURRENT_HIGHLIGHT);
            styledDoc.setCharacterAttributes(pos[0], pos[1] - pos[0], attrs, false);
        }
    }

    /**
     * 在匹配结果间导航
     */
    private void navigateMatch(int direction) {
        if (matchPositions.isEmpty()) return;

        // 先恢复当前匹配为普通高亮
        if (currentMatchIndex >= 0 && currentMatchIndex < matchPositions.size()) {
            int[] pos = matchPositions.get(currentMatchIndex);
            SimpleAttributeSet attrs = new SimpleAttributeSet();
            StyleConstants.setBackground(attrs, HIGHLIGHT_COLOR);
            styledDoc.setCharacterAttributes(pos[0], pos[1] - pos[0], attrs, false);
        }

        // 计算新索引（循环）
        currentMatchIndex += direction;
        if (currentMatchIndex >= matchPositions.size()) {
            currentMatchIndex = 0;
        } else if (currentMatchIndex < 0) {
            currentMatchIndex = matchPositions.size() - 1;
        }

        // 标记新当前匹配
        scrollToMatch(currentMatchIndex);
        matchCountLabel.setText((currentMatchIndex + 1) + "/" + matchPositions.size());
    }

    /**
     * 滚动到指定匹配位置
     */
    private void scrollToMatch(int matchIndex) {
        if (matchIndex < 0 || matchIndex >= matchPositions.size()) return;

        int[] pos = matchPositions.get(matchIndex);

        // 标记当前匹配
        SimpleAttributeSet attrs = new SimpleAttributeSet();
        StyleConstants.setBackground(attrs, CURRENT_HIGHLIGHT);
        styledDoc.setCharacterAttributes(pos[0], pos[1] - pos[0], attrs, false);

        // 滚动到可见区域
        logTextPane.setCaretPosition(pos[0]);
    }

    /**
     * 清除搜索
     */
    private void clearSearch() {
        searchField.setText("");
        clearHighlights();
        matchPositions.clear();
        currentMatchIndex = -1;
        matchCountLabel.setText("0/0");
        searchField.setBackground(UIManager.getColor("TextField.background"));
    }

    /**
     * 导出日志到文件
     */
    private void exportLog() {
        File selectedFile = oxff.top.utils.FileChooserHelper.showSaveDialog(
            oxff.top.utils.FileChooserHelper.OP_LOG_EXPORT, "导出日志", this,
            new File("repeater_manager_log.txt"));

        if (selectedFile != null) {
            try (BufferedWriter bw = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(selectedFile), StandardCharsets.UTF_8))) {
                for (LogEntry entry : entryBuffer) {
                    bw.write(entry.getFileFormattedMesssage());
                    bw.newLine();
                }
                JOptionPane.showMessageDialog(this,
                    "日志已导出到: " + selectedFile.getAbsolutePath(),
                    "导出成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this,
                    "导出失败: " + e.getMessage(),
                    "导出错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    /**
     * 设置最大条目数
     */
    public void setMaxEntries(int max) {
        this.maxEntries = Math.max(1, Math.min(1024, max));
        trimEntries();
    }

    public int getMaxEntries() {
        return maxEntries;
    }
}

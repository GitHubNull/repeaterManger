package org.oxff.repeater.ui.history;

import org.oxff.repeater.utils.TextLineNumber;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 差异显示面板 — 自包含的差异文本显示组件
 * 封装: JTextPane(差异渲染) + 行号 + 可折叠搜索栏 + 差异区域追踪
 */
public class DiffPane extends JPanel {
    private static final long serialVersionUID = 1L;

    // ==================== 差异高亮颜色 ====================

    /** 行级颜色 */
    private static final Color COLOR_UNCHANGED_LINE = new Color(230, 255, 230);    // 浅绿: 相同行(符合"相同字符串标绿色"要求)
    private static final Color COLOR_ADDED_LINE = new Color(220, 255, 220);       // 绿色: 新增行
    private static final Color COLOR_REMOVED_LINE = new Color(255, 220, 220);     // 红色: 删除行
    private static final Color COLOR_CHANGED_LINE = new Color(255, 250, 230);     // 浅黄: 变更行底色

    /** 行内字符级颜色 */
    private static final Color COLOR_INLINE_MATCH = new Color(200, 255, 200);     // 绿色: 匹配字符
    private static final Color COLOR_INLINE_DIFF_ORIG = new Color(255, 200, 200); // 红色: 原始侧差异字符
    private static final Color COLOR_INLINE_DIFF_MOD = new Color(150, 255, 150);  // 深绿: 修改侧差异字符



    private static final Font MONO_FONT = new Font("Monospaced", Font.PLAIN, 13);

    // ==================== 核心组件 ====================

    private final JTextPane textPane;
    private final StyledDocument styledDoc;
    private final JScrollPane scrollPane;
    private final SearchBar searchBar;

    // ==================== 差异区域追踪 ====================

    private final List<DiffRegion> diffRegions = new ArrayList<>();

    // ==================== 搜索与差异属性快照 ====================

    /** 记录每行的差异背景色，用于搜索清除后恢复 */
    private final List<LineAttributeSnapshot> lineSnapshots = new ArrayList<>();



    // ==================== 数据类 ====================

    public DiffPane() {
        super(new BorderLayout());

        // 创建文本显示区
        textPane = new JTextPane();
        textPane.setEditable(false);
        textPane.setBackground(Color.WHITE);
        textPane.setFont(MONO_FONT);
        styledDoc = textPane.getStyledDocument();

        // 设置默认样式
        Style baseStyle = textPane.getStyle(StyleContext.DEFAULT_STYLE);
        StyleConstants.setFontFamily(baseStyle, "Monospaced");
        StyleConstants.setFontSize(baseStyle, 13);

        // 行号
        TextLineNumber textLineNumber = new TextLineNumber(textPane);
        textLineNumber.setForeground(Color.GRAY);
        textLineNumber.setBackground(new Color(245, 245, 245));

        // 滚动面板
        scrollPane = new JScrollPane(textPane);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        scrollPane.setRowHeaderView(textLineNumber);

        // 搜索栏（默认可见）
        searchBar = new SearchBar(textPane, this);
        searchBar.setVisible(true);

        // 组装
        add(searchBar, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);

        // 注册 Ctrl+F 快捷键
        registerKeyboardAction(
            e -> toggleSearchBar(),
            KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_F, java.awt.event.InputEvent.CTRL_DOWN_MASK),
            WHEN_ANCESTOR_OF_FOCUSED_COMPONENT
        );
    }

    // ==================== 渲染方法 ====================

    /**
     * 渲染字符串级行差异（含行内字符级差异）
     *
     * @param diffLines      差异行列表
     * @param isOriginalSide 是否为原始侧(左侧)
     */
    public void renderDiffLines(List<DiffLine> diffLines, boolean isOriginalSide) {
        this.diffRegions.clear();
        this.lineSnapshots.clear();

        try {
            styledDoc.remove(0, styledDoc.getLength());
        } catch (BadLocationException e) {
            // 忽略
        }

        // 定义行级样式
        Style defaultStyle = textPane.getStyle(StyleContext.DEFAULT_STYLE);
        Style unchangedStyle = styledDoc.addStyle("unchanged", defaultStyle);
        StyleConstants.setBackground(unchangedStyle, COLOR_UNCHANGED_LINE);

        Style removedStyle = styledDoc.addStyle("removed", defaultStyle);
        StyleConstants.setBackground(removedStyle, COLOR_REMOVED_LINE);

        Style addedStyle = styledDoc.addStyle("added", defaultStyle);
        StyleConstants.setBackground(addedStyle, COLOR_ADDED_LINE);

        Style changedStyle = styledDoc.addStyle("changed", defaultStyle);
        StyleConstants.setBackground(changedStyle, COLOR_CHANGED_LINE);

        Style blankStyle = styledDoc.addStyle("blank", defaultStyle);
        StyleConstants.setBackground(blankStyle, Color.WHITE);

        try {
            for (DiffLine line : diffLines) {
                int lineStartOffset = styledDoc.getLength();

                switch (line.getDiffType()) {
                    case UNCHANGED:
                        styledDoc.insertString(styledDoc.getLength(), line.getLineText() + "\n", unchangedStyle);
                        recordLineSnapshot(lineStartOffset, styledDoc.getLength() - lineStartOffset, COLOR_UNCHANGED_LINE);
                        break;

                    case REMOVED:
                        if (isOriginalSide) {
                            styledDoc.insertString(styledDoc.getLength(), line.getLineText() + "\n", removedStyle);
                            recordDiffRegion(lineStartOffset, styledDoc.getLength(), DiffType.REMOVED, line.getLineNumber());
                            recordLineSnapshot(lineStartOffset, styledDoc.getLength() - lineStartOffset, COLOR_REMOVED_LINE);
                        } else {
                            styledDoc.insertString(styledDoc.getLength(), "\n", blankStyle);
                            // 对齐空行也记录为差异区域，以便导航同步
                            recordDiffRegion(lineStartOffset, styledDoc.getLength(), DiffType.REMOVED, line.getLineNumber());
                            recordLineSnapshot(lineStartOffset, styledDoc.getLength() - lineStartOffset, Color.WHITE);
                        }
                        break;

                    case ADDED:
                        if (isOriginalSide) {
                            styledDoc.insertString(styledDoc.getLength(), "\n", blankStyle);
                            recordDiffRegion(lineStartOffset, styledDoc.getLength(), DiffType.ADDED, line.getLineNumber());
                            recordLineSnapshot(lineStartOffset, styledDoc.getLength() - lineStartOffset, Color.WHITE);
                        } else {
                            styledDoc.insertString(styledDoc.getLength(), line.getLineText() + "\n", addedStyle);
                            recordDiffRegion(lineStartOffset, styledDoc.getLength(), DiffType.ADDED, line.getLineNumber());
                            recordLineSnapshot(lineStartOffset, styledDoc.getLength() - lineStartOffset, COLOR_ADDED_LINE);
                        }
                        break;

                    case CHANGED:
                        if (line instanceof ChangedDiffLine changedLine) {
                            renderChangedLine(changedLine, isOriginalSide, changedStyle);
                        } else {
                            // 降级为普通行
                            styledDoc.insertString(styledDoc.getLength(), line.getLineText() + "\n", changedStyle);
                            recordLineSnapshot(lineStartOffset, styledDoc.getLength() - lineStartOffset, COLOR_CHANGED_LINE);
                        }
                        recordDiffRegion(lineStartOffset, styledDoc.getLength(), DiffType.CHANGED, line.getLineNumber());
                        break;
                }
            }
        } catch (BadLocationException e) {
            // 忽略
        }

        // 重置搜索状态
        searchBar.clearSearch();
    }

    /**
     * 渲染 CHANGED 行 — 行内字符级差异: MATCH=绿底, DIFF=红底(原始侧)/深绿底(修改侧)
     */
    private void renderChangedLine(ChangedDiffLine changedLine, boolean isOriginalSide,
                                   Style changedBaseStyle) throws BadLocationException {
        List<InlineDiffSegment> segments;
        String displayText;

        if (isOriginalSide) {
            segments = changedLine.getOriginalInlineDiff();
            displayText = changedLine.getLineText();
        } else {
            segments = changedLine.getModifiedInlineDiff();
            displayText = changedLine.getPairedText();
        }

        if (segments == null || segments.isEmpty()) {
            // 无行内差异数据，整行渲染
            int start = styledDoc.getLength();
            styledDoc.insertString(styledDoc.getLength(), displayText + "\n", changedBaseStyle);
            recordLineSnapshot(start, styledDoc.getLength() - start, COLOR_CHANGED_LINE);
            return;
        }

        Style defaultStyle = textPane.getStyle(StyleContext.DEFAULT_STYLE);

        // 预先创建行内样式（避免循环中重复创建同名样式导致覆盖）
        String matchStyleName = isOriginalSide ? "inline_orig_match" : "inline_mod_match";
        String diffStyleName = isOriginalSide ? "inline_orig_diff" : "inline_mod_diff";

        Style inlineMatchStyle = styledDoc.addStyle(matchStyleName, defaultStyle);
        StyleConstants.setFontFamily(inlineMatchStyle, "Monospaced");
        StyleConstants.setFontSize(inlineMatchStyle, 13);
        StyleConstants.setBackground(inlineMatchStyle, COLOR_INLINE_MATCH);

        Style inlineDiffStyle = styledDoc.addStyle(diffStyleName, defaultStyle);
        StyleConstants.setFontFamily(inlineDiffStyle, "Monospaced");
        StyleConstants.setFontSize(inlineDiffStyle, 13);
        StyleConstants.setBackground(inlineDiffStyle, isOriginalSide ? COLOR_INLINE_DIFF_ORIG : COLOR_INLINE_DIFF_MOD);

        // 渲染行内段，同时记录每段快照用于搜索恢复
        for (InlineDiffSegment segment : segments) {
            int segStartOffset = styledDoc.getLength();
            boolean isMatch = segment.getType() == InlineDiffType.MATCH;
            Style segStyle = isMatch ? inlineMatchStyle : inlineDiffStyle;
            styledDoc.insertString(styledDoc.getLength(), segment.getText(), segStyle);
            Color segBgColor = isMatch ? COLOR_INLINE_MATCH : (isOriginalSide ? COLOR_INLINE_DIFF_ORIG : COLOR_INLINE_DIFF_MOD);
            recordLineSnapshot(segStartOffset, segment.getText().length(), segBgColor);
        }

        // 行尾换行
        int newlineStartOffset = styledDoc.getLength();
        styledDoc.insertString(styledDoc.getLength(), "\n", changedBaseStyle);
        recordLineSnapshot(newlineStartOffset, 1, COLOR_CHANGED_LINE);
    }

    /**
     * 渲染 Hex 级差异
     */
    public void renderHexDiffSegments(List<DiffSegment> diffSegments, boolean isOriginalSide) {
        this.diffRegions.clear();
        this.lineSnapshots.clear();

        try {
            styledDoc.remove(0, styledDoc.getLength());
        } catch (BadLocationException e) {
            // 忽略
        }

        Style defaultStyle = textPane.getStyle(StyleContext.DEFAULT_STYLE);
        StyleConstants.setFontFamily(defaultStyle, "Monospaced");
        StyleConstants.setFontSize(defaultStyle, 13);

        Style unchangedStyle = styledDoc.addStyle("hex_unchanged", defaultStyle);
        StyleConstants.setBackground(unchangedStyle, COLOR_UNCHANGED_LINE);

        Style removedStyle = styledDoc.addStyle("hex_removed", defaultStyle);
        StyleConstants.setBackground(removedStyle, COLOR_REMOVED_LINE);

        Style addedStyle = styledDoc.addStyle("hex_added", defaultStyle);
        StyleConstants.setBackground(addedStyle, COLOR_ADDED_LINE);

        Style blankStyle = styledDoc.addStyle("hex_blank", defaultStyle);
        StyleConstants.setBackground(blankStyle, Color.WHITE);

        try {
            for (DiffSegment seg : diffSegments) {
                String lineText = String.format("%08X  %-47s  %s\n",
                    seg.getOffset(), seg.getHexData(), seg.getAsciiData());
                int lineStartOffset = styledDoc.getLength();

                switch (seg.getDiffType()) {
                    case UNCHANGED:
                        styledDoc.insertString(styledDoc.getLength(), lineText, unchangedStyle);
                        recordLineSnapshot(lineStartOffset, styledDoc.getLength() - lineStartOffset, COLOR_UNCHANGED_LINE);
                        break;
                    case REMOVED:
                        if (isOriginalSide) {
                            styledDoc.insertString(styledDoc.getLength(), lineText, removedStyle);
                            recordDiffRegion(lineStartOffset, styledDoc.getLength(), DiffType.REMOVED, seg.getOffset());
                            recordLineSnapshot(lineStartOffset, styledDoc.getLength() - lineStartOffset, COLOR_REMOVED_LINE);
                        } else {
                            styledDoc.insertString(styledDoc.getLength(), "\n", blankStyle);
                            recordDiffRegion(lineStartOffset, styledDoc.getLength(), DiffType.REMOVED, seg.getOffset());
                            recordLineSnapshot(lineStartOffset, styledDoc.getLength() - lineStartOffset, Color.WHITE);
                        }
                        break;
                    case ADDED:
                        if (isOriginalSide) {
                            styledDoc.insertString(styledDoc.getLength(), "\n", blankStyle);
                            recordDiffRegion(lineStartOffset, styledDoc.getLength(), DiffType.ADDED, seg.getOffset());
                            recordLineSnapshot(lineStartOffset, styledDoc.getLength() - lineStartOffset, Color.WHITE);
                        } else {
                            styledDoc.insertString(styledDoc.getLength(), lineText, addedStyle);
                            recordDiffRegion(lineStartOffset, styledDoc.getLength(), DiffType.ADDED, seg.getOffset());
                            recordLineSnapshot(lineStartOffset, styledDoc.getLength() - lineStartOffset, COLOR_ADDED_LINE);
                        }
                        break;
                    default:
                        styledDoc.insertString(styledDoc.getLength(), lineText, unchangedStyle);
                        break;
                }
            }
        } catch (BadLocationException e) {
            // 忽略
        }

        searchBar.clearSearch();
    }

    /**
     * 渲染纯文本（四面板模式中的独立面板）
     */
    public void renderPlainText(byte[] data, boolean isHexMode) {
        this.diffRegions.clear();
        this.lineSnapshots.clear();

        try {
            styledDoc.remove(0, styledDoc.getLength());
        } catch (BadLocationException e) {
            // 忽略
        }

        Style baseStyle = textPane.getStyle(StyleContext.DEFAULT_STYLE);
        StyleConstants.setFontFamily(baseStyle, "Monospaced");
        StyleConstants.setFontSize(baseStyle, 13);
        StyleConstants.setBackground(baseStyle, Color.WHITE);

        try {
            if (isHexMode) {
                List<String> hexLines = DiffEngine.generateHexDump(data != null ? data : new byte[0]);
                for (String line : hexLines) {
                    int lineStart = styledDoc.getLength();
                    styledDoc.insertString(styledDoc.getLength(), line + "\n", baseStyle);
                    recordLineSnapshot(lineStart, styledDoc.getLength() - lineStart, Color.WHITE);
                }
            } else {
                String text = (data != null) ? bytesToString(data) : "";
                int lineStart = styledDoc.getLength();
                styledDoc.insertString(styledDoc.getLength(), text, baseStyle);
                recordLineSnapshot(lineStart, styledDoc.getLength() - lineStart, Color.WHITE);
            }
        } catch (BadLocationException e) {
            // 忽略
        }

        searchBar.clearSearch();
    }

    // ==================== 差异区域追踪 ====================

    private void recordDiffRegion(int startOffset, int endOffset, DiffType type, int lineNumber) {
        diffRegions.add(new DiffRegion(startOffset, endOffset, type, lineNumber));
    }

    private void recordLineSnapshot(int startOffset, int length, Color backgroundColor) {
        lineSnapshots.add(new LineAttributeSnapshot(startOffset, length, backgroundColor));
    }

    /**
     * 获取差异区域列表（供 DiffNavigator 使用）
     */
    public List<DiffRegion> getDiffRegions() {
        return diffRegions;
    }

    /**
     * 恢复差异背景色（搜索清除时调用）
     */
    public void restoreDiffBackgrounds() {
        for (LineAttributeSnapshot snapshot : lineSnapshots) {
            if (snapshot.startOffset + snapshot.length <= styledDoc.getLength()) {
                SimpleAttributeSet attrs = new SimpleAttributeSet();
                StyleConstants.setBackground(attrs, snapshot.backgroundColor);
                styledDoc.setCharacterAttributes(snapshot.startOffset, snapshot.length, attrs, false);
            }
        }
    }

    // ==================== 搜索栏控制 ====================

    /**
     * 切换搜索栏可见性
     */
    public void toggleSearchBar() {
        searchBar.setVisible(!searchBar.isVisible());
        if (searchBar.isVisible()) {
            searchBar.focusSearchField();
        }
        revalidate();
        repaint();
    }

    /**
     * 显示搜索栏
     */
    public void showSearchBar() {
        if (!searchBar.isVisible()) {
            searchBar.setVisible(true);
            searchBar.focusSearchField();
            revalidate();
            repaint();
        }
    }

    /**
     * 隐藏搜索栏
     */
    public void hideSearchBar() {
        if (searchBar.isVisible()) {
            searchBar.setVisible(false);
            searchBar.clearSearch();
            revalidate();
            repaint();
        }
    }

    // ==================== 访问方法 ====================

    /**
     * 获取内部滚动面板
     */
    public JScrollPane getScrollPane() {
        return scrollPane;
    }

    /**
     * 获取文本面板
     */
    public JTextPane getTextPane() {
        return textPane;
    }

    /**
     * 获取搜索栏
     */
    public SearchBar getSearchBar() {
        return searchBar;
    }

    // ==================== 辅助方法 ====================

    private String bytesToString(byte[] data) {
        if (data == null) return "";
        int bodyOffset = findBodyOffset(data);
        if (bodyOffset > 0 && bodyOffset < data.length) {
            String header = new String(data, 0, bodyOffset, java.nio.charset.StandardCharsets.ISO_8859_1);
            String body = new String(data, bodyOffset, data.length - bodyOffset, java.nio.charset.StandardCharsets.UTF_8);
            return header + body;
        }
        return new String(data, java.nio.charset.StandardCharsets.UTF_8);
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
}

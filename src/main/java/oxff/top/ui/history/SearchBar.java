package oxff.top.ui.history;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 可折叠搜索栏 — 附加在 DiffPane 顶部
 * 支持: 关键字/正则匹配、大小写敏感、上一个/下一个导航、匹配计数
 * 搜索高亮与差异着色通过叠加层策略共存
 */
public class SearchBar extends JPanel {
    private static final long serialVersionUID = 1L;

    /** 搜索高亮颜色 */
    private static final Color COLOR_MATCH = new Color(255, 255, 0);       // 黄色: 所有匹配
    private static final Color COLOR_CURRENT = new Color(255, 165, 0);     // 橙色: 当前匹配
    /** 无匹配时搜索框背景 */
    private static final Color COLOR_NO_MATCH = new Color(255, 220, 220);

    // ==================== 关联组件 ====================

    private final JTextPane textPane;
    private final StyledDocument styledDoc;
    private final DiffPane diffPane;

    // ==================== UI 组件 ====================

    private final JToggleButton keywordModeButton;
    private final JToggleButton regexModeButton;
    private final JTextField searchField;
    private final JCheckBox caseSensitiveCheckbox;
    private final JButton prevMatchButton;
    private final JButton nextMatchButton;
    private final JLabel matchCountLabel;
    private final JButton clearButton;

    // ==================== 搜索状态 ====================

    private boolean isRegexMode = false;
    private final List<int[]> matchPositions = new ArrayList<>();
    private int currentMatchIndex = -1;

    // 防抖定时器
    private Timer debounceTimer;

    /**
     * 创建搜索栏
     *
     * @param textPane 关联的文本面板
     * @param diffPane 关联的差异面板(用于恢复差异背景色)
     */
    public SearchBar(JTextPane textPane, DiffPane diffPane) {
        this.textPane = textPane;
        this.styledDoc = textPane.getStyledDocument();
        this.diffPane = diffPane;

        setLayout(new FlowLayout(FlowLayout.LEFT, 4, 2));
        setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY));

        // 搜索模式按钮
        keywordModeButton = new JToggleButton("关键字");
        keywordModeButton.setSelected(true);
        regexModeButton = new JToggleButton("正则");
        ButtonGroup searchModeGroup = new ButtonGroup();
        searchModeGroup.add(keywordModeButton);
        searchModeGroup.add(regexModeButton);

        keywordModeButton.addActionListener(e -> { isRegexMode = false; performSearch(); });
        regexModeButton.addActionListener(e -> { isRegexMode = true; performSearch(); });

        // 搜索输入框
        searchField = new JTextField(18);
        searchField.setToolTipText("输入关键字或正则表达式搜索");

        // 大小写敏感
        caseSensitiveCheckbox = new JCheckBox("Aa", false);
        caseSensitiveCheckbox.setToolTipText("区分大小写");
        caseSensitiveCheckbox.addActionListener(e -> performSearch());

        // 上一个/下一个
        prevMatchButton = new JButton("▲");
        prevMatchButton.setToolTipText("上一个匹配");
        prevMatchButton.addActionListener(e -> navigateMatch(-1));

        nextMatchButton = new JButton("▼");
        nextMatchButton.setToolTipText("下一个匹配");
        nextMatchButton.addActionListener(e -> navigateMatch(1));

        // 匹配计数
        matchCountLabel = new JLabel("0/0");
        matchCountLabel.setPreferredSize(new Dimension(60, 20));

        // 清除按钮
        clearButton = new JButton("✕");
        clearButton.setToolTipText("清除搜索");
        clearButton.addActionListener(e -> clearSearch());

        // 组装
        add(keywordModeButton);
        add(regexModeButton);
        add(searchField);
        add(caseSensitiveCheckbox);
        add(prevMatchButton);
        add(nextMatchButton);
        add(matchCountLabel);
        add(clearButton);

        // 初始化防抖定时器
        debounceTimer = new Timer(300, e -> performSearch());
        debounceTimer.setRepeats(false);

        // 搜索框输入监听
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { debounceTimer.restart(); }
            @Override
            public void removeUpdate(DocumentEvent e) { debounceTimer.restart(); }
            @Override
            public void changedUpdate(DocumentEvent e) { debounceTimer.restart(); }
        });

        // 回车搜索
        searchField.addActionListener(e -> {
            debounceTimer.stop();
            performSearch();
        });

        // 搜索框键盘快捷键
        searchField.registerKeyboardAction(
            e -> navigateMatch(-1),
            KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.SHIFT_DOWN_MASK),
            WHEN_FOCUSED
        );
        searchField.registerKeyboardAction(
            e -> navigateMatch(1),
            KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0),
            WHEN_FOCUSED
        );
        searchField.registerKeyboardAction(
            e -> {
                clearSearch();
                diffPane.hideSearchBar();
            },
            KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
            WHEN_FOCUSED
        );
    }

    // ==================== 搜索核心逻辑 ====================

    /**
     * 执行搜索
     */
    public void performSearch() {
        String searchText = searchField.getText().trim();

        // 先恢复差异背景色，再清除高亮
        diffPane.restoreDiffBackgrounds();

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
            try {
                int flags = caseSensitive ? 0 : Pattern.CASE_INSENSITIVE;
                Pattern pattern = Pattern.compile(searchText, flags);
                Matcher matcher = pattern.matcher(docText);

                while (matcher.find()) {
                    matchPositions.add(new int[]{matcher.start(), matcher.end()});
                }

                searchField.setBackground(UIManager.getColor("TextField.background"));
            } catch (PatternSyntaxException e) {
                searchField.setBackground(COLOR_NO_MATCH);
                matchCountLabel.setText("0/0");
                return;
            }
        } else {
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

        // 应用搜索高亮
        applySearchHighlights();

        // 更新计数和导航
        if (matchPositions.isEmpty()) {
            matchCountLabel.setText("0/0");
            searchField.setBackground(COLOR_NO_MATCH);
        } else {
            currentMatchIndex = 0;
            matchCountLabel.setText("1/" + matchPositions.size());
            searchField.setBackground(UIManager.getColor("TextField.background"));
            scrollToMatch(0);
        }
    }

    /**
     * 应用搜索高亮（叠加在差异背景色之上）
     */
    private void applySearchHighlights() {
        // 所有匹配: 黄色背景
        for (int[] pos : matchPositions) {
            SimpleAttributeSet attrs = new SimpleAttributeSet();
            StyleConstants.setBackground(attrs, COLOR_MATCH);
            styledDoc.setCharacterAttributes(pos[0], pos[1] - pos[0], attrs, false);
        }

        // 当前匹配: 橙色背景
        if (currentMatchIndex >= 0 && currentMatchIndex < matchPositions.size()) {
            int[] pos = matchPositions.get(currentMatchIndex);
            SimpleAttributeSet attrs = new SimpleAttributeSet();
            StyleConstants.setBackground(attrs, COLOR_CURRENT);
            styledDoc.setCharacterAttributes(pos[0], pos[1] - pos[0], attrs, false);
        }
    }

    /**
     * 在匹配结果间导航
     *
     * @param direction +1=下一个, -1=上一个
     */
    public void navigateMatch(int direction) {
        if (matchPositions.isEmpty()) return;

        // 恢复当前匹配为普通黄色
        if (currentMatchIndex >= 0 && currentMatchIndex < matchPositions.size()) {
            int[] pos = matchPositions.get(currentMatchIndex);
            SimpleAttributeSet attrs = new SimpleAttributeSet();
            StyleConstants.setBackground(attrs, COLOR_MATCH);
            styledDoc.setCharacterAttributes(pos[0], pos[1] - pos[0], attrs, false);
        }

        // 计算新索引（循环）
        currentMatchIndex += direction;
        if (currentMatchIndex >= matchPositions.size()) {
            currentMatchIndex = 0;
        } else if (currentMatchIndex < 0) {
            currentMatchIndex = matchPositions.size() - 1;
        }

        // 标记新当前匹配并滚动
        scrollToMatch(currentMatchIndex);
        matchCountLabel.setText((currentMatchIndex + 1) + "/" + matchPositions.size());
    }

    /**
     * 滚动到指定匹配位置
     */
    private void scrollToMatch(int matchIndex) {
        if (matchIndex < 0 || matchIndex >= matchPositions.size()) return;

        int[] pos = matchPositions.get(matchIndex);

        // 标记当前匹配为橙色
        SimpleAttributeSet attrs = new SimpleAttributeSet();
        StyleConstants.setBackground(attrs, COLOR_CURRENT);
        styledDoc.setCharacterAttributes(pos[0], pos[1] - pos[0], attrs, false);

        // 滚动到可见区域
        textPane.setCaretPosition(pos[0]);
    }

    /**
     * 清除搜索高亮并重置搜索状态
     */
    public void clearSearch() {
        // 恢复差异背景色
        diffPane.restoreDiffBackgrounds();

        matchPositions.clear();
        currentMatchIndex = -1;
        matchCountLabel.setText("0/0");
        searchField.setBackground(UIManager.getColor("TextField.background"));
    }

    /**
     * 聚焦搜索输入框
     */
    public void focusSearchField() {
        searchField.requestFocusInWindow();
        searchField.selectAll();
    }

    /**
     * 获取当前匹配数量
     */
    public int getMatchCount() {
        return matchPositions.size();
    }

    /**
     * 获取当前匹配索引
     */
    public int getCurrentMatchIndex() {
        return currentMatchIndex;
    }
}

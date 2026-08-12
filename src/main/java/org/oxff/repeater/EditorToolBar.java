package org.oxff.repeater;

import org.oxff.repeater.i18n.I18nManager;
import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.ui.*;
import org.oxff.repeater.ui.layout.LayoutManager;

import javax.swing.*;
import java.awt.*;

/**
 * 编辑区工具栏构建器
 * 从 RepeaterManagerUI 中提取，负责构建编辑区域顶部的控制面板
 */
public class EditorToolBar {

    private final RequestDispatchHandler dispatchHandler;
    private final LayoutManager layoutManager;
    private final JPanel mainPanel;

    // 公开的UI组件引用 — 外部（RepeaterManagerUI）需要通过这些引用更新样式状态
    public final SwitchButton modeToggleButton;
    public final JLabel normalModeLabel;
    public final JLabel privilegeModeLabel;
    public final SwitchButton debugToggleButton;
    public final JLabel debugNormalLabel;
    public final JLabel debugModeLabel;
    public final SwitchButton gcToggleButton;
    public final JLabel gcOffLabel;
    public final JLabel gcOnLabel;
    public final SwitchButton languageToggleButton;
    public final JLabel languageZhLabel;
    public final JLabel languageEnLabel;

    // 布局下拉框（需要在语言切换时刷新选项文本）
    private JComboBox<String> layoutComboBox;
    // 布局标签
    private JLabel layoutLabel;
    // 相似度计算按钮
    private JButton similarityCalcBtn;
    // 清空报文按钮
    private JButton clearAllBtn;

    /**
     * 清空操作回调接口
     */
    public interface ClearAllCallback {
        void onClearAll();
    }

    private ClearAllCallback clearAllCallback;

    /**
     * 设置清空操作回调
     */
    public void setClearAllCallback(ClearAllCallback callback) {
        this.clearAllCallback = callback;
    }

    public EditorToolBar(RequestDispatchHandler dispatchHandler,
                         LayoutManager layoutManager, JPanel mainPanel) {
        this.dispatchHandler = dispatchHandler;
        this.layoutManager = layoutManager;
        this.mainPanel = mainPanel;

        // 创建组件实例（供外部引用）
        this.modeToggleButton = new SwitchButton();
        this.normalModeLabel = new JLabel(I18nManager.tr("toolbar.mode.normal"));
        this.privilegeModeLabel = new JLabel(I18nManager.tr("toolbar.mode.privilege"));
        this.debugToggleButton = new SwitchButton();
        this.debugNormalLabel = new JLabel(I18nManager.tr("toolbar.debug.normal"));
        this.debugModeLabel = new JLabel(I18nManager.tr("toolbar.debug.mode"));
        this.gcToggleButton = new SwitchButton();
        this.gcOffLabel = new JLabel(I18nManager.tr("toolbar.gc.manual"));
        this.gcOnLabel = new JLabel(I18nManager.tr("toolbar.gc.auto"));
        this.languageToggleButton = new SwitchButton();
        // 语言名标签使用固有名称，不随界面语言切换变化
        this.languageZhLabel = new JLabel("中文");
        this.languageEnLabel = new JLabel("English");

        // 根据当前语言偏好初始化开关状态
        this.languageToggleButton.setSelected(I18nManager.getInstance().isEnglish());

        // 注册语言变更监听：刷新工具栏所有文本
        I18nManager.getInstance().addLocaleChangeListener(this::refreshTexts);
    }

    /**
     * 构建全局工具栏（插件顶部）
     * 包含：模式切换、调试切换、GC切换、语言切换
     */
    public JPanel buildGlobalToolBar() {
        JPanel globalToolBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        globalToolBar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, UIManager.getColor("Separator.foreground")),
            BorderFactory.createEmptyBorder(5, 10, 5, 10)
        ));

        // 普通模式/权限测试切换
        normalModeLabel.setToolTipText(I18nManager.tr("toolbar.mode.tooltip"));
        globalToolBar.add(normalModeLabel);

        modeToggleButton.setToolTipText(I18nManager.tr("toolbar.mode.tooltip"));
        modeToggleButton.addActionListener(e -> {
            boolean selected = modeToggleButton.isSelected();
            dispatchHandler.setPrivilegeTestMode(selected);
            LogManager.getInstance().printOutput(
                I18nManager.tr(selected ? "log.privilege.mode.on" : "log.privilege.mode.off"));
        });
        globalToolBar.add(modeToggleButton);

        privilegeModeLabel.setToolTipText(I18nManager.tr("toolbar.mode.tooltip"));
        globalToolBar.add(privilegeModeLabel);
        globalToolBar.add(new JSeparator(SwingConstants.VERTICAL));

        // 调试切换
        debugNormalLabel.setToolTipText(I18nManager.tr("toolbar.debug.tooltip"));
        globalToolBar.add(debugNormalLabel);

        debugToggleButton.setToolTipText(I18nManager.tr("toolbar.debug.tooltip"));
        debugToggleButton.addActionListener(e -> {
            boolean selected = debugToggleButton.isSelected();
            LogManager.getInstance().setJudgmentDebugEnabled(selected);
            LogManager.getInstance().printOutput(
                I18nManager.tr(selected ? "log.debug.mode.on" : "log.debug.mode.off"));
        });
        globalToolBar.add(debugToggleButton);

        debugModeLabel.setToolTipText(I18nManager.tr("toolbar.debug.tooltip"));
        globalToolBar.add(debugModeLabel);
        globalToolBar.add(new JSeparator(SwingConstants.VERTICAL));

        // GC切换
        gcOffLabel.setToolTipText(I18nManager.tr("toolbar.gc.tooltip"));
        globalToolBar.add(gcOffLabel);

        gcToggleButton.setToolTipText(I18nManager.tr("toolbar.gc.tooltip"));
        gcToggleButton.addActionListener(e -> {
            boolean selected = gcToggleButton.isSelected();
            LogManager.getInstance().setAutoGcEnabled(selected);
            LogManager.getInstance().printOutput(
                I18nManager.tr(selected ? "log.gc.on" : "log.gc.off"));
        });
        globalToolBar.add(gcToggleButton);

        gcOnLabel.setToolTipText(I18nManager.tr("toolbar.gc.tooltip"));
        globalToolBar.add(gcOnLabel);
        globalToolBar.add(new JSeparator(SwingConstants.VERTICAL));

        // 清空报文按钮
        clearAllBtn = new JButton(I18nManager.tr("request.list.clearAll"));
        clearAllBtn.setToolTipText(I18nManager.tr("request.list.clearAll.tooltip"));
        clearAllBtn.addActionListener(e -> {
            if (clearAllCallback != null) {
                clearAllCallback.onClearAll();
            }
        });
        globalToolBar.add(clearAllBtn);
        globalToolBar.add(new JSeparator(SwingConstants.VERTICAL));

        // 语言切换：左侧中文、右侧English，开关选中=英文
        languageZhLabel.setToolTipText(I18nManager.tr("toolbar.language.tooltip"));
        globalToolBar.add(languageZhLabel);

        languageToggleButton.setToolTipText(I18nManager.tr("toolbar.language.tooltip"));
        languageToggleButton.addActionListener(e -> {
            boolean toEnglish = languageToggleButton.isSelected();
            I18nManager.getInstance().setLocale(
                toEnglish ? I18nManager.LOCALE_EN : I18nManager.LOCALE_ZH);
            LogManager.getInstance().printOutput(I18nManager.tr("log.language.switched"));
        });
        globalToolBar.add(languageToggleButton);

        languageEnLabel.setToolTipText(I18nManager.tr("toolbar.language.tooltip"));
        globalToolBar.add(languageEnLabel);

        return globalToolBar;
    }

    /**
     * 构建报文显示编辑工具栏（编辑区顶部）
     * 包含：相似度计算、布局选择
     */
    public JPanel buildMessageEditorToolBar() {
        JPanel toolBar = new JPanel(new BorderLayout());
        toolBar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, UIManager.getColor("Separator.foreground")),
            BorderFactory.createEmptyBorder(5, 10, 5, 10)
        ));

        // 左侧：相似度计算
        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        similarityCalcBtn = new JButton(I18nManager.tr("toolbar.similarity"));
        similarityCalcBtn.setToolTipText(I18nManager.tr("toolbar.similarity.tooltip"));
        similarityCalcBtn.addActionListener(e -> {
            SimilarityCalculatorDialog dialog = new SimilarityCalculatorDialog(
                (Frame) SwingUtilities.getWindowAncestor(mainPanel));
            dialog.setVisible(true);
        });
        leftPanel.add(similarityCalcBtn);

        // 右侧：布局选择（按索引判断逻辑，显示文本从资源读取，与逻辑解耦）
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 2));
        layoutComboBox = new JComboBox<>(buildLayoutItems());
        layoutComboBox.setToolTipText(I18nManager.tr("toolbar.layout.tooltip"));
        layoutComboBox.addActionListener(e -> {
            int index = layoutComboBox.getSelectedIndex();
            switch (index) {
                case 0:
                    layoutManager.setLayout(LayoutManager.LayoutType.HORIZONTAL);
                    break;
                case 1:
                    layoutManager.setLayout(LayoutManager.LayoutType.VERTICAL);
                    break;
                case 2:
                    layoutManager.setLayoutRequestOnly();
                    break;
                case 3:
                    layoutManager.setLayoutResponseOnly();
                    break;
                default:
                    break;
            }
        });
        layoutLabel = new JLabel(I18nManager.tr("toolbar.layout.label"));
        rightPanel.add(layoutLabel);
        rightPanel.add(layoutComboBox);

        toolBar.add(leftPanel, BorderLayout.WEST);
        toolBar.add(rightPanel, BorderLayout.EAST);

        return toolBar;
    }

    /**
     * 构建布局下拉框选项（从资源读取当前语言文本）
     */
    private String[] buildLayoutItems() {
        return new String[]{
            I18nManager.tr("toolbar.layout.horizontal"),
            I18nManager.tr("toolbar.layout.vertical"),
            I18nManager.tr("toolbar.layout.requestOnly"),
            I18nManager.tr("toolbar.layout.responseOnly")
        };
    }

    /**
     * 语言变更时刷新工具栏所有文本
     */
    private void refreshTexts() {
        // 全局工具栏标签
        normalModeLabel.setText(I18nManager.tr("toolbar.mode.normal"));
        privilegeModeLabel.setText(I18nManager.tr("toolbar.mode.privilege"));
        debugNormalLabel.setText(I18nManager.tr("toolbar.debug.normal"));
        debugModeLabel.setText(I18nManager.tr("toolbar.debug.mode"));
        gcOffLabel.setText(I18nManager.tr("toolbar.gc.manual"));
        gcOnLabel.setText(I18nManager.tr("toolbar.gc.auto"));

        // tooltip
        String modeTooltip = I18nManager.tr("toolbar.mode.tooltip");
        normalModeLabel.setToolTipText(modeTooltip);
        modeToggleButton.setToolTipText(modeTooltip);
        privilegeModeLabel.setToolTipText(modeTooltip);

        String debugTooltip = I18nManager.tr("toolbar.debug.tooltip");
        debugNormalLabel.setToolTipText(debugTooltip);
        debugToggleButton.setToolTipText(debugTooltip);
        debugModeLabel.setToolTipText(debugTooltip);

        String gcTooltip = I18nManager.tr("toolbar.gc.tooltip");
        gcOffLabel.setToolTipText(gcTooltip);
        gcToggleButton.setToolTipText(gcTooltip);
        gcOnLabel.setToolTipText(gcTooltip);

        String langTooltip = I18nManager.tr("toolbar.language.tooltip");
        languageZhLabel.setToolTipText(langTooltip);
        languageToggleButton.setToolTipText(langTooltip);
        languageEnLabel.setToolTipText(langTooltip);

        // 清空报文按钮
        if (clearAllBtn != null) {
            clearAllBtn.setText(I18nManager.tr("request.list.clearAll"));
            clearAllBtn.setToolTipText(I18nManager.tr("request.list.clearAll.tooltip"));
        }

        // 编辑区工具栏
        if (similarityCalcBtn != null) {
            similarityCalcBtn.setText(I18nManager.tr("toolbar.similarity"));
            similarityCalcBtn.setToolTipText(I18nManager.tr("toolbar.similarity.tooltip"));
        }
        if (layoutLabel != null) {
            layoutLabel.setText(I18nManager.tr("toolbar.layout.label"));
        }
        if (layoutComboBox != null) {
            layoutComboBox.setToolTipText(I18nManager.tr("toolbar.layout.tooltip"));
            // 重建下拉项文本，保持选中索引不变
            int selectedIndex = layoutComboBox.getSelectedIndex();
            layoutComboBox.setModel(new DefaultComboBoxModel<>(buildLayoutItems()));
            if (selectedIndex >= 0 && selectedIndex < layoutComboBox.getItemCount()) {
                layoutComboBox.setSelectedIndex(selectedIndex);
            }
        }

        // 触发布局重算，适应文本长度变化
        if (mainPanel != null) {
            mainPanel.revalidate();
            mainPanel.repaint();
        }
    }

    /**
     * 构建编辑区控制面板（已废弃，保留以兼容）
     * @deprecated 使用 {@link #buildGlobalToolBar()} 和 {@link #buildMessageEditorToolBar()} 替代
     */
    @Deprecated
    public JPanel build() {
        return buildMessageEditorToolBar();
    }
}

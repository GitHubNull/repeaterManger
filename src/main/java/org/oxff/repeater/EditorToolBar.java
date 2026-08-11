package org.oxff.repeater;

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

    public EditorToolBar(RequestDispatchHandler dispatchHandler,
                         LayoutManager layoutManager, JPanel mainPanel) {
        this.dispatchHandler = dispatchHandler;
        this.layoutManager = layoutManager;
        this.mainPanel = mainPanel;

        // 创建组件实例（供外部引用）
        this.modeToggleButton = new SwitchButton();
        this.normalModeLabel = new JLabel("普通模式");
        this.privilegeModeLabel = new JLabel("权限测试");
        this.debugToggleButton = new SwitchButton();
        this.debugNormalLabel = new JLabel("正常");
        this.debugModeLabel = new JLabel("调试");
        this.gcToggleButton = new SwitchButton();
        this.gcOffLabel = new JLabel("手动GC");
        this.gcOnLabel = new JLabel("自动GC");
        this.languageToggleButton = new SwitchButton();
        this.languageZhLabel = new JLabel("中文");
        this.languageEnLabel = new JLabel("英文");
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
        normalModeLabel.setToolTipText("切换普通模式/权限测试模式 — 开启后从右键菜单发送的请求将自动进行越权重放");
        globalToolBar.add(normalModeLabel);

        modeToggleButton.setToolTipText("切换普通模式/权限测试模式 — 开启后从右键菜单发送的请求将自动进行越权重放");
        modeToggleButton.addActionListener(e -> {
            boolean selected = modeToggleButton.isSelected();
            dispatchHandler.setPrivilegeTestMode(selected);
            LogManager.getInstance().printOutput("[*] 权限测试模式: " + (selected ? "已开启" : "已关闭"));
        });
        globalToolBar.add(modeToggleButton);

        privilegeModeLabel.setToolTipText("切换普通模式/权限测试模式 — 开启后从右键菜单发送的请求将自动进行越权重放");
        globalToolBar.add(privilegeModeLabel);
        globalToolBar.add(new JSeparator(SwingConstants.VERTICAL));

        // 调试切换
        debugNormalLabel.setToolTipText("切换正常模式/调试模式 — 调试模式会在日志中输出判决引擎详细计算过程");
        globalToolBar.add(debugNormalLabel);

        debugToggleButton.setToolTipText("切换正常模式/调试模式 — 调试模式会在日志中输出判决引擎详细计算过程");
        debugToggleButton.addActionListener(e -> {
            boolean selected = debugToggleButton.isSelected();
            LogManager.getInstance().setJudgmentDebugEnabled(selected);
            LogManager.getInstance().printOutput("[*] 判决调试模式: " + (selected ? "已开启" : "已关闭"));
        });
        globalToolBar.add(debugToggleButton);

        debugModeLabel.setToolTipText("切换正常模式/调试模式 — 调试模式会在日志中输出判决引擎详细计算过程");
        globalToolBar.add(debugModeLabel);
        globalToolBar.add(new JSeparator(SwingConstants.VERTICAL));

        // GC切换
        gcOffLabel.setToolTipText("切换手动GC/自动GC — 开启后每隔30秒自动触发一次垃圾回收");
        globalToolBar.add(gcOffLabel);

        gcToggleButton.setToolTipText("切换手动GC/自动GC — 开启后每隔30秒自动触发一次垃圾回收");
        gcToggleButton.addActionListener(e -> {
            boolean selected = gcToggleButton.isSelected();
            LogManager.getInstance().setAutoGcEnabled(selected);
            LogManager.getInstance().printOutput("[*] 自动GC: " + (selected ? "已开启" : "已关闭"));
        });
        globalToolBar.add(gcToggleButton);

        gcOnLabel.setToolTipText("切换手动GC/自动GC — 开启后每隔30秒自动触发一次垃圾回收");
        globalToolBar.add(gcOnLabel);
        globalToolBar.add(new JSeparator(SwingConstants.VERTICAL));

        // 语言切换（新增，功能待实现）：左侧中文、右侧英文，默认中文（开关关闭状态）
        languageZhLabel.setToolTipText("切换界面语言 / Switch Language");
        globalToolBar.add(languageZhLabel);

        languageToggleButton.setToolTipText("切换界面语言 / Switch Language");
        languageToggleButton.addActionListener(e -> {
            // UI占位：功能未实现，提示后恢复为默认中文状态
            JOptionPane.showMessageDialog(
                mainPanel,
                "语言切换功能开发中，敬请期待！\nLanguage switching feature is under development.",
                "功能提示 / Feature Notice",
                JOptionPane.INFORMATION_MESSAGE
            );
            languageToggleButton.setSelected(false);
            LogManager.getInstance().printOutput("[*] 语言切换: 功能开发中，当前保持中文");
        });
        globalToolBar.add(languageToggleButton);

        languageEnLabel.setToolTipText("切换界面语言 / Switch Language");
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
        JButton similarityCalcBtn = new JButton("相似度计算");
        similarityCalcBtn.setToolTipText("打开相似度计算工具，比较两个HTTP报文的相似度");
        similarityCalcBtn.addActionListener(e -> {
            SimilarityCalculatorDialog dialog = new SimilarityCalculatorDialog(
                (Frame) SwingUtilities.getWindowAncestor(mainPanel));
            dialog.setVisible(true);
        });
        leftPanel.add(similarityCalcBtn);

        // 右侧：布局选择
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 2));
        JComboBox<String> layoutComboBox = new JComboBox<>(new String[]{"左右布局", "上下布局", "仅请求", "仅响应"});
        layoutComboBox.setToolTipText("切换请求和响应的布局方式");
        layoutComboBox.addActionListener(e -> {
            String selectedLayout = (String) layoutComboBox.getSelectedItem();
            if ("左右布局".equals(selectedLayout)) {
                layoutManager.setLayout(LayoutManager.LayoutType.HORIZONTAL);
            } else if ("上下布局".equals(selectedLayout)) {
                layoutManager.setLayout(LayoutManager.LayoutType.VERTICAL);
            } else if ("仅请求".equals(selectedLayout)) {
                layoutManager.setLayoutRequestOnly();
            } else if ("仅响应".equals(selectedLayout)) {
                layoutManager.setLayoutResponseOnly();
            }
        });
        rightPanel.add(new JLabel("布局："));
        rightPanel.add(layoutComboBox);

        toolBar.add(leftPanel, BorderLayout.WEST);
        toolBar.add(rightPanel, BorderLayout.EAST);

        return toolBar;
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

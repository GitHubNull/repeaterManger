package org.oxff.repeater;

import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.ui.*;
import org.oxff.repeater.ui.editor.BurpRequestPanel;
import org.oxff.repeater.ui.editor.BurpResponsePanel;
import org.oxff.repeater.ui.layout.LayoutManager;

import javax.swing.*;
import java.awt.*;

/**
 * 编辑区工具栏构建器
 * 从 RepeaterManagerUI 中提取，负责构建编辑区域顶部的控制面板
 */
public class EditorToolBar {

    private final BurpRequestPanel requestPanel;
    private final BurpResponsePanel responsePanel;
    private final StatusPanel statusPanel;
    private final RequestDispatchHandler dispatchHandler;
    private final LayoutManager layoutManager;
    private final JPanel mainPanel;
    private final Runnable onNewRequest;

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

    public EditorToolBar(BurpRequestPanel requestPanel, BurpResponsePanel responsePanel,
                         StatusPanel statusPanel, RequestDispatchHandler dispatchHandler,
                         LayoutManager layoutManager, JPanel mainPanel,
                         Runnable onNewRequest) {
        this.requestPanel = requestPanel;
        this.responsePanel = responsePanel;
        this.statusPanel = statusPanel;
        this.dispatchHandler = dispatchHandler;
        this.layoutManager = layoutManager;
        this.mainPanel = mainPanel;
        this.onNewRequest = onNewRequest;

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
    }

    /**
     * 构建编辑区控制面板
     */
    public JPanel build() {
        JPanel controlPanel = new JPanel(new BorderLayout());

        // 左侧工具按钮区
        JPanel leftToolPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton newRequestButton = new JButton("新建请求");
        newRequestButton.setToolTipText("创建新的空白请求");
        newRequestButton.addActionListener(e -> onNewRequest.run());
        leftToolPanel.add(newRequestButton);

        JButton clearButton = new JButton("清空");
        clearButton.setToolTipText("清空当前请求和响应内容");
        clearButton.addActionListener(e -> {
            requestPanel.clear();
            responsePanel.clear();
            statusPanel.clear();
        });
        leftToolPanel.add(clearButton);

        leftToolPanel.add(new JSeparator(SwingConstants.VERTICAL));

        // 普通模式标签 + 切换开关 + 权限测试标签
        normalModeLabel.setToolTipText("切换普通模式/权限测试模式 — 开启后从右键菜单发送的请求将自动进行越权重放");
        leftToolPanel.add(normalModeLabel);

        modeToggleButton.setToolTipText("切换普通模式/权限测试模式 — 开启后从右键菜单发送的请求将自动进行越权重放");
        modeToggleButton.addActionListener(e -> {
            boolean selected = modeToggleButton.isSelected();
            dispatchHandler.setPrivilegeTestMode(selected);
            LogManager.getInstance().printOutput("[*] 权限测试模式: " + (selected ? "已开启" : "已关闭"));
        });
        leftToolPanel.add(modeToggleButton);

        privilegeModeLabel.setToolTipText("切换普通模式/权限测试模式 — 开启后从右键菜单发送的请求将自动进行越权重放");
        leftToolPanel.add(privilegeModeLabel);

        leftToolPanel.add(new JSeparator(SwingConstants.VERTICAL));

        // 相似度计算按钮
        JButton similarityCalcBtn = new JButton("相似度计算");
        similarityCalcBtn.setToolTipText("打开相似度计算工具，比较两个HTTP报文的相似度");
        similarityCalcBtn.addActionListener(e -> {
            SimilarityCalculatorDialog dialog = new SimilarityCalculatorDialog(
                (Frame) SwingUtilities.getWindowAncestor(mainPanel));
            dialog.setVisible(true);
        });
        leftToolPanel.add(similarityCalcBtn);

        leftToolPanel.add(new JSeparator(SwingConstants.VERTICAL));

        // 判决调试开关
        debugNormalLabel.setToolTipText("切换正常模式/调试模式 — 调试模式会在日志中输出判决引擎详细计算过程");
        leftToolPanel.add(debugNormalLabel);

        debugToggleButton.setToolTipText("切换正常模式/调试模式 — 调试模式会在日志中输出判决引擎详细计算过程");
        debugToggleButton.addActionListener(e -> {
            boolean selected = debugToggleButton.isSelected();
            LogManager.getInstance().setJudgmentDebugEnabled(selected);
            LogManager.getInstance().printOutput("[*] 判决调试模式: " + (selected ? "已开启" : "已关闭"));
        });
        leftToolPanel.add(debugToggleButton);

        debugModeLabel.setToolTipText("切换正常模式/调试模式 — 调试模式会在日志中输出判决引擎详细计算过程");
        leftToolPanel.add(debugModeLabel);

        leftToolPanel.add(new JSeparator(SwingConstants.VERTICAL));

        // 自动GC开关
        gcOffLabel.setToolTipText("切换手动GC/自动GC — 开启后每隔30秒自动触发一次垃圾回收");
        leftToolPanel.add(gcOffLabel);

        gcToggleButton.setToolTipText("切换手动GC/自动GC — 开启后每隔30秒自动触发一次垃圾回收");
        gcToggleButton.addActionListener(e -> {
            boolean selected = gcToggleButton.isSelected();
            LogManager.getInstance().setAutoGcEnabled(selected);
            LogManager.getInstance().printOutput("[*] 自动GC: " + (selected ? "已开启" : "已关闭"));
        });
        leftToolPanel.add(gcToggleButton);

        gcOnLabel.setToolTipText("切换手动GC/自动GC — 开启后每隔30秒自动触发一次垃圾回收");
        leftToolPanel.add(gcOnLabel);

        // 右侧布局控制区
        JPanel rightToolPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));

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

        rightToolPanel.add(new JLabel("布局："));
        rightToolPanel.add(layoutComboBox);

        controlPanel.add(leftToolPanel, BorderLayout.WEST);
        controlPanel.add(rightToolPanel, BorderLayout.EAST);

        return controlPanel;
    }
}

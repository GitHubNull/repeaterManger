package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.report.ReportContainerWriter;
import org.oxff.repeater.privilege.report.ReportExporter;

import javax.swing.*;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.html.StyleSheet;
import java.awt.*;

/**
 * 权限测试配置面板（第4个Tab）
 * 仅包含配置项，报文重放和结果查看复用"请求管理"Tab
 */
public class PrivilegeTestPanel extends JPanel {

    private static final String REPORT_CSS =
              "body { font-family: sans-serif; font-size: 13px; margin: 0; padding: 0; background: transparent; }"
            + "p { margin: 2px 0; }"
            + "b { font-weight: bold; }"
            + ".warning { color: #d32f2f; }";

    private final JTabbedPane innerTabbedPane;
    private final ScopeConfigTab scopeConfigTab;
    private final SessionConfigTab sessionConfigTab;

    public PrivilegeTestPanel() {
        super(new BorderLayout());

        innerTabbedPane = new JTabbedPane();

        // 会话配置子Tab
        sessionConfigTab = new SessionConfigTab();
        innerTabbedPane.addTab("会话配置", sessionConfigTab);

        // 判决规则子Tab（Phase 2）
        JudgmentRuleConfigTab judgmentRuleConfigTab = new JudgmentRuleConfigTab();
        innerTabbedPane.addTab("判决规则", judgmentRuleConfigTab);

        // Scope子Tab
        scopeConfigTab = new ScopeConfigTab();
        innerTabbedPane.addTab("Scope", scopeConfigTab);

        // 去重配置子Tab
        DedupConfigTab dedupConfigTab = new DedupConfigTab();
        innerTabbedPane.addTab("去重配置", dedupConfigTab);

        // 报告导出子Tab
        JPanel reportExportPanel = createReportExportPanel();
        innerTabbedPane.addTab("报告导出", reportExportPanel);

        add(innerTabbedPane, BorderLayout.CENTER);
    }

    /**
     * 创建一个支持HTML渲染的JEditorPane，用于替代JLabel的HTML渲染
     * （Burp Suite的L&F环境下JLabel的HTML渲染可能失效）
     */
    private JEditorPane createHtmlLabel(String htmlBody) {
        JEditorPane pane = new JEditorPane();
        pane.setContentType("text/html");
        pane.setEditable(false);
        pane.setFocusable(false);
        pane.setOpaque(false);

        HTMLEditorKit kit = new HTMLEditorKit();
        StyleSheet styleSheet = kit.getStyleSheet();
        styleSheet.addRule(REPORT_CSS);
        pane.setEditorKit(kit);

        pane.setText("<html><body>" + htmlBody + "</body></html>");
        pane.setCaretPosition(0);

        // 使JEditorPane在布局中表现为标签行为（不抢焦点、背景透明）
        pane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        pane.setFont(new Font("SansSerif", Font.PLAIN, 13));

        return pane;
    }

    private JPanel createReportExportPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // row 0: 标题
        JLabel titleLabel = new JLabel("越权测试报告导出");
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 16));
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        panel.add(titleLabel, gbc);

        // row 1: 说明
        JEditorPane descPane = createHtmlLabel(
                "<p>生成专业的越权测试报告，包含完整的请求/响应详情、<br>"
              + "判决结果、cURL命令和Postman导入片段，方便与开发人员沟通复现。</p>");
        gbc.gridy = 1;
        panel.add(descPane, gbc);

        // row 2: 格式选择
        gbc.gridwidth = 1;
        gbc.gridy = 2;
        panel.add(new JLabel("报告格式:"), gbc);

        JRadioButton htmlRadio = new JRadioButton("HTML", true);
        JRadioButton mdRadio = new JRadioButton("Markdown");
        JRadioButton pdfRadio = new JRadioButton("PDF");

        ButtonGroup formatGroup = new ButtonGroup();
        formatGroup.add(htmlRadio);
        formatGroup.add(mdRadio);
        formatGroup.add(pdfRadio);

        JPanel radioPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        radioPanel.add(htmlRadio);
        radioPanel.add(mdRadio);
        radioPanel.add(pdfRadio);
        gbc.gridx = 1;
        panel.add(radioPanel, gbc);

        // row 3: 输出模式选择
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 1;
        panel.add(new JLabel("输出模式:"), gbc);

        JRadioButton encryptedRadio = new JRadioButton("加密+压缩 (推荐)", true);
        JRadioButton compressedRadio = new JRadioButton("仅压缩");
        JRadioButton plainRadio = new JRadioButton("明文 (不推荐)");

        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(encryptedRadio);
        modeGroup.add(compressedRadio);
        modeGroup.add(plainRadio);

        JPanel modePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        modePanel.add(encryptedRadio);
        modePanel.add(compressedRadio);
        modePanel.add(plainRadio);
        gbc.gridx = 1;
        panel.add(modePanel, gbc);

        // row 3.5: 输出模式说明
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.gridwidth = 2;
        JEditorPane modeDescPane = createHtmlLabel(
                "<p>加密+压缩：生成.ermr文件，需密码解密查看 | 仅压缩：生成.ermr文件，无需密码 | 明文：原始格式文件</p>");
        panel.add(modeDescPane, gbc);

        // row 5: 按钮区（生成 + 解密）
        gbc.gridy = 5;
        gbc.gridwidth = 2;
        gbc.anchor = GridBagConstraints.CENTER;

        JButton generateButton = new JButton("生成报告");
        generateButton.setPreferredSize(new Dimension(140, 32));
        generateButton.addActionListener(e -> {
            String format;
            if (htmlRadio.isSelected()) {
                format = "html";
            } else if (mdRadio.isSelected()) {
                format = "md";
            } else {
                format = "pdf";
            }

            ReportContainerWriter.EncryptionMode encryptionMode;
            if (encryptedRadio.isSelected()) {
                encryptionMode = ReportContainerWriter.EncryptionMode.ENCRYPTED_COMPRESSED;
            } else if (compressedRadio.isSelected()) {
                encryptionMode = ReportContainerWriter.EncryptionMode.COMPRESSED_ONLY;
            } else {
                encryptionMode = ReportContainerWriter.EncryptionMode.PLAIN;
            }

            ReportExporter exporter = new ReportExporter(this);
            exporter.export(format, encryptionMode);
        });

        JButton decryptButton = new JButton("解密报告");
        decryptButton.setPreferredSize(new Dimension(140, 32));
        decryptButton.addActionListener(e -> {
            ReportExporter.decryptReportFile(this);
        });

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 20, 0));
        buttonPanel.add(generateButton);
        buttonPanel.add(decryptButton);
        panel.add(buttonPanel, gbc);

        // row 6: 格式说明
        gbc.gridy = 6;
        gbc.anchor = GridBagConstraints.WEST;
        JEditorPane formatDescPane = createHtmlLabel(
                "<b>HTML</b> — 自包含网页报告，样式美观，支持折叠展开，可直接打印为PDF<br>"
              + "<b>Markdown</b> — 纯文本标记格式，适合存入Git仓库或文档系统<br>"
              + "<b>PDF</b> — 原生PDF文件，适合正式报告分发");
        panel.add(formatDescPane, gbc);

        // row 7: 警告
        gbc.gridy = 7;
        JEditorPane warningPane = createHtmlLabel(
                "<p class='warning'>⚠ 报告可能包含敏感字段数据（Bearer Token、Session Cookie等），请妥善保管导出的文件。<br>"
              + "加密模式的报告文件(.ermr)需要密码才能查看，请妥善保管密码。</p>");
        panel.add(warningPane, gbc);

        return panel;
    }

    /**
     * 同步ScopeConfigTab的autoTestCheckbox状态到ScopeManager当前值
     * 供RepeaterManagerUI模式变更监听器调用：越权模式按钮切换时联动代理监听器，
     * ScopeConfigTab的复选框需同步反映最新状态
     */
    public void syncScopeConfigAutoTestState() {
        if (scopeConfigTab != null) {
            scopeConfigTab.syncAutoTestState();
        }
    }

    /**
     * 刷新会话配置数据（用户会话表格等）
     * 供BurpExtender在解析用户会话后调用
     */
    public void refreshSessionConfigData() {
        if (sessionConfigTab != null) {
            sessionConfigTab.refreshData();
        }
    }
}

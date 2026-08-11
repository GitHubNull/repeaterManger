package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.i18n.I18nManager;
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

    // 报告导出面板组件
    private JLabel reportTitleLabel;
    private JEditorPane reportDescPane;
    private JLabel reportFormatLabel;
    private JRadioButton encryptedRadio;
    private JRadioButton compressedRadio;
    private JRadioButton plainRadio;
    private JLabel reportModeLabel;
    private JEditorPane reportModeDescPane;
    private JButton generateButton;
    private JButton decryptButton;
    private JEditorPane reportFormatDescPane;
    private JEditorPane reportWarningPane;

    public PrivilegeTestPanel() {
        super(new BorderLayout());

        innerTabbedPane = new JTabbedPane();

        // 会话配置子Tab
        sessionConfigTab = new SessionConfigTab();
        innerTabbedPane.addTab(I18nManager.tr("privilege.tab.session"), sessionConfigTab);

        // 判决规则子Tab（Phase 2）
        JudgmentRuleConfigTab judgmentRuleConfigTab = new JudgmentRuleConfigTab();
        innerTabbedPane.addTab(I18nManager.tr("privilege.tab.judgment"), judgmentRuleConfigTab);

        // Scope子Tab
        scopeConfigTab = new ScopeConfigTab();
        innerTabbedPane.addTab(I18nManager.tr("privilege.tab.scope"), scopeConfigTab);

        // 去重配置子Tab
        DedupConfigTab dedupConfigTab = new DedupConfigTab();
        innerTabbedPane.addTab(I18nManager.tr("privilege.tab.dedup"), dedupConfigTab);

        // 测试信息配置子Tab
        TestInfoConfigTab testInfoConfigTab = new TestInfoConfigTab();
        innerTabbedPane.addTab(I18nManager.tr("privilege.tab.testInfo"), testInfoConfigTab);

        // 报告导出子Tab
        JPanel reportExportPanel = createReportExportPanel();
        innerTabbedPane.addTab(I18nManager.tr("privilege.tab.report"), reportExportPanel);

        add(innerTabbedPane, BorderLayout.CENTER);

        I18nManager.getInstance().addLocaleChangeListener(this::refreshTexts);
    }

    /**
     * 语言切换时刷新Tab标题和报告导出面板文本
     */
    private void refreshTexts() {
        innerTabbedPane.setTitleAt(0, I18nManager.tr("privilege.tab.session"));
        innerTabbedPane.setTitleAt(1, I18nManager.tr("privilege.tab.judgment"));
        innerTabbedPane.setTitleAt(2, I18nManager.tr("privilege.tab.scope"));
        innerTabbedPane.setTitleAt(3, I18nManager.tr("privilege.tab.dedup"));
        innerTabbedPane.setTitleAt(4, I18nManager.tr("privilege.tab.testInfo"));
        innerTabbedPane.setTitleAt(5, I18nManager.tr("privilege.tab.report"));

        if (reportTitleLabel != null) {
            reportTitleLabel.setText(I18nManager.tr("report.title"));
            reportDescPane.setText(wrapHtml(I18nManager.tr("report.desc")));
            reportFormatLabel.setText(I18nManager.tr("report.format"));
            reportModeLabel.setText(I18nManager.tr("report.mode"));
            encryptedRadio.setText(I18nManager.tr("report.mode.encrypted"));
            compressedRadio.setText(I18nManager.tr("report.mode.compressed"));
            plainRadio.setText(I18nManager.tr("report.mode.plain"));
            reportModeDescPane.setText(wrapHtml(I18nManager.tr("report.mode.desc")));
            generateButton.setText(I18nManager.tr("report.generate"));
            decryptButton.setText(I18nManager.tr("report.decrypt"));
            reportFormatDescPane.setText(wrapHtml(I18nManager.tr("report.format.desc")));
            reportWarningPane.setText(wrapHtml(I18nManager.tr("report.warning")));
        }
    }

    /**
     * 包装HTML内容为完整的HTML文档结构
     */
    private String wrapHtml(String body) {
        return "<html><body>" + body + "</body></html>";
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

        pane.setText(wrapHtml(htmlBody));
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
        reportTitleLabel = new JLabel(I18nManager.tr("report.title"));
        reportTitleLabel.setFont(new Font("SansSerif", Font.BOLD, 16));
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        panel.add(reportTitleLabel, gbc);

        // row 1: 说明
        reportDescPane = createHtmlLabel(I18nManager.tr("report.desc"));
        gbc.gridy = 1;
        panel.add(reportDescPane, gbc);

        // row 2: 格式选择
        gbc.gridwidth = 1;
        gbc.gridy = 2;
        reportFormatLabel = new JLabel(I18nManager.tr("report.format"));
        panel.add(reportFormatLabel, gbc);

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
        reportModeLabel = new JLabel(I18nManager.tr("report.mode"));
        panel.add(reportModeLabel, gbc);

        encryptedRadio = new JRadioButton(I18nManager.tr("report.mode.encrypted"), true);
        compressedRadio = new JRadioButton(I18nManager.tr("report.mode.compressed"));
        plainRadio = new JRadioButton(I18nManager.tr("report.mode.plain"));

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
        reportModeDescPane = createHtmlLabel(I18nManager.tr("report.mode.desc"));
        panel.add(reportModeDescPane, gbc);

        // row 5: 按钮区（生成 + 解密）
        gbc.gridy = 5;
        gbc.gridwidth = 2;
        gbc.anchor = GridBagConstraints.CENTER;

        generateButton = new JButton(I18nManager.tr("report.generate"));
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

        decryptButton = new JButton(I18nManager.tr("report.decrypt"));
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
        reportFormatDescPane = createHtmlLabel(I18nManager.tr("report.format.desc"));
        panel.add(reportFormatDescPane, gbc);

        // row 7: 警告
        gbc.gridy = 7;
        reportWarningPane = createHtmlLabel(I18nManager.tr("report.warning"));
        panel.add(reportWarningPane, gbc);

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

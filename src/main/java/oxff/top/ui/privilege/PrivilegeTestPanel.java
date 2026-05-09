package oxff.top.ui.privilege;

import oxff.top.privilege.report.ReportExporter;

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

    public PrivilegeTestPanel() {
        super(new BorderLayout());

        innerTabbedPane = new JTabbedPane();

        // 会话配置子Tab
        SessionConfigTab sessionConfigTab = new SessionConfigTab();
        innerTabbedPane.addTab("会话配置", sessionConfigTab);

        // 判决规则子Tab（Phase 2）
        JudgmentRuleConfigTab judgmentRuleConfigTab = new JudgmentRuleConfigTab();
        innerTabbedPane.addTab("判决规则", judgmentRuleConfigTab);

        // Scope子Tab
        ScopeConfigTab scopeConfigTab = new ScopeConfigTab();
        innerTabbedPane.addTab("Scope", scopeConfigTab);

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

        // 标题
        JLabel titleLabel = new JLabel("越权测试报告导出");
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 16));
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        panel.add(titleLabel, gbc);

        // 说明 - 使用JEditorPane替代JLabel的HTML渲染
        JEditorPane descPane = createHtmlLabel(
                "<p>生成专业的越权测试报告，包含完整的请求/响应详情、<br>"
              + "判决结果、cURL命令和Postman导入片段，方便与开发人员沟通复现。</p>");
        gbc.gridy = 1;
        panel.add(descPane, gbc);

        // 格式选择
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

        // 生成按钮
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
            ReportExporter exporter = new ReportExporter(this);
            exporter.export(format);
        });

        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 2;
        gbc.anchor = GridBagConstraints.CENTER;
        panel.add(generateButton, gbc);

        // 格式说明 - 使用JEditorPane替代JLabel的HTML渲染
        gbc.gridy = 4;
        gbc.anchor = GridBagConstraints.WEST;
        JEditorPane formatDescPane = createHtmlLabel(
                "<b>HTML</b> — 自包含网页报告，样式美观，支持折叠展开，可直接打印为PDF<br>"
              + "<b>Markdown</b> — 纯文本标记格式，适合存入Git仓库或文档系统<br>"
              + "<b>PDF</b> — 原生PDF文件，适合正式报告分发");
        panel.add(formatDescPane, gbc);

        // 警告 - 使用JEditorPane替代JLabel的HTML渲染
        gbc.gridy = 5;
        JEditorPane warningPane = createHtmlLabel(
                "<p class='warning'>⚠ 报告可能包含敏感令牌数据（Bearer Token、Session Cookie等），请妥善保管导出的文件。</p>");
        panel.add(warningPane, gbc);

        return panel;
    }
}

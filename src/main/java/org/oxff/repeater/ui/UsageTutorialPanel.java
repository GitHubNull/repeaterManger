package org.oxff.repeater.ui;

import org.commonmark.Extension;
import org.commonmark.ext.gfm.tables.TablesExtension;
import org.commonmark.node.Node;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;
import org.oxff.repeater.i18n.I18nManager;

import javax.swing.*;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.html.StyleSheet;
import java.awt.*;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * 使用教程面板 - 支持中英文切换和快速入门/详细教程切换
 * <p>
 * 使用 CommonMark 库将 Markdown 转换为 HTML，支持 GFM 表格扩展。
 * 面板内语言切换与全局语言切换联动。
 */
public class UsageTutorialPanel extends JPanel {

    private enum Language { ZH, EN }
    private enum DocType { QUICK, DETAILED }

    private static final Parser PARSER;
    private static final HtmlRenderer RENDERER;
    private static final String CSS;

    static {
        List<Extension> extensions = List.of(TablesExtension.create());
        PARSER = Parser.builder().extensions(extensions).build();
        RENDERER = HtmlRenderer.builder().extensions(extensions).build();

        CSS = "body { font-family: sans-serif; font-size: 14px; padding: 15px; line-height: 1.6; }"
                + "h1 { font-size: 22px; color: #333; margin-top: 20px; margin-bottom: 10px; }"
                + "h2 { font-size: 18px; color: #444; margin-top: 18px; margin-bottom: 8px; }"
                + "h3 { font-size: 16px; color: #555; margin-top: 15px; margin-bottom: 6px; }"
                + "h4 { font-size: 15px; color: #555; margin-top: 12px; margin-bottom: 5px; }"
                + "h5 { font-size: 14px; color: #555; margin-top: 10px; margin-bottom: 4px; }"
                + "h6 { font-size: 13px; color: #666; margin-top: 10px; margin-bottom: 4px; }"
                + "p { margin: 8px 0; }"
                + "ul, ol { margin: 8px 0; padding-left: 25px; }"
                + "li { margin: 4px 0; }"
                + "blockquote { border-left: 3px solid #ccc; margin: 10px 0; padding: 5px 15px; color: #666; background: #f9f9f9; }"
                + "code { background: #f5f5f5; padding: 2px 5px; border-radius: 3px; font-family: monospace; font-size: 13px; }"
                + "pre { background: #f5f5f5; padding: 12px; border-radius: 4px; overflow-x: auto; }"
                + "pre code { background: transparent; padding: 0; }"
                + "a { color: #0066cc; text-decoration: none; }"
                + "a:hover { text-decoration: underline; }"
                + "hr { border: none; border-top: 1px solid #ddd; margin: 15px 0; }"
                + "table { border-collapse: collapse; margin: 10px 0; }"
                + "th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }"
                + "th { background: #f5f5f5; font-weight: bold; }"
                + "img { max-width: 100%; height: auto; }";
    }

    private Language currentLanguage = Language.ZH;
    private DocType currentDocType = DocType.QUICK;

    private JEditorPane editorPane;
    private JComboBox<String> languageCombo;
    private JComboBox<String> docTypeCombo;
    private JLabel languageLabel;
    private JLabel docTypeLabel;

    public UsageTutorialPanel() {
        super(new BorderLayout());
        // 初始化文档语言与全局语言一致
        currentLanguage = I18nManager.getInstance().isEnglish() ? Language.EN : Language.ZH;
        initUI();
        loadContent();

        // 注册全局语言变更监听：同步切换文档语言
        I18nManager.getInstance().addLocaleChangeListener(this::onGlobalLanguageChanged);
    }

    private void initUI() {
        // 顶部控制栏
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        controlPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        languageLabel = new JLabel(I18nManager.tr("tutorial.language"));
        controlPanel.add(languageLabel);
        // 语言名下拉项使用固有名称，不随界面语言变化
        languageCombo = new JComboBox<>(new String[]{"中文", "English"});
        languageCombo.setSelectedIndex(currentLanguage == Language.EN ? 1 : 0);
        languageCombo.addActionListener(e -> {
            currentLanguage = languageCombo.getSelectedIndex() == 1 ? Language.EN : Language.ZH;
            loadContent();
        });
        controlPanel.add(languageCombo);

        controlPanel.add(Box.createHorizontalStrut(20));

        docTypeLabel = new JLabel(I18nManager.tr("tutorial.doc"));
        controlPanel.add(docTypeLabel);
        docTypeCombo = new JComboBox<>(buildDocTypeItems());
        docTypeCombo.addActionListener(e -> {
            // 索引1=详细教程，与显示文本解耦
            currentDocType = docTypeCombo.getSelectedIndex() == 1 ? DocType.DETAILED : DocType.QUICK;
            loadContent();
        });
        controlPanel.add(docTypeCombo);

        add(controlPanel, BorderLayout.NORTH);

        // 内容显示区
        editorPane = new JEditorPane();
        editorPane.setContentType("text/html");
        editorPane.setEditable(false);
        editorPane.setCaretPosition(0);

        // 配置 HTML 样式
        HTMLEditorKit kit = new HTMLEditorKit();
        StyleSheet styleSheet = kit.getStyleSheet();
        styleSheet.addRule(CSS);
        editorPane.setEditorKit(kit);

        editorPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        editorPane.setFont(new Font("SansSerif", Font.PLAIN, 14));

        JScrollPane scrollPane = new JScrollPane(editorPane);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        add(scrollPane, BorderLayout.CENTER);
    }

    /**
     * 构建文档类型下拉项（从资源读取当前语言文本）
     */
    private static String[] buildDocTypeItems() {
        return new String[]{
            I18nManager.tr("tutorial.doc.quick"),
            I18nManager.tr("tutorial.doc.detailed")
        };
    }

    /**
     * 全局语言变更时同步切换文档语言
     */
    private void onGlobalLanguageChanged() {
        // 刷新面板标签文本
        languageLabel.setText(I18nManager.tr("tutorial.language"));
        docTypeLabel.setText(I18nManager.tr("tutorial.doc"));

        // 刷新文档类型下拉项（保持选中索引）
        int docIndex = docTypeCombo.getSelectedIndex();
        docTypeCombo.setModel(new DefaultComboBoxModel<>(buildDocTypeItems()));
        if (docIndex >= 0 && docIndex < docTypeCombo.getItemCount()) {
            docTypeCombo.setSelectedIndex(docIndex);
        }

        // 同步文档语言与全局语言
        Language targetLanguage = I18nManager.getInstance().isEnglish() ? Language.EN : Language.ZH;
        if (currentLanguage != targetLanguage) {
            currentLanguage = targetLanguage;
            languageCombo.setSelectedIndex(currentLanguage == Language.EN ? 1 : 0);
            loadContent();
        }

        revalidate();
        repaint();
    }

    private void loadContent() {
        String resourcePath = String.format("/doc/tutorials/usage_%s_%s.md",
                currentDocType == DocType.QUICK ? "quick" : "detailed",
                currentLanguage == Language.ZH ? "zh" : "en");

        try (InputStream is = getClass().getResourceAsStream(resourcePath)) {
            if (is == null) {
                editorPane.setText("<html><head><style>" + CSS + "</style></head><body>"
                        + "<p>" + I18nManager.tr("tutorial.load.failed", escapeHtml(resourcePath)) + "</p></body></html>");
                return;
            }
            String markdown = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            Node document = PARSER.parse(markdown);
            String bodyHtml = RENDERER.render(document);
            editorPane.setText("<html><head><style>" + CSS + "</style></head><body>" + bodyHtml + "</body></html>");
            editorPane.setCaretPosition(0);
        } catch (IOException e) {
            editorPane.setText("<html><head><style>" + CSS + "</style></head><body>"
                    + "<p>" + I18nManager.tr("tutorial.read.error", escapeHtml(e.getMessage())) + "</p></body></html>");
        }
    }

    private static String escapeHtml(String text) {
        return text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }
}

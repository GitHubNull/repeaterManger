package org.oxff.repeater.ui;

import org.commonmark.Extension;
import org.commonmark.ext.gfm.tables.TablesExtension;
import org.commonmark.node.Node;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;

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

    public UsageTutorialPanel() {
        super(new BorderLayout());
        initUI();
        loadContent();
    }

    private void initUI() {
        // 顶部控制栏
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        controlPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        controlPanel.add(new JLabel("语言:"));
        languageCombo = new JComboBox<>(new String[]{"中文", "English"});
        languageCombo.addActionListener(e -> {
            String selected = (String) languageCombo.getSelectedItem();
            currentLanguage = "English".equals(selected) ? Language.EN : Language.ZH;
            loadContent();
        });
        controlPanel.add(languageCombo);

        controlPanel.add(Box.createHorizontalStrut(20));

        controlPanel.add(new JLabel("文档:"));
        docTypeCombo = new JComboBox<>(new String[]{"快速入门", "详细教程"});
        docTypeCombo.addActionListener(e -> {
            String selected = (String) docTypeCombo.getSelectedItem();
            currentDocType = "详细教程".equals(selected) ? DocType.DETAILED : DocType.QUICK;
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

    private void loadContent() {
        String resourcePath = String.format("/doc/usage_%s_%s.md",
                currentDocType == DocType.QUICK ? "quick" : "detailed",
                currentLanguage == Language.ZH ? "zh" : "en");

        try (InputStream is = getClass().getResourceAsStream(resourcePath)) {
            if (is == null) {
                editorPane.setText("<html><head><style>" + CSS + "</style></head><body>"
                        + "<p>文档加载失败: " + escapeHtml(resourcePath) + "</p></body></html>");
                return;
            }
            String markdown = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            Node document = PARSER.parse(markdown);
            String bodyHtml = RENDERER.render(document);
            editorPane.setText("<html><head><style>" + CSS + "</style></head><body>" + bodyHtml + "</body></html>");
            editorPane.setCaretPosition(0);
        } catch (IOException e) {
            editorPane.setText("<html><head><style>" + CSS + "</style></head><body>"
                    + "<p>读取文档出错: " + escapeHtml(e.getMessage()) + "</p></body></html>");
        }
    }

    private static String escapeHtml(String text) {
        return text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }
}

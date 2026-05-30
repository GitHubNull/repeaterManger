package oxff.top.ui;

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import java.awt.*;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;

/**
 * 关于面板 - 展示项目元数据、版本信息和技术栈
 */
public class AboutPanel extends JPanel {

    private static final String VERSION = "2.20.1";
    private static final String AUTHOR = "githubnull";
    private static final String LICENSE = "Apache License 2.0";
    private static final String GITHUB_URL = "https://github.com/githubnull/repeater-manager";

    public AboutPanel() {
        super(new BorderLayout());
        initUI();
    }

    private void initUI() {
        JEditorPane editorPane = new JEditorPane();
        editorPane.setContentType("text/html");
        editorPane.setEditable(false);
        editorPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        editorPane.setFont(new Font("SansSerif", Font.PLAIN, 14));

        String html = buildAboutHtml();
        editorPane.setText(html);
        editorPane.setCaretPosition(0);

        editorPane.addHyperlinkListener(e -> {
            if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
                openUrl(e.getURL().toString());
            }
        });

        JScrollPane scrollPane = new JScrollPane(editorPane);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        add(scrollPane, BorderLayout.CENTER);
    }

    private String buildAboutHtml() {
        String template = loadTemplate("/templates/about/about.html");
        return template
                .replace("${VERSION}", VERSION)
                .replace("${AUTHOR}", AUTHOR)
                .replace("${LICENSE}", LICENSE)
                .replace("${GITHUB_URL}", GITHUB_URL);
    }

    private String loadTemplate(String resourcePath) {
        try (InputStream is = getClass().getResourceAsStream(resourcePath)) {
            if (is == null) {
                return "<html><body><p>无法加载关于页面模板。</p></body></html>";
            }
            byte[] bytes = is.readAllBytes();
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "<html><body><p>加载关于页面模板失败: " + e.getMessage() + "</p></body></html>";
        }
    }

    private void openUrl(String url) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(new URI(url));
            } else {
                JOptionPane.showMessageDialog(this,
                        "无法自动打开浏览器，请手动访问:\n" + url,
                        "打开链接", JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (IOException | URISyntaxException e) {
            JOptionPane.showMessageDialog(this,
                    "打开链接失败: " + e.getMessage() + "\n请手动访问:\n" + url,
                    "错误", JOptionPane.ERROR_MESSAGE);
        }
    }
}

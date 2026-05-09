package oxff.top.ui;

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import java.awt.*;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * 关于面板 - 展示项目元数据、版本信息和技术栈
 */
public class AboutPanel extends JPanel {

    private static final String VERSION = "2.5.0";
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
        return "<html>"
                + "<head><style>"
                + "body { font-family: sans-serif; padding: 30px; text-align: center; }"
                + "h1 { margin: 0 0 10px 0; }"
                + ".version { color: #666; font-size: 14px; margin-bottom: 20px; }"
                + ".info { margin: 5px 0; }"
                + "a { color: #0066cc; text-decoration: none; }"
                + "a:hover { text-decoration: underline; }"
                + ".desc { text-align: left; max-width: 600px; margin: 20px auto; line-height: 1.6; }"
                + ".deps { text-align: left; max-width: 600px; margin: 20px auto; }"
                + ".deps-title { font-weight: bold; margin-bottom: 10px; text-align: center; }"
                + "pre { background: #f5f5f5; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 13px; line-height: 1.5; }"
                + "hr { width: 300px; margin: 15px auto; }"
                + "</style></head>"
                + "<body>"
                + "<h1>Repeater Manager</h1>"
                + "<div class='version'>版本: v" + VERSION + "</div>"
                + "<hr>"
                + "<div class='info'>作者: " + AUTHOR + "</div>"
                + "<div class='info'>许可证: " + LICENSE + "</div>"
                + "<div class='info'><a href='" + GITHUB_URL + "'>GitHub 项目主页</a></div>"
                + "<div class='desc'>"
                + "<p>Repeater Manager 是一个为 Burp Suite Professional 设计的高级 HTTP 请求重放管理插件。</p>"
                + "<p>相比原生 Repeater，它提供了更强大的功能，包括请求的分类管理、响应历史自动记录与比对、"
                + "SQLite 本地持久化、内容去重存储、多条件高级搜索、API 规则提取、自动化越权测试、"
                + "多种格式导入导出（ERM 加密存档 / Postman Collection）以及定时自动保存防丢机制。</p>"
                + "<p>本插件特别适合安全测试人员和渗透测试专家使用，可有效提高 HTTP/HTTPS 请求测试的效率和组织性。</p>"
                + "</div>"
                + "<div class='deps'>"
                + "<div class='deps-title'>技术栈 / Dependencies</div>"
                + "<pre>"
                + "Montoya API          2025.12    - Burp Suite 现代扩展接口\n"
                + "RSyntaxTextArea      3.3.3      - 语法高亮编辑器\n"
                + "SQLite JDBC          3.42.0.0   - 本地数据持久化\n"
                + "HikariCP             5.0.1      - 数据库连接池\n"
                + "Apache Commons IO    2.11.0     - 文件操作工具\n"
                + "Apache Commons Lang  3.12.0     - 工具类\n"
                + "Gson                 2.10.1     - JSON 序列化\n"
                + "SnakeYAML            2.2        - YAML 序列化"
                + "</pre>"
                + "</div>"
                + "</body></html>";
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

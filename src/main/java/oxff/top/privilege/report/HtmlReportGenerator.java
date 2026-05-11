package oxff.top.privilege.report;

import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.Map;

/**
 * HTML 格式报告生成器
 * 使用 FreeMarker 模板引擎渲染，支持二进制内容智能渲染
 */
public class HtmlReportGenerator extends ReportGenerator {

    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    @Override
    public String getFileExtension() {
        return "html";
    }

    @Override
    public String generate(ReportData data) {
        try {
            Map<String, Object> model = new HashMap<>();
            model.put("title", data.getTitle());
            model.put("generatedAt", DATE_FORMAT.format(data.getGeneratedAt()));
            model.put("pluginVersion", data.getPluginVersion());
            model.put("summary", data.getSummary());
            model.put("sessionBreakdown", data.getSessionBreakdown());
            model.put("endpoints", data.getEndpoints());

            StringWriter writer = new StringWriter();
            FreeMarkerConfig.getInstance().getHtmlTemplate("html_report.ftl").process(model, writer);
            return writer.toString();
        } catch (Exception e) {
            throw new RuntimeException("HTML report generation failed: " + e.getMessage(), e);
        }
    }
}

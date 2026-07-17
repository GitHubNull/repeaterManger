package org.oxff.repeater.privilege.report;

import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.Map;

/**
 * Markdown 格式报告生成器
 * 使用 FreeMarker 模板引擎渲染，支持二进制内容智能渲染
 */
public class MarkdownReportGenerator extends ReportGenerator {

    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    @Override
    public String getFileExtension() {
        return "md";
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
            model.put("escalatedEndpoints", data.getEscalatedEndpoints());
            model.put("errorEndpoints", data.getErrorEndpoints());
            model.put("safeEndpoints", data.getSafeEndpoints());
            model.put("endpoints", data.getEndpoints());
            model.put("userInfoEntries", data.getUserInfoEntries());
            // 测试信息配置
            if (data.getTestInfoConfig() != null) {
                model.put("testInfoConfig", data.getTestInfoConfig());
                model.put("testInfoConfigScreenshots", data.getTestInfoConfigBase64Screenshots());
            }

            StringWriter writer = new StringWriter();
            FreeMarkerConfig.getInstance().getMdTemplate("md_report.ftl").process(model, writer);
            return writer.toString();
        } catch (Exception e) {
            throw new RuntimeException("Markdown 报告生成失败: " + e.getMessage(), e);
        }
    }
}

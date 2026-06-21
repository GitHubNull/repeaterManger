package org.oxff.repeater.privilege.report;

import freemarker.cache.ClassTemplateLoader;
import freemarker.core.PlainTextOutputFormat;
import freemarker.template.Configuration;
import freemarker.template.TemplateExceptionHandler;
import freemarker.template.Version;

import java.util.Locale;

/**
 * FreeMarker 模板引擎配置单例
 * 提供 HTML 和 Markdown 两个独立的 Configuration 实例
 */
public class FreeMarkerConfig {

    private static volatile FreeMarkerConfig instance;

    private final Configuration htmlConfig;
    private final Configuration mdConfig;

    private FreeMarkerConfig() {
        Version version = Configuration.VERSION_2_3_33;

        // HTML 配置：HTMLOutputFormat 自动转义
        htmlConfig = new Configuration(version);
        htmlConfig.setTemplateLoader(new ClassTemplateLoader(getClass(), "/templates/report"));
        htmlConfig.setOutputFormat(freemarker.core.HTMLOutputFormat.INSTANCE);
        htmlConfig.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);
        htmlConfig.setLogTemplateExceptions(false);
        htmlConfig.setLocale(Locale.US);

        // Markdown 配置：PlainTextOutputFormat 不做自动转义
        mdConfig = new Configuration(version);
        mdConfig.setTemplateLoader(new ClassTemplateLoader(getClass(), "/templates/report"));
        mdConfig.setOutputFormat(PlainTextOutputFormat.INSTANCE);
        mdConfig.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);
        mdConfig.setLogTemplateExceptions(false);
        mdConfig.setLocale(Locale.US);
    }

    public static FreeMarkerConfig getInstance() {
        if (instance == null) {
            synchronized (FreeMarkerConfig.class) {
                if (instance == null) {
                    instance = new FreeMarkerConfig();
                }
            }
        }
        return instance;
    }

    /**
     * 获取 HTML 模板
     */
    public freemarker.template.Template getHtmlTemplate(String name) throws Exception {
        return htmlConfig.getTemplate(name);
    }

    /**
     * 获取 Markdown 模板
     */
    public freemarker.template.Template getMdTemplate(String name) throws Exception {
        return mdConfig.getTemplate(name);
    }

    /**
     * 获取 HTML Configuration 实例
     */
    public Configuration getHtmlConfig() {
        return htmlConfig;
    }

    /**
     * 获取 Markdown Configuration 实例
     */
    public Configuration getMdConfig() {
        return mdConfig;
    }
}

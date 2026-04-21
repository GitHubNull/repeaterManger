package oxff.top.io;

import java.awt.Component;

/**
 * 数据导出器 - 统一导出调度器
 */
public class DataExporter {

    private final ErmArchiveWriter ermWriter;
    private final PostmanExporter postmanExporter;

    public DataExporter() {
        this.ermWriter = new ErmArchiveWriter();
        this.postmanExporter = new PostmanExporter();
    }

    /**
     * 导出到ERM存档格式
     */
    public boolean exportToErm(Component parent, boolean encrypted) {
        return ermWriter.export(parent, encrypted);
    }

    /**
     * 导出到Postman Collection v2.1.0格式
     */
    public boolean exportToPostman(Component parent) {
        return postmanExporter.export(parent);
    }
}

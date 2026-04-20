package oxff.top.io;

import java.awt.Component;

/**
 * 数据导出器 - 统一导出调度器
 */
public class DataExporter {

    private final SQLiteExporter sqliteExporter;
    private final CustomJsonExporter jsonExporter;
    private final PostmanExporter postmanExporter;

    public DataExporter() {
        this.sqliteExporter = new SQLiteExporter();
        this.jsonExporter = new CustomJsonExporter();
        this.postmanExporter = new PostmanExporter();
    }

    /**
     * 导出到SQLite3格式
     */
    public boolean exportToSQLite(Component parent) {
        return sqliteExporter.export(parent);
    }

    /**
     * 导出到自定义JSON格式
     */
    public boolean exportToJson(Component parent) {
        return jsonExporter.export(parent);
    }

    /**
     * 导出到Postman Collection v2.1.0格式
     */
    public boolean exportToPostman(Component parent) {
        return postmanExporter.export(parent);
    }
}

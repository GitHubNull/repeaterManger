package oxff.top.io;

import burp.BurpExtender;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Component;
import java.io.File;

/**
 * 数据导入器 - 统一导入调度器，支持自动格式检测
 */
public class DataImporter {

    private final SQLiteImporter sqliteImporter;
    private final PostmanImporter postmanImporter;

    public DataImporter() {
        this.sqliteImporter = new SQLiteImporter();
        this.postmanImporter = new PostmanImporter();
    }

    /**
     * 智能导入 - 自动检测文件格式并导入
     */
    public boolean smartImport(Component parent) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("导入数据文件");
        fileChooser.setFileFilter(new FileNameExtensionFilter(
            "支持的数据文件 (*.sqlite3, *.db, *.json)", "sqlite3", "db", "json"));

        int result = fileChooser.showOpenDialog(parent);
        if (result != JFileChooser.APPROVE_OPTION) {
            return false;
        }

        File selectedFile = fileChooser.getSelectedFile();
        if (!selectedFile.exists() || !selectedFile.isFile()) {
            JOptionPane.showMessageDialog(parent, "所选文件不存在", "导入错误", JOptionPane.ERROR_MESSAGE);
            return false;
        }

        // 自动检测格式
        FormatDetector.ImportFormat format = FormatDetector.detectFormat(selectedFile);
        BurpExtender.printOutput("[*] 检测到文件格式: " + format);

        switch (format) {
            case SQLITE3:
                return sqliteImporter.importFromFile(parent);
            case POSTMAN_V21:
                return postmanImporter.importFromFile(parent);
            case UNKNOWN:
            default:
                JOptionPane.showMessageDialog(parent,
                    "无法识别的文件格式。\n支持的格式: SQLite3 (.sqlite3, .db), Postman Collection v2.1 (.json)",
                    "格式错误", JOptionPane.ERROR_MESSAGE);
                return false;
        }
    }

    /**
     * 从SQLite数据库导入
     */
    public boolean importFromSQLite(Component parent) {
        return sqliteImporter.importFromFile(parent);
    }

    /**
     * 从Postman Collection导入
     */
    public boolean importFromPostman(Component parent) {
        return postmanImporter.importFromFile(parent);
    }
}

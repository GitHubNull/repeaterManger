package oxff.top.io;

import burp.BurpExtender;

import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Component;
import java.io.File;

/**
 * 数据导入器 - 统一导入调度器，支持自动格式检测
 */
public class DataImporter {

    private final ErmArchiveReader ermReader;
    private final PostmanImporter postmanImporter;

    public DataImporter() {
        this.ermReader = new ErmArchiveReader();
        this.postmanImporter = new PostmanImporter();
    }

    /**
     * 智能导入 - 自动检测文件格式并导入
     * 只弹出一次文件对话框，不再二次弹出
     */
    public boolean smartImport(Component parent) {
        File selectedFile = oxff.top.utils.FileChooserHelper.showOpenDialog(
                oxff.top.utils.FileChooserHelper.OP_ERM_IMPORT, "导入数据文件", parent,
                new FileNameExtensionFilter("支持的数据文件 (*.erm, *.json)", "erm", "json"));

        if (selectedFile == null) {
            return false;
        }

        if (!selectedFile.exists() || !selectedFile.isFile()) {
            JOptionPane.showMessageDialog(parent, "所选文件不存在", "导入错误", JOptionPane.ERROR_MESSAGE);
            return false;
        }

        // 自动检测格式
        FormatDetector.ImportFormat format = FormatDetector.detectFormat(selectedFile);
        BurpExtender.printOutput("[*] 检测到文件格式: " + format);

        switch (format) {
            case ERM:
                return ermReader.importFromPath(selectedFile, parent);
            case POSTMAN_V21:
                return postmanImporter.importFromPath(selectedFile, parent);
            case SQLITE3:
                JOptionPane.showMessageDialog(parent,
                        "旧版 SQLite3 格式已不再支持，请使用 ERM 存档格式 (.erm) 导入。",
                        "格式不再支持", JOptionPane.WARNING_MESSAGE);
                return false;
            case UNKNOWN:
            default:
                JOptionPane.showMessageDialog(parent,
                        "无法识别的文件格式。\n支持的格式: ERM存档 (.erm), Postman Collection v2.1 (.json)",
                        "格式错误", JOptionPane.ERROR_MESSAGE);
                return false;
        }
    }

    /**
     * 从ERM存档导入
     */
    public boolean importFromErm(Component parent) {
        return ermReader.importFromFile(parent);
    }

    /**
     * 从Postman Collection导入
     */
    public boolean importFromPostman(Component parent) {
        return postmanImporter.importFromFile(parent);
    }
}
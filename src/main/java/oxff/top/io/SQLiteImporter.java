package oxff.top.io;

import burp.BurpExtender;
import oxff.top.db.DatabaseManager;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Component;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * SQLite数据库导入器
 */
public class SQLiteImporter {
    private final DatabaseManager dbManager;
    private final AtomicBoolean isImporting = new AtomicBoolean(false);

    public SQLiteImporter() {
        this.dbManager = DatabaseManager.getInstance();
    }

    /**
     * 从SQLite文件导入（UI入口）
     */
    public boolean importFromFile(Component parent) {
        if (isImporting.get()) {
            JOptionPane.showMessageDialog(parent,
                "另一个导入操作正在进行中，请稍后再试。", "导入繁忙", JOptionPane.WARNING_MESSAGE);
            return false;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("导入SQLite数据库");
        fileChooser.setFileFilter(new FileNameExtensionFilter(
            "SQLite数据库文件 (*.sqlite3, *.db)", "sqlite3", "db", "sqlite"));
        fileChooser.setAcceptAllFileFilterUsed(false);

        int result = fileChooser.showOpenDialog(parent);
        if (result != JFileChooser.APPROVE_OPTION) {
            return false;
        }

        File selectedFile = fileChooser.getSelectedFile();
        if (!selectedFile.exists() || !selectedFile.isFile()) {
            JOptionPane.showMessageDialog(parent, "所选文件不存在", "导入错误", JOptionPane.ERROR_MESSAGE);
            return false;
        }

        int confirm = JOptionPane.showConfirmDialog(parent,
            "导入操作将使用新的数据库文件，当前会话数据将不可用。\n是否继续？",
            "确认导入", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);

        if (confirm != JOptionPane.YES_OPTION) {
            return false;
        }

        isImporting.set(true);
        CompletableFuture.runAsync(() -> {
            try {
                doImport(selectedFile, parent);
                JOptionPane.showMessageDialog(parent, "数据导入成功", "导入成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                BurpExtender.printError("[!] 导入数据失败: " + e.getMessage());
                JOptionPane.showMessageDialog(parent,
                    "导入数据失败: " + e.getMessage(), "导入错误", JOptionPane.ERROR_MESSAGE);
            } finally {
                isImporting.set(false);
            }
        });

        return true;
    }

    /**
     * 执行导入：将源SQLite复制到新的会话数据库文件
     */
    private void doImport(File sourceFile, Component parent) throws IOException, SQLException {
        BurpExtender.printOutput("[*] 开始SQLite数据库导入...");

        // 新策略：将源文件复制到当前基础目录下的新自动生成的文件名
        String newDbPath = dbManager.getConfig().getEffectiveDatabasePath();
        File targetFile = new File(newDbPath);
        File targetDir = targetFile.getParentFile();

        if (targetDir != null && !targetDir.exists()) {
            targetDir.mkdirs();
        }

        // 复制文件
        Files.copy(sourceFile.toPath(), targetFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
        BurpExtender.printOutput("[+] 已复制数据库文件到: " + targetFile.getAbsolutePath());

        // 设置为当前会话文件并重新初始化
        dbManager.getConfig().setSessionFile(newDbPath);
        dbManager.resetForNewSession();

        boolean success = dbManager.initialize();
        if (!success) {
            throw new SQLException("导入数据库后初始化失败");
        }

        BurpExtender.printOutput("[+] 数据导入成功，新数据库: " + newDbPath);

        // 刷新UI
        refreshUIAfterImport();
    }

    /**
     * 从SQLite数据库直接导入数据到当前数据库（合并模式）
     */
    public void importDataFromSQLite(String sourceDbPath) {
        try {
            File sourceFile = new File(sourceDbPath);
            if (!sourceFile.exists()) {
                BurpExtender.printError("[!] 源数据库文件不存在: " + sourceDbPath);
                return;
            }

            Connection sourceConn = java.sql.DriverManager.getConnection("jdbc:sqlite:" + sourceDbPath);
            Connection targetConn = dbManager.getConnection();

            try {
                targetConn.setAutoCommit(false);

                // 导入请求数据
                Statement stmt = sourceConn.createStatement();
                ResultSet rs = stmt.executeQuery("SELECT * FROM requests");

                while (rs.next()) {
                    PreparedStatement pstmt = targetConn.prepareStatement(
                        "INSERT INTO requests (protocol, domain, path, query, method, request_data, comment, color, add_time) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
                        Statement.RETURN_GENERATED_KEYS);

                    pstmt.setString(1, rs.getString("protocol"));
                    pstmt.setString(2, rs.getString("domain"));
                    pstmt.setString(3, rs.getString("path"));
                    pstmt.setString(4, rs.getString("query"));
                    pstmt.setString(5, rs.getString("method"));
                    pstmt.setBytes(6, rs.getBytes("request_data"));
                    pstmt.setString(7, rs.getString("comment"));
                    pstmt.setString(8, rs.getString("color"));

                    pstmt.executeUpdate();
                    pstmt.close();
                }

                // 导入历史数据
                rs = stmt.executeQuery("SELECT * FROM history");
                while (rs.next()) {
                    PreparedStatement pstmt = targetConn.prepareStatement(
                        "INSERT INTO history (request_id, method, protocol, domain, path, query, status_code, " +
                        "response_length, response_time, comment, color, request_data, response_data, timestamp) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)");

                    pstmt.setObject(1, rs.getObject("request_id"));
                    pstmt.setString(2, rs.getString("method"));
                    pstmt.setString(3, rs.getString("protocol"));
                    pstmt.setString(4, rs.getString("domain"));
                    pstmt.setString(5, rs.getString("path"));
                    pstmt.setString(6, rs.getString("query"));
                    pstmt.setInt(7, rs.getInt("status_code"));
                    pstmt.setInt(8, rs.getInt("response_length"));
                    pstmt.setInt(9, rs.getInt("response_time"));
                    pstmt.setString(10, rs.getString("comment"));
                    pstmt.setString(11, rs.getString("color"));
                    pstmt.setBytes(12, rs.getBytes("request_data"));
                    pstmt.setBytes(13, rs.getBytes("response_data"));

                    pstmt.executeUpdate();
                    pstmt.close();
                }

                targetConn.commit();
                BurpExtender.printOutput("[+] SQLite数据合并导入完成");

            } catch (Exception e) {
                targetConn.rollback();
                BurpExtender.printError("[!] 导入数据时出错: " + e.getMessage());
            } finally {
                sourceConn.close();
                targetConn.setAutoCommit(true);
                targetConn.close();
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 导入数据库时出错: " + e.getMessage());
        }
    }

    private void refreshUIAfterImport() {
        try {
            java.lang.reflect.Field repeaterUIField = burp.BurpExtender.class.getDeclaredField("repeaterUI");
            repeaterUIField.setAccessible(true);
            Object repeaterUIObj = repeaterUIField.get(null);
            if (repeaterUIObj != null && repeaterUIObj instanceof oxff.top.EnhancedRepeaterUI) {
                ((oxff.top.EnhancedRepeaterUI) repeaterUIObj).refreshAllData();
                BurpExtender.printOutput("[+] 界面数据刷新成功");
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 刷新界面数据时出错: " + e.getMessage());
        }
    }
}

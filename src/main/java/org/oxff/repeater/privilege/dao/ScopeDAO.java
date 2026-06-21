package org.oxff.repeater.privilege.dao;

import burp.BurpExtender;
import org.oxff.repeater.db.DatabaseManager;
import org.oxff.repeater.privilege.model.ScopeEntry;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * Scope条目数据访问对象
 * 管理 scope_entries 表的 CRUD
 */
public class ScopeDAO {

    /**
     * 获取所有Scope条目
     */
    public List<ScopeEntry> getAllEntries() {
        List<ScopeEntry> entries = new ArrayList<>();
        String sql = "SELECT id, name, url_pattern, enabled, description FROM scope_entries ORDER BY id ASC";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                ScopeEntry entry = new ScopeEntry();
                entry.setId(rs.getInt("id"));
                entry.setName(rs.getString("name"));
                entry.setUrlPattern(rs.getString("url_pattern"));
                entry.setEnabled(rs.getInt("enabled") == 1);
                entry.setDescription(rs.getString("description"));
                entries.add(entry);
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取Scope条目列表失败: " + e.getMessage());
        }
        return entries;
    }

    /**
     * 获取所有已启用的Scope条目
     */
    public List<ScopeEntry> getEnabledEntries() {
        List<ScopeEntry> entries = new ArrayList<>();
        String sql = "SELECT id, name, url_pattern, enabled, description FROM scope_entries WHERE enabled = 1 ORDER BY id ASC";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                ScopeEntry entry = new ScopeEntry();
                entry.setId(rs.getInt("id"));
                entry.setName(rs.getString("name"));
                entry.setUrlPattern(rs.getString("url_pattern"));
                entry.setEnabled(true);
                entry.setDescription(rs.getString("description"));
                entries.add(entry);
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 获取已启用Scope条目列表失败: " + e.getMessage());
        }
        return entries;
    }

    /**
     * 添加Scope条目
     * @return 新记录ID，失败返回-1
     */
    public int addEntry(ScopeEntry entry) {
        String sql = "INSERT INTO scope_entries (name, url_pattern, enabled, description) VALUES (?, ?, ?, ?)";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, entry.getName() != null ? entry.getName() : "");
            pstmt.setString(2, entry.getUrlPattern());
            pstmt.setInt(3, entry.isEnabled() ? 1 : 0);
            pstmt.setString(4, entry.getDescription() != null ? entry.getDescription() : "");
            pstmt.executeUpdate();
            try (ResultSet rs = pstmt.getGeneratedKeys()) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 添加Scope条目失败: " + e.getMessage());
        }
        return -1;
    }

    /**
     * 更新Scope条目
     */
    public boolean updateEntry(ScopeEntry entry) {
        String sql = "UPDATE scope_entries SET name = ?, url_pattern = ?, enabled = ?, description = ? WHERE id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, entry.getName() != null ? entry.getName() : "");
            pstmt.setString(2, entry.getUrlPattern());
            pstmt.setInt(3, entry.isEnabled() ? 1 : 0);
            pstmt.setString(4, entry.getDescription() != null ? entry.getDescription() : "");
            pstmt.setInt(5, entry.getId());
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            BurpExtender.printError("[!] 更新Scope条目失败: " + e.getMessage());
        }
        return false;
    }

    /**
     * 删除Scope条目
     */
    public boolean deleteEntry(int id) {
        String sql = "DELETE FROM scope_entries WHERE id = ?";
        try (Connection conn = DatabaseManager.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            BurpExtender.printError("[!] 删除Scope条目失败: " + e.getMessage());
        }
        return false;
    }
}

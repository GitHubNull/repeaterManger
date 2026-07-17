package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.SessionManager;
import org.oxff.repeater.privilege.model.Scheme;
import org.oxff.repeater.privilege.model.UserInfo;
import org.oxff.repeater.privilege.model.UserSession;

import javax.swing.table.DefaultTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * 用户会话表格模型
 * 列：名称、颜色、关联方案、启用、角色、用户名、匿名、截图、字段值摘要
 */
public class UserSessionTableModel extends DefaultTableModel {

    private static final String[] COLUMN_NAMES = {
        "名称", "颜色", "关联方案", "启用", "角色", "用户名", "匿名", "截图", "字段值摘要"
    };

    private final List<UserSession> sessions = new ArrayList<>();

    public UserSessionTableModel() {
        super(COLUMN_NAMES, 0);
    }

    public void setData(List<UserSession> sessions) {
        this.sessions.clear();
        setRowCount(0);
        if (sessions != null) {
            SessionManager sm = SessionManager.getInstance();
            for (UserSession session : sessions) {
                this.sessions.add(session);
                String schemeName = resolveSchemeName(session.getSchemeId());
                UserInfo userInfo = sm.getUserInfo(session.getId());
                String role = "";
                String username = "";
                String anonymous = "";
                String screenshotCount = "";
                if (userInfo != null) {
                    role = userInfo.getRole() != null ? userInfo.getRole() : "";
                    username = userInfo.getUsername() != null ? userInfo.getUsername() : "";
                    anonymous = userInfo.isAnonymous() ? "是" : "";
                    int count = userInfo.getScreenshotCount();
                    screenshotCount = count > 0 ? count + "张" : "";
                }
                addRow(new Object[]{
                        session.getName(),
                        session.getColorHex() != null ? session.getColorHex() : "",
                        schemeName,
                        session.isEnabled() ? "是" : "否",
                        role,
                        username,
                        anonymous,
                        screenshotCount,
                        session.getFieldValuesSummary()
                });
            }
        }
        fireTableDataChanged();
    }

    private String resolveSchemeName(Integer schemeId) {
        if (schemeId == null) return "";
        SessionManager sm = SessionManager.getInstance();
        Scheme scheme = sm.getSchemeById(schemeId);
        return scheme != null ? scheme.getName() : "";
    }

    public UserSession getUserSession(int row) {
        if (row >= 0 && row < sessions.size()) {
            return sessions.get(row);
        }
        return null;
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return false;
    }
}

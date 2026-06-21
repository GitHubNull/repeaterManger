package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.SessionManager;
import org.oxff.repeater.privilege.model.TokenScheme;
import org.oxff.repeater.privilege.model.UserSession;

import javax.swing.table.DefaultTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * 用户会话表格模型
 * 列：名称、颜色、关联方案、启用、令牌值摘要
 */
public class UserSessionTableModel extends DefaultTableModel {

    private static final String[] COLUMN_NAMES = {"名称", "颜色", "关联方案", "启用", "令牌值摘要"};

    private final List<UserSession> sessions = new ArrayList<>();

    public UserSessionTableModel() {
        super(COLUMN_NAMES, 0);
    }

    public void setData(List<UserSession> sessions) {
        this.sessions.clear();
        setRowCount(0);
        if (sessions != null) {
            for (UserSession session : sessions) {
                this.sessions.add(session);
                String schemeName = resolveSchemeName(session.getSchemeId());
                addRow(new Object[]{
                        session.getName(),
                        session.getColorHex() != null ? session.getColorHex() : "",
                        schemeName,
                        session.isEnabled() ? "是" : "否",
                        session.getTokenValuesSummary()
                });
            }
        }
        fireTableDataChanged();
    }

    private String resolveSchemeName(Integer schemeId) {
        if (schemeId == null) return "";
        SessionManager sm = SessionManager.getInstance();
        TokenScheme scheme = sm.getTokenSchemeById(schemeId);
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

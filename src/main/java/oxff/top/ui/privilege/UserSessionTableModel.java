package oxff.top.ui.privilege;

import oxff.top.privilege.model.UserSession;

import javax.swing.table.DefaultTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * 用户会话表格模型
 */
public class UserSessionTableModel extends DefaultTableModel {

    private static final String[] COLUMN_NAMES = {"名称", "颜色", "启用", "令牌值摘要"};

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
                addRow(new Object[]{
                        session.getName(),
                        session.getColorHex() != null ? session.getColorHex() : "",
                        session.isEnabled() ? "是" : "否",
                        session.getTokenValuesSummary()
                });
            }
        }
        fireTableDataChanged();
    }

    public UserSession getUserSession(int row) {
        if (row >= 0 && row < sessions.size()) {
            return sessions.get(row);
        }
        return null;
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return false;
    }
}

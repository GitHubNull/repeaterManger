package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.i18n.I18nManager;
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

    private static final String[] COLUMN_KEYS = {
        "session.col.name", "session.col.color", "session.col.scheme",
        "session.col.enabled", "session.col.role", "session.col.username",
        "session.col.anonymous", "session.col.screenshot", "session.col.fieldSummary"
    };

    private final List<UserSession> sessions = new ArrayList<>();

    public UserSessionTableModel() {
        super(new Object[COLUMN_KEYS.length], 0);
    }

    @Override
    public String getColumnName(int column) {
        return I18nManager.tr(COLUMN_KEYS[column]);
    }

    /**
     * 语言切换后刷新列名及行内本地化文本
     */
    public void refreshColumnNames() {
        fireTableStructureChanged();
        // 行内"是/否"等文本随语言变化，需重新填充
        setData(SessionManager.getInstance().getUserSessions());
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
                    anonymous = userInfo.isAnonymous() ? I18nManager.tr("session.col.yes") : "";
                    int count = userInfo.getScreenshotCount();
                    screenshotCount = count > 0 ? I18nManager.tr("session.col.screenshot.count", count) : "";
                }
                addRow(new Object[]{
                        session.getName(),
                        session.getColorHex() != null ? session.getColorHex() : "",
                        schemeName,
                        session.isEnabled() ? I18nManager.tr("session.col.yes") : I18nManager.tr("session.col.no"),
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

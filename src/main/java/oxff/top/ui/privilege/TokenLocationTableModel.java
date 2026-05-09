package oxff.top.ui.privilege;

import oxff.top.privilege.model.TokenLocation;
import javax.swing.table.DefaultTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * 令牌位置表格模型
 */
public class TokenLocationTableModel extends DefaultTableModel {

    private static final String[] COLUMN_NAMES = {"类型", "表达式", "描述", "持久化到全局", "启用"};

    private final List<TokenLocation> locations = new ArrayList<>();

    public TokenLocationTableModel() {
        super(COLUMN_NAMES, 0);
    }

    public void setData(List<TokenLocation> locations) {
        this.locations.clear();
        setRowCount(0);
        if (locations != null) {
            for (TokenLocation loc : locations) {
                this.locations.add(loc);
                addRow(new Object[]{
                        loc.getType().getDisplayName(),
                        loc.getExpression(),
                        loc.getDescription(),
                        loc.isPersistToGlobal() ? "是" : "否",
                        loc.isEnabled() ? "是" : "否"
                });
            }
        }
        fireTableDataChanged();
    }

    public TokenLocation getTokenLocation(int row) {
        if (row >= 0 && row < locations.size()) {
            return locations.get(row);
        }
        return null;
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return false;
    }
}

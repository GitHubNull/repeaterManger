package org.oxff.repeater.db.schema;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * 数据库 Schema 迁移步骤接口。
 * 每个实现类代表从一个版本到下一个版本的迁移逻辑。
 */
public interface MigrationStep {

    /** 迁移起始版本（不包含） */
    int fromVersion();

    /** 迁移目标版本 */
    int toVersion();

    /** 执行迁移 */
    void migrate(Connection conn) throws SQLException;
}

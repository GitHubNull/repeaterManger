package org.oxff.repeater.db;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.concurrent.BlockingQueue;

/**
 * 连接池代理的调用处理器
 * 拦截close()方法，将连接归还到池中
 */
class PooledConnectionInvocationHandler implements InvocationHandler {
    private final Connection realConnection;
    private final BlockingQueue<Connection> connectionPool;
    private final Runnable onReturnCallback;
    private boolean closed = false;

    PooledConnectionInvocationHandler(Connection realConnection,
                                       BlockingQueue<Connection> connectionPool,
                                       Runnable onReturnCallback) {
        this.realConnection = realConnection;
        this.connectionPool = connectionPool;
        this.onReturnCallback = onReturnCallback;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        if ("close".equals(method.getName())) {
            if (!closed) {
                closed = true;
                try {
                    if (!realConnection.getAutoCommit()) {
                        realConnection.setAutoCommit(true);
                    }
                } catch (SQLException e) {
                    // 忽略
                }
                if (!realConnection.isClosed()) {
                    if (connectionPool.offer(realConnection)) {
                        onReturnCallback.run();
                    } else {
                        realConnection.close();
                    }
                }
            }
            return null;
        }

        if ("isClosed".equals(method.getName())) {
            return closed || realConnection.isClosed();
        }

        if (closed) {
            throw new SQLException("Connection is closed");
        }

        return method.invoke(realConnection, args);
    }
}

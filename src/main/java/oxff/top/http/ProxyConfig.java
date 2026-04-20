package oxff.top.http;

import oxff.top.config.DatabaseConfig;
import oxff.top.logging.LogManager;
import java.net.InetSocketAddress;
import java.net.Proxy;

/**
 * HTTP代理配置单例 - 管理调试代理的主机、端口和启用状态
 */
public class ProxyConfig {

    private static ProxyConfig instance;

    private boolean proxyEnabled = false;
    private String proxyHost = "127.0.0.1";
    private int proxyPort = 8080;

    private ProxyConfig() {
    }

    public static synchronized ProxyConfig getInstance() {
        if (instance == null) {
            instance = new ProxyConfig();
        }
        return instance;
    }

    /**
     * 从DatabaseConfig加载代理配置
     */
    public void loadFromConfig(DatabaseConfig config) {
        this.proxyEnabled = config.isProxyEnabled();
        this.proxyHost = config.getProxyHost();
        this.proxyPort = config.getProxyPort();

        if (proxyEnabled) {
            LogManager.getInstance().info("[*] HTTP代理已启用: " + proxyHost + ":" + proxyPort);
        }
    }

    /**
     * 保存代理配置到DatabaseConfig
     */
    public void saveToConfig(DatabaseConfig config) {
        config.setProxyEnabled(proxyEnabled);
        config.setProxyHost(proxyHost);
        config.setProxyPort(proxyPort);
    }

    /**
     * 转换为java.net.Proxy对象
     */
    public Proxy toJavaProxy() {
        if (!proxyEnabled) {
            return Proxy.NO_PROXY;
        }
        return new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHost, proxyPort));
    }

    public boolean isProxyEnabled() {
        return proxyEnabled;
    }

    public void setProxyEnabled(boolean proxyEnabled) {
        boolean changed = this.proxyEnabled != proxyEnabled;
        this.proxyEnabled = proxyEnabled;
        if (changed) {
            LogManager lm = LogManager.getInstance();
            if (proxyEnabled) {
                lm.info("[*] HTTP代理已启用: " + proxyHost + ":" + proxyPort);
            } else {
                lm.info("[*] HTTP代理已禁用");
            }
        }
    }

    public String getProxyHost() {
        return proxyHost;
    }

    public void setProxyHost(String proxyHost) {
        this.proxyHost = proxyHost;
    }

    public int getProxyPort() {
        return proxyPort;
    }

    public void setProxyPort(int proxyPort) {
        this.proxyPort = proxyPort;
    }
}

package com.securitytest;

import java.io.File;

import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;

/**
 * 安全测试插件 - 仅用于授权靶场环境验证 CVE-2023-32315 漏洞
 * JSP 文件位于 web/ 目录，插件加载后自动对外暴露
 */
public class SecurityTestPlugin implements Plugin {

    @Override
    public void initializePlugin(PluginManager manager, File pluginDirectory) {
        System.out.println("[SecurityTest] 插件已初始化，Web shell 可通过 /plugins/securitytest/ 访问");
    }

    @Override
    public void destroyPlugin() {
        System.out.println("[SecurityTest] 插件已销毁。");
    }
}

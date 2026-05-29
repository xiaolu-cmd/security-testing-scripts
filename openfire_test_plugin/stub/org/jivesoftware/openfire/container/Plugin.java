package org.jivesoftware.openfire.container;

import java.io.File;

public interface Plugin {
    void initializePlugin(PluginManager manager, File pluginDirectory);
    void destroyPlugin();
}

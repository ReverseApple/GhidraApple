package lol.fairplay.ghidraapple

import ghidra.framework.plugintool.util.PluginPackage
import resources.ResourceManager
import javax.swing.Icon
import javax.swing.ImageIcon

class GhidraApplePluginPackage : PluginPackage(PKG_NAME, PKG_ICON, PKG_DESC) {
    companion object {
        const val PKG_NAME = "GhidraApple"
        val PKG_ICON = ResourceManager.loadImage("icon/package-icon.png")
        const val PKG_DESC = "Better Apple Binary Analysis for Ghidra"

        val OBJC_ICON: Icon = ImageIcon(ClassLoader.getSystemClassLoader().getResource("icon/oc.png"))
    }
}

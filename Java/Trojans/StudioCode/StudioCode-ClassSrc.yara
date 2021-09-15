rule StudioCode_Backdoor: Minecraft_Backdoor {
    strings: 
        $lib_used = "org.apache.commons.io.IOUtils" ascii
        $dropped_file = /plugins\/[A-Za-z0-9_-]+.jar/
        $converter = "IOUtils.toByteArray" ascii
        $injected_method = /private void [A-Za-z0-9]+\(\)/
        $dropped_file_loader = "Bukkit.getPluginManager().loadPlugin" ascii
        $dropped_file_enabler = "Bukkit.getPluginManager().enablePlugin" ascii
        $t = "getClass().getClassLoader().getResourceAsStream"
    condition:
        all of them
}

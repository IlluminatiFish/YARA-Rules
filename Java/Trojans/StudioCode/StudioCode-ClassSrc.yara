rule StudioCode_Backdoor: Minecraft_Backdoor {

    meta:
		author = "IlluminatiFish"
		description = "Detects the StudioCode backdoor that injects itself into the onEnable() of a minecraft plugin and loads it payload from a ZIP masked as a YML file and masks itself using the names 'EssentialBackup' & 'PluginMetrics'"
		created = "15-09-21"
		last_modified = "15-09-21"

    strings: 
        $lib_used = "org.apache.commons.io.IOUtils" ascii
        $dropped_file = /plugins\/[A-Za-z0-9_-]+.jar/
        $converter = "IOUtils.toByteArray" ascii
        $injected_method = /private void [A-Za-z0-9]+\(\)/
        $dropped_file_loader = "Bukkit.getPluginManager().loadPlugin" ascii
        $dropped_file_enabler = "Bukkit.getPluginManager().enablePlugin" ascii
        $backdoor_loader = "getClass().getClassLoader().getResourceAsStream"
    condition:
        all of them
}

rule StudioCode_2018_Loader : Minecraft_Backdoor {

    meta:
        author = "IlluminatiFish"
        description = "Detects the StudioCode backdoor that injects itself into the onEnable() of a minecraft plugin and loads it payload from a ZIP masked as a YML file and masks itself using the names 'EssentialBackup' & 'PluginMetrics'"
        created = "10-03-21"
        last_modified = "10-03-21"

    /* These strings detect the undecompiled class where the loader code is in */
    strings:
        $s_1 = "org/apache/commons/io/IOUtils" nocase /* Appears: 1 */
        $s_2 = /[A-Za-z0-9]{10,}.yml/
        $s_3 = "java/lang/ClassLoader" nocase /* Appears: 2 */
        $s_4 = "loadPlugin" nocase /* Appears: 1 */
        $s_5 = "enablePlugin" nocase /* Appears: 1 */
        $s_6 = "toByteArray" nocase /* Appears: 1 */
        $s_7 = "getClassLoader" nocase /* Appears: 1 */
        $s_8 = "getClass" nocase /* Appears: 2 */
        $s_9 = "java/io/FileOutputStream" nocase /* Appears: 1 */
        $s_10 = "java/io/File" nocase /* Appears: 4 */
        $s_11 = /plugins\/[A-Za-z0-9]+.jar/ /* Appears: 1 */
        $s_12 = "java/lang/Exception" nocase /* Appears: 1 */

    condition:
        all of them or (#s_1 == 1 and $s_2 and #s_3 == 2 and #s_4 == 1 and #s_5 == 1 and #s_6 == 1 and #s_7 == 1 and #s_8 == 2 and #s_9 == 1 and #s_10 == 4 and #s_11 == 1 and #s_12 == 1)
}




rule StudioCode_2018_Payload : Minecraft_Backdoor {

    meta:
        author = "IlluminatiFish"
        description = "Detects the StudioCode backdoor that injects itself into the onEnable() of a minecraft plugin and loads it payload from a ZIP masked as a YML file and masks itself using the names 'EssentialBackup' & 'PluginMetrics'"
        created = "10-03-21"
        last_modified = "10-03-21"

	/* These strings detect the payload YML (ZIP) file found in the plugin */
    strings:
        $s_1 = "DRAWXxQcTebFLnizmMrWVYbLhRDCnqfCYgGdHrWFkSTzrghYlXTGxqkwjhkRasMxTrfftWPTojaYcDjvMDRrxUuQCyJFVndubUALwRxcKymnNJGYBVnfLimzoVDAyczEVMdLPukgobrDNueyXipYRRCmLfXqvUwsfdThVdOxkhurNAIeCcxHoyhQunXHH" /* Appears: 424 */
        $s_2 = "data" nocase /* Appears: 2 */
        $s_3 = "info" nocase /* Appears: 2 */
        $s_4 = "plugin.yml" nocase /* Appears: 2 */
     
    condition:
        all of them or ($s_1 and #s_2 == 2 and #s_3 == 2 and #s_4 == 2)
}

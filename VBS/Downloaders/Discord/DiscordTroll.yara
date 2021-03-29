rule Discord_Troll_Downloader : VBS_Downloader {

    meta:
        author = "IlluminatiFish"
        description = "Detects any discord image that has specific VBScript injected into it which flag AVs for some 2006 exploit"
        created = "06-03-2021"
        last_modified = "15-03-2021"

    strings:
        $http_request = "CreateObject(\"Microsoft.XMLHTTP\")" nocase
        $adodb_stream = "CreateObject(\"Adodb.Stream\")" nocase
        $wscript_shell = "CreateObject(\"WScript.Shell\")" nocase
        $payload_url = "https://cdn.discordapp.com/avatars/275808021605777409/1f5eae5d8b12034c335309a0150942c5.png?size=512"
        $registry_key = "HKCU\\Control Panel\\Desktop\\Wallpaper"
        $shell_cmd = "%windir%\\System32\\RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameter"
        $temp_folder = "ExpandEnvironmentStrings(\"%temp%\")"
        $image_file = "myImage.png"

    condition:
        (7 of them
            and #image_file == 2 
            and #temp_folder == 1 
            and #shell_cmd == 1 
            and #registry_key == 1 
            and #payload_url == 1 
            and #wscript_shell == 1 
            and #adodb_stream == 1 
            and #http_request == 1
        ) 
}

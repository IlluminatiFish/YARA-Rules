rule Spare_Change_DOM : JSMiner
{
    meta:
        author = "IlluminatiFish"
        description = "Detects the SpareChange miner in a given DOM"
        date = "24-02-2021"
    strings:
        $sc_launcher = "new Miner" nocase
        $sc_launcher_start = ".start(" nocase
    condition:
    	all of them
        
}

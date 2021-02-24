rule XXHjbiner_DOM : JSMiner
{
    meta:
        author = "IlluminatiFish"
        description = "Detects the XXHjbiner miner in a given DOM"
        date = "24-02-2021"
    strings:
        $xh_launcher = "new XXHjbiner.Anonymous" nocase
        $xh_launcher_start = ".start(" nocase
    condition:
    	all of them
        
}

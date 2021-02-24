rule Miner_Worker_DOM : JSMiner
{
    meta:
        author = "IlluminatiFish"
        description = "Detects the MinerWorker miner in a given DOM"
        date = "24-02-2021"
    strings:
        $mw_launcher = "new MinerWorker.Anonymous" nocase
        $mw_launcher_start = ".start(" nocase
    condition:
    	all of them
        
}

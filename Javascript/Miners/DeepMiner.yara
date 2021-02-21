rule DeepMiner_DOM : JSMiner {
    meta:
        author = "IlluminatiFish"
        date = "14-02-2021"
        description = "Detects the DeepMiner miner script in a given DOM"
    
    strings:
        $dm_lib = /<script src="(https:|http:|)?\/\/(www\.)?[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z0-9]{1,}\.[a-zA-Z]{2,}\/lib\/deepMiner.min.js"><\/script>/
        $dm_launcher_a = "new deepMiner.Anonymous" nocase
        $dm_launcher_b = "new deepMiner.Init" nocase
        $dm_launcher_start = ".start();" nocase
       
    condition:
        all of them
        
}

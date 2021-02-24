rule Coin_IMP_DOM : JSMiner {
    meta:
        author = "IlluminatiFish"
        date = "24-02-2021"
        description = "Detects the CoinIMP miner script in a given DOM"
    
    strings:
        $ci_launcher = "new Client.Anonymous"
        $ci_launcher_start = ".start(" nocase
       
    condition:
        all of them
        
}

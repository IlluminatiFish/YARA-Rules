rule Coin_Hive_DOM : JSMiner {
    meta:
        author = "IlluminatiFish"
        date = "24-02-2021"
        description = "Detects the CoinHive miner script in a given DOM"
    
    strings:
        $ch_launcher_a = "new CoinHive.Anonymous" nocase
        $ch_launcher_b = "new CoinHive.User" nocase
        $ch_launcher_start = ".start(" nocase
       
    condition:
        ($ch_launcher_a and $ch_launcher_start) or ($ch_launcher_b and $ch_launcher_start)     
}

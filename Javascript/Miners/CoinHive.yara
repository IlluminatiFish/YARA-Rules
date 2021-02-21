rule Coin_Hive_DOM : JSMiner {
    meta:
        author = "IlluminatiFish"
        date = "14-02-2021"
        description = "Detects the CoinHive miner script in a given DOM"
    
    strings:
        $ch_lib = "http://coinhive.com/lib/coinhive.min.js" nocase
        $ch_launcher = /new CoinHive.Anonymous\('[A-Za-z0-9]{32}', {/
        $ch_launcher_start = ".start();" nocase
       
    condition:
        all of them or ($ch_lib and $ch_launcher) or ($ch_launcher and $ch_launcher_start)     
}

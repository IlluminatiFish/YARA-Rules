rule CryptoLoot : JS.Miner
{
    meta:
        author = "IlluminatiFish"
        date = "14-02-2021"
        description = "Detects the CryptoLoot miner script in a given DOM"
        

    strings:
        $cl_lib = "https://crypto-loot.com/lib/miner.min.js" nocase
        $cl_launcher = /new CryptoLoot.Anonymous\('[a-z0-9]{44}', {/
        $cl_launcher_start = ".start();" nocase
       
    condition:
        all of them or ($cl_lib and $cl_launcher) or ($cl_launcher and $cl_launcher_start)
        
}

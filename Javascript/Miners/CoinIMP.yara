rule CoinIMP : JS.Miner
{
    meta:
        author = "IlluminatiFish"
        date = "14-02-2021"
        description = "Detects the CoinIMP miner script in a given DOM"
    
    strings:
        $ci_launcher = /new Client.Anonymous\('[a-z0-9]{64}', {/
        $ci_launcher_start = ".start();" nocase
       
    condition:
        all of them
        
}

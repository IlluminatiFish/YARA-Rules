rule CryptoLoot_Miner_DOM : JS_Miner {
    meta:
        author = "IlluminatiFish"
        date = "21-02-2021"
        description = "Detects the CryptoLoot miner script in a given DOM"

    strings:
        $cl_function_a = /new CryptoLoot.Anonymous\('[a-z0-9]{44}'/
        $cl_function_b = /new CRLT.Anonymous\('[a-z0-9]{44}'/
        $cl_function_start = ".start();" nocase

    condition:
        ($cl_function_a and $cl_function_start) or ($cl_function_b and $cl_function_start)

}

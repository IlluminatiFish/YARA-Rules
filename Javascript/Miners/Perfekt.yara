rule Perfekt_Miner_DOM : JS_Miner {
	meta:
		author = "IlluminatiFish"
		description = "Detects the Perfekt javascript miner in a given DOM"
		created = "21-02-2021"
		last_modified = "21-02-2021"

	strings:
		$pf_function_a = "PerfektStart"
		$pf_function_b = "EverythingIsBinary"
		$pf_throttle_string = "throttleMiner"

	condition:
		($pf_function_a and $pf_throttle_string) or ($pf_function_b and $pf_throttle_string) or $pf_function_a or $pf_function_b
}

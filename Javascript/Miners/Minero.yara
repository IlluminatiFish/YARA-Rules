rule Minero_Miner_DOM : JS_Miner {
	meta:
		description = "Detects the Minero javascript miner in a given DOM"
		author = "IlluminatiFish"
		date = "21-02-2021"

	strings:
		$mo_injector = /<div class="minero-hidden" style="display: none" data-key="[a-z0-9]{32}"><\/div>/
		$mo_script = /<script src="https:\/\/minero.cc\/lib\/minero-hidden.min.js" async><\/script>/

	condition:
		all of them
}

rule Generic_Miner_DOM : JS_Miner {

	meta:
		author = "IlluminatiFish"
		description = "Generic YARA rule to detect a javascript miner in a website's DOM"
		created = "26-02-2021"
		last_modified = "26-02-2021"

	//NOTE: Aggregated all miner YARA rules into one using regex below (26th Feb 2021)
	strings:
		$miner = /new [a-zA-Z]+\.(User|Anonymous|Init)?/
		$miner_launcher = ".start("

	condition:
		all of them
}

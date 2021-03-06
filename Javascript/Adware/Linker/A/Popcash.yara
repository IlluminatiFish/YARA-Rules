rule Popcash_Linker_DOM : JS_Adware {

	meta:
		author = "IlluminatiFish"
		description = "Detects the popcash adware linker in a given DOM"
		created = "24-02-2021"
		last_modified = "10-03-2021"

	strings:
		$popcash_uid = /var uid = \'[0-9]+\'/
		$popcash_wid = /var wid = \'[0-9]+\'/
		$popcash_script_a = /\/\/cdn([0-9]+)?.popcash.net\/show.js/
		$popcash_script_b = /\/\/cdn([0-9]+)?.popcash.net\/pop.js/

	condition:
		($popcash_wid and $popcash_uid and $popcash_script_a) or ($popcash_wid and $popcash_uid and $popcash_script_b)

}

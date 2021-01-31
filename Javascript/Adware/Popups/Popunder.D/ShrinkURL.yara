rule ShrinkURL_Adware_DOM : JS_Adware {
	meta:
		author = "IlluminatiFish"
		date = "28-01-2021"
		description = "Detects ShrinkURL adware script being loaded without the user's consent"

	strings:
		$div_container_tag = /<div id="container-[0-9a-f]{32}"><\/div>/
		$invoker_script_tag_a = /\/\/[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\/[0-9a-f]{32}\/invoke.js/
		$invoker_script_tag_b = /(www\.)[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\/[0-9a-f]{32}\/invoke.js/
		$invoker_script_tag_c = "atOptions"
		$ad_script_tag = /\/\/[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\/[0-9a-f]{2}\/[0-9a-f]{2}\/[0-9a-f]{2}\/[0-9a-f]{32}.js/

	condition:
		any of them
}


rule ShrinkURL_Adware_Generic : JS_Adware {
	meta:
		author = "IlluminatiFish"
		date = "28-01-2021"
		description = "Detects ShrinkURL adware generic script string"
		generator = "https://gist.github.com/IlluminatiFish/b4e4298a7ac8a87a4d91b41a33f3cdb4"
    
	strings:
		$string_a = ")](0x0,0x2)+"
    
	condition:
		all of them
}

rule ShirnkURL_Adware_Invoker : JS_Adware {
	meta:
		author = "IlluminatiFish"
		date = "28-01-2021"
		description = "Detects ShrinkURL adware invoker script"
		generator = "https://gist.github.com/IlluminatiFish/b4e4298a7ac8a87a4d91b41a33f3cdb4"
    
	strings:
		$string_a = "if(void 0x0"
		$string_b = "},0x3e8)"
		$string_c = ")](0x4,0x2)+"
		$domain_a = "r.remarketingpixel.com"
		$url_a = "https://r.remarketingpixel.com/stats"
    
	condition:
		all of them
		
}	

rule ShirnkURL_Adware_Script : JS_Adware {
	meta:
		author = "IlluminatiFish"
		date = "28-01-2021"
		description = "Detects ShrinkURL adware ad generation script"
		generator = "https://gist.github.com/IlluminatiFish/b4e4298a7ac8a87a4d91b41a33f3cdb4"
    
	strings:
		$string_a = ")[0x1]"
		$string_b = "},0xc8)"
		$string_c = ")](0x2,0x2)+"
		$string_d = "sendNetworkMetrics"
		$string_e = "touchPixel"
		$string_f = "placementKey"
		$string_g = "templateId"
		$string_h = "buildVersion"
		$string_i = "withCredentials"
		$string_j = "dom3ic8zudi28v8lr6fgphwffqoz0j6c"
		
	condition:
		all of them
		
}

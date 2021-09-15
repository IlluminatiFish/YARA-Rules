rule Anonud4y_HE_Generator : Web_Phishing {

	meta:
		author = "IlluminatiFish"
		description = "A rule used to detect HTML comments left by webpage mirroring software, sometimes observed on phishing websites"
		created = "27-04-2021"
		last_modified = "27-04-2021"

	strings:
		$comment_a = "Webpage generated by Anonud4y" nocase

	condition:
		any of them
}
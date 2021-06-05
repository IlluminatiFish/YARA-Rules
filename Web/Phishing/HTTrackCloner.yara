rule HTTrack_Cloner : Web_Phishing {

	meta:
		author = "IlluminatiFish"
		description = "A rule used to detect HTML comments left by webpage mirroring software, sometimes observed on phishing websites"
		created = "27-04-2021"
		last_modified = "27-04-2021"

	strings:
		$comment_a = /saved from url=\([0-9]+\)(.*)/ nocase
		$comment_b = /<!--\sMirrored from (.*) by HTTrack Website Copier\/(.*)\s-->/ nocase
		$comment_c = /<!--\s(\/)?Added by HTTrack\s-->/ nocase

	condition:
		any of them
}

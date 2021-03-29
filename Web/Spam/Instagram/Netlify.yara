rule Instagram_Netlify_Porn : Web_Spam {

    meta:
        author = "IlluminatiFish"
        description = "A rule used to detect URLs that are used to advertise porn on Instagram"
        created = "23-03-2021"
        last_modified = "30-03-2021"

    strings:
        $str = "en-US" nocase
        $str1 = "utf-8" nocase
        $str2 = /https:\/\/cdn-[0-9A-z]+.akamaized.net/
        $str3 = "/images/favicon.ico" nocase
        $str4 = /\/landings\/[0-9]{6}\/[0-9]{10}\/css\/[0-9A-Za-z]+.css\?[0-9]{10}/
        $str5 = /\/landings\/[0-9]{6}\/[0-9]{10}\/js\/[0-9A-Za-z]+.js\?[0-9]{10}/

    condition:
        6 of them
}

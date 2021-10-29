// TO-DO: 
// Allow the rule to detect different skidded variants of this stealer

rule Wodx_Token_Stealer : Discord_Stealer {

    meta:
        author = "IlluminatiFish"
        description = "A rule to detect the wodx discord token stealer"
        created = "26-07-2021"
        last_modified = "29-10-2021"

    strings:
        $webhook_url = /(https?):\/\/((?:ptb\.|canary\.)?discord(?:app)?\.com)\/api(?:\/)?(v\d{1,2})?\/webhooks\/(\d{17,19})\/([\w\-]{68})/ ascii wide nocase
        $token_path = /\\\\Local Storage\\\\leveldb/ ascii wide nocase
        $developer_signature = "https://pastebin.com/raw/ssFxiejv" ascii wide nocase

    condition:
        2 of them
}

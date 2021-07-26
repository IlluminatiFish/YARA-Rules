// TO-DO: 
// Allow the rule to detect different skidded variants of this stealer

rule Wodx_Token_Stealer : Discord_Stealer {

    meta:
        author = "IlluminatiFish"
        description = "A rule to detect the wodx discord token stealer"
        created = "26-07-2021"
        last_modified = "26-07-2021"

    strings:
        $webhook_url = /http[s]:\/\/(ptb\.|canary\.)?discord\.com\/api\/webhooks\/[0-9]{18}\/[a-zA-Z0-9-_]+/ ascii wide nocase
        $token_path = /\\\\Local Storage\\\\leveldb/ ascii wide nocase
        $developer_signature = "https://pastebin.com/raw/ssFxiejv" ascii wide nocase

    condition:
        2 of them
}

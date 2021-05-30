rule smart102944_Campaign : Email_Phishing {

    meta:
        author = "IlluminatiFish"
        description = "Used to identify spam emails belonging to a massive advertisement campaign ran by smart102944@gmail.com"
        created = "30-05-2021"
        last_modified = "30-05-2021"

    strings:
        $reply_to = "smart102944@gmail.com"
        $message_id = /(\w)+.[0-9]\.([A-Z0-9]+)@affpartners.com/
        $sender = /xxxx@media(\?:pub|[0-9]+).[a-z]{2}.(\?:org|com)/
        $from = /newsletter.[A-Za-z0-9]+@[a-z]+.(\?:mp|edu)/

    condition:
        3 of them
}

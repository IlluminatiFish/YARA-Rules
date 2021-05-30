rule Alife12_Campaign : Email_Phishing {

    meta:
        author = "IlluminatiFish"
        description = "Used to identify spam emails belonging to a massive advertisement campaign identified as Alfie12 due to the X-Mailer header used"
        created = "30-05-2021"
        last_modified = "30-05-2021"

    strings:
        $to_and_cc = "<-----@---->" ascii
        $mailer = "Alife12" ascii
        $receiver_a = "from 127.0.0.1 (EHLO mta104a.mail.e.sparkpost.com) (34.216.191.165) by mta4043.aol.mail.gq1.yahoo.com" ascii
        $receiver_b = "from mx1.banqueaudi.com" ascii

    condition:
        all of them
}

# YARA-Rules
A repository to host all my YARA rules that I make for the public, and the security community


# Rules Overview

## JS:/Adware.Popups.Popunder.A!sw

Created a comprehensive [YARA rule](../main/Javascript/Adware/Popups/Popunder/A/AdsterraAdware.yara) that utilises regular expressions (regex) to detect the adware that can be found on the ShrinkURL URL shorterning service website. 
Sample: http://beta.shrinkurl.org/yiwC8Q

## JS:/Miner.Gen!sw

Created a comprehensive [YARA rule](../main/Javascript/Miners) that utilises regular expressions (regex) to detect the crypto miners that can be found in the DOM of a given website.
Sample: http://montre24.com/

## Java:/Trojan.Gen.StudioCode!sw

Created a comprehensive [YARA rule](../main/Java/Trojans/StudioCode.yara) that utilises some regular expressions and strings to detect the StudioCode backdoor inside of minecraft plugins.
Sample: <a href="../main/Java/Trojans/StudioCode-sample.jar">StudioCode sample</a>

## VBS:/Downloader.Discord.DiscordTroll!sw

Created a comprehensive [YARA rule](../main/VBS/Downloaders/Discord/DiscordTroll.yara) that utilises some regular expressions and strings to detect the VBScript image file being sent around on discord to spook people and flag their antiviruses.
Sample: https://cdn.discordapp.com/emojis/794755796326940674.png?v=1

## Web:/Spam.Instagram.Netlify!sw

Created a comprehensive [YARA rule](../main/Web/Spam/Instagram/Netlify.yara) that utilises regular expressions (regex) to detect the URLs advertised by Instagram porn bots.
Sample: https://priceless-lewin-1df237.netlify.app

**NOTE: Proceed with caution, I do not advise you not to vist any of the links or download any of the samples unless you know what you are doing, I am not liable for any destruction or infections.**

BurpSuite Extensions
====================
This is an assorted set of various BurpSuite extensions that I've created while doing pentesting and other things.

> **Note**
> Every extension is tested on following configuration
> 
>- BurpSuite 1.6.01 and newest one (I use free and pro version respectively)
>- Jython 2.7
> 
> To send bug reports, feature requests, or whisky, simply drop a mail to michal.melewski@gmail.com

### JSONDecoder (1.1)
Quite simply just a JSON pretty printer with some additional features.

* Ability to remove json garbage (like }]);) - it does a bit of guessing, so not always reliable
* Ability to force JSON decoding on atypical content-type (by default decodes only application/json and text/javascript)

### Argonaut (0.1)
Extension process all request parameters and try to find if they are echoed back in response. Key feature of transformation support (so, will also recognize if for example > is translated to &amp;gt;) under development.

_Pending heavy testing so might not always work as expected._
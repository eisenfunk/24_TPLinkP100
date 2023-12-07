# 24_TPLinkP100 module for fhem
Fhem module for TP-Link Tapo P100/P110/P115 power outlets. Basic on/off is supported as well as power management for P110 devices.

## Installation
Copy the module to your FHEM folder, restart fhem and define your device.

## fhem device definition
<code>define <name> TPLinkP100 [IP/Hostname] [login] [password]</code>

e.g.

<code>define myOfficeOutlet TPLinkP100 192.168.10.110 john@doe.com JohnDoesSecret</code>

login and password is your Tapo App registered login. The documentation is included in the module as usual in german/english. click
on "Help for TPLinkP100" in FhemWeb.

## New Tapo Device authentification

TP-link rolled out new firmware for their devices. Main reason was a massive security leak in their authentification, which is completly changed.
24_TPLinkP100 is supporting the new authentification only and dedicated since version 0.4. You have to use the initial uploaded version of this fhem module If you have placed your devices behind a firewall and block them from updates. I strongly recommend updating your firmware because a) i won't support the old authentification because it is b) unsecure.
Energy measurement is not inplemented after this change, so i will add this in the upcoming weeks.

## Bugs
The module is well tested against Tapo P100, P110 and P115 power outlets. Currently just two major bug are known, that may not be caused by the modules code:

Version 0.3

Powermanagement on P110 is working flawless UNTIL YOU UNPLUG THE POWER OUTLET.
After a powerloss the device is returning **1003 MALFORMED JSON** errors and overall functionality is gone.
The only way to fix this is resetting your device by rpessing the power button for longer than 5 seconds until the led blink yellow/green.
After doing the setup again with the Tapo App the device is working again in fhem without restarting fhem or the module.

Version 0.4 (New auth protocol)

four of my five P100 suddenly sent me 403 forbidden when i tried to define the device. I was unable to use the devices until i changed my password in the tapo app. I've changed from my old password to the same, so no change at all. This did solve the problem.

## Thank you
Many thanks to https://github.com/dswd/OctoPrint-PSUControl-Tapo . They did all the reverse engineering and research. I've just translated the python code into a fhem perl module :)

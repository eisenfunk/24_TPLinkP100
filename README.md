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

## Bugs
The module is well tested against Tapo P100, P110 and P115 power outlets. Currently just one major bug is known, that may not be caused by the modules code:

Powermanagement on P110 is working flawless UNTIL YOU UNPLUG THE POWER OUTLET.
After a powerloss the device is returning **1003 MALFORMED JSON** errors and overall functionality is gone.
The only way to fix this is resetting your device by rpessing the power button for longer than 5 seconds until the led blink yellow/green.
After doing the setup again with the Tapo App the device is working again in fhem without restarting fhem or the module.

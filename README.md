# Tuyapp

C++ client library for the Local Tuya API

## Description

This project takes a lot of its ideas from jasonacox's Python based tinytuya project.

Reason for redeveloping this in C++ is that Python is quite heavy on resources and that does not suit well with embedded machines.

## Examples

There are several (simple) examples included in this project that show how the library can be used. Feel free to use whatever you like from these sources to build your own project using this library. Run ` make examples ` to build and check out these examples.

Additional note: since creating this library, upstream has changed the device keys from having hex numbers only to include special characters that may cause problems attempting to pass on the command line. As a result you may not be able to access some Tuya devices with the `simple_switch` and `simple_energy_monitor` examples without adding additional logic to handle escaping or encoding-decoding of those special characters. The other four examples which reference `tuya-devices.json` for the device specifications do work with the new key format.

## Feedback Welcome!

If you have any problems, questions or comments regarding this project, feel free to contact me! (gordon@bosvangennip.nl)

[![Buy me a beer!](https://raw.githubusercontent.com/gordonb3/cache/master/Algemeen/Buy%20me%20a%20beer!.png)](https://www.paypal.com/donate/?hosted_button_id=USJR8BWKEAEAL)


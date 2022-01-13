# WSAStartup

Source: https://twitter.com/notareverser/status/1477984201601335298
Description: Finding calls to what is likely WSAStartup based upon arguments.

```yara
rule ARGS_WSAStartup_VersionRequested_0x202
{
  strings:
    $call_rel = {68 02 02 00 00 e8 ?? ?? ?? ??}
    $call_abs = {68 02 02 00 00 ff 15 ?? ?? ?? ??}
    $call_reg = {68 02 02 00 00 ff d?}
  condition:
    any of them
}
```

# Generate YARA rule in 140 characters or less!

Source: https://twitter.com/notareverser/status/1478348327989223424
Description: A python script to generate YARA rules

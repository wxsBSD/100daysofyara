# Interesting zip files

Source: https://twitter.com/tylabs/status/1478143087025209356
Description: Look for zip files created on a certain platform. ;)

```yara
rule zip_unix_63 {
  meta:
    author = "@tylabs"
    desc = "detect zips created by unix v6.3"
  strings:
    $header = {504B01023F0314}
  condition:
    uint16be(0) == 0x504B and @header [1] > filesize - 200 and filesize < 200KB
}
```

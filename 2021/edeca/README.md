# Improvements in iterating sections:

Source: https://gist.github.com/edeca/2213636e7a2d58b200e354aa5e79edc3
Description: Some improvements to rules originally written by @greglesnewich
focused on making the rules no longer user a hardcoded section name.

```yara
/*

Original rule from: https://gist.github.com/g-les/0745a9d6cd7f4abb3083a8dee1eaf984

Two variations on the original rule by @greglesnewich.

Conversation on Twitter at: https://twitter.com/edeca/status/1477650229709225990

*/

import "pe"
import "math"

rule SUSP_Very_High_Entropy_Code_Section
{
  meta:
    description = "check for an executable with any code section that is very high entropy."
    DaysofYARA_day = "2/100"
  
  condition:
    for any var_sect in pe.sections: ( //iterate across all of the sections of the PE and for each one (we're using variable named var_sect to make it clear)
        var_sect.characteristics & pe.SECTION_CNT_CODE //check that this section contains executable code
        and
        math.in_range( //set a range
            math.entropy( //calculate entropy
            var_sect.raw_data_offset, var_sect.raw_data_size), // between the start (offset) of the section
            7.8, 8.0) //entropy caps at 8, so lets set a value close to that
          )
}

rule SUSP_Very_High_Entropy_Entry_Section
{
  meta:
    description = "check for a PE file where the section containing the entrypoint is very high entropy."
    DaysofYARA_day = "2/100"
  
  condition:
    for any var_sect in pe.sections: ( //iterate across all of the sections of the PE and for each one (we're using variable named var_sect to make it clear)
        ((var_sect.virtual_address <= pe.entry_point) and pe.entry_point < (var_sect.virtual_address + var_sect.virtual_size)) //check that the entry point is within this section
        and
        math.in_range( //set a range
            math.entropy( //calculate entropy
            var_sect.raw_data_offset, var_sect.raw_data_size), // between the start (offset) of the section
            7.8, 8.0) //entropy caps at 8, so lets set a value close to that
          )
}
```

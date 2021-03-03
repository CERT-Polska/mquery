import "pe"

rule EntryPointExample1
{
    strings:
        $a = { E8 00 00 00 00 }
    condition:
       $a at pe.entry_point
}
rule EntryPointExample2
{
    strings:
        $a = { 9C 50 66 A1 ?? ?? ?? 00 66 A9 ?? ?? 58 0F 85 }
    condition:
       $a in (pe.entry_point..pe.entry_point + 10)
}

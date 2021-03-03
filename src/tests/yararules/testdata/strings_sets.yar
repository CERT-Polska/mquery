rule OfExample4
{
    strings:
        $a = "dummy1"
        $b = "dummy2"
        $c = "dummy3"
    condition:
        1 of them // equivalent to 1 of ($*)
}

rule OfExample5
{
    strings:
        $a = "dummy1"
        $b = "dummy2"
        $c = "dummy3"
    condition:
        for any of ($a,$b,$c) : ( $ )
}

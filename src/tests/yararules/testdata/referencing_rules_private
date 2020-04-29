private rule Rule1
{
    strings:
        $a = "dummy1"
    condition:
        $a
}
rule Rule2
{
    strings:
        $a = "dummy2"
    condition:
        $a and Rule1
}

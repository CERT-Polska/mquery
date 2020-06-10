rule Example
{
    strings:
        $a = "text1"
        $b = "text2"
        $c = "text3"
        $d = "text4"
    condition:
        ($a or $b) and ($c or $d)
}

rule Occurrences
{
    strings:
        $a = "dummy1"
        $b = "dummy2"
    condition:
        for all i in (1,2,3) : ( @a[i] + 10 == @b[i] )
}

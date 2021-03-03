rule AtExample
{
    strings:
        $a = "dummy1"
        $b = "dummy2"
    condition:
        $a at 100 and $b in (0..100)
}

rule AnonymousStrings
{
    strings:
        $ = "dummy1"
        $ = "dummy2"
    condition:
        1 of them
}

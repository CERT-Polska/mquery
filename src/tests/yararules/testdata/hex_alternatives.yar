rule AlternativesExample1
{
    strings:
       $hex_string = { F4 23 ( 62 B4 | 56 ) 45 }

    condition:
       $hex_string
}

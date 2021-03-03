rule XorExample3
{
    strings:
        $xor_string = "Hello" xor wide ascii
    condition:
        $xor_string
}

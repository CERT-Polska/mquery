rule parse_exception_example {
    strings:
        $xor_key_size   = { ((BB)|(68))??020000} 
        $c2         = { FF FF 68 74 74 70 }
    condition:
        all of them
}

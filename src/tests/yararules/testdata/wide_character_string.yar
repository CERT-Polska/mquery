rule WideCharTextExample1
{
    strings:
        $wide_string = "Borland" wide
    condition:
       $wide_string
}

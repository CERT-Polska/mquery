rule WideCharTextExample2
{
    strings:
        $wide_and_ascii_string = "Borland" wide ascii
    condition:
       $wide_and_ascii_string
}

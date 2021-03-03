rule TextExample
{
    strings:
        $text_string = "hello" fullword
    condition:
       $text_string
}

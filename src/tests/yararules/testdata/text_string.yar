rule TextExample
{
    strings:
        $text_string = "hello"
    condition:
       $text_string
}

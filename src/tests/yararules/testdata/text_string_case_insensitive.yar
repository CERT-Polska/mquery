rule CaseInsensitiveTextExample
{
    strings:
        $text_string = "hello" nocase
    condition:
        $text_string
}

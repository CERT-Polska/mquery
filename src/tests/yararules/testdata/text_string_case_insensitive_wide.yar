rule CaseInsensitiveTextExample
{
    strings:
        $text_string = "hello" nocase wide
    condition:
        $text_string
}

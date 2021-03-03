rule PrivateStringExample
{
    strings:
        $text_string = "hello" private
    condition:
        $text_string
}

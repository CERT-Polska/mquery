rule RegExpExample1
{
    strings:
        $re1 = /md5: [0-9a-fA-F]{32}/
        $re2 = /state: (on|off)/
        $re3 = /on|off/
        $re4 = /up|..../
        $re5 = /up(down|\w\w)/
    condition:
        $re1 and $re2 and $re3 and $re4 and $re5
}

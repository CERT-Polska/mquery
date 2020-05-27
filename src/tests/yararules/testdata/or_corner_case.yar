rule or_corner_case
{
    meta:
        description = "presents the problem with discarding other branch from *or* expressions"
        date = "2020-05-19"
    strings:
        $a = "this is a legit string"
        $b = /[a-f]{10}/
    condition:
        $a or $b
}
# How to write good Yara rules

In an ideal world, every YARA rule would be supported equally well by mquery.
Unfortunately, this is not the case. Some rules work great, but some are pretty slow.

In this document, we will give some hints on how to make your rules more
mquery-friendly. It assumes you're already familiar with the YARA language.

We will only cover the basic rules here. To learn more read [this](./yara.md)
document with more details.

## The basics

Simplifying a lot, mquery works by first generating a list of "likely hits", and
later running real YARA on them. Prefiltering works by looking at all input
strings, splitting them into short fragments (called n-grams), and looking
them up separately. For example, this rule:

```yara
rule mquery_example
{
    strings:
        $first = {11 22 33 44 55}
    condition:
        all of them
}
```

Is looking for a sequence of bytes {11 22 33 44 55}. Internally, mquery will
look for:

- files containing a trigram {11 22 33}
- files containing a trigram {22 33 44}
- files containing a trigram {33 44 55}

And AND the resulting sets together. False positives are later sorted out by
running a normal YARA matching on candidate files.

Not only 3grams are used. For plaintext strings and Unicode strings (a-zA-Z0-9)
4-grams (n-grams of length 4, like "firs" and "irst") are used if enabled.

Every condition that can't be checked using just n-grams will be ignored,
- and this means that mquery will stay on the safe side and assume every file satisfies it.

## In practice

Ok, what does it mean in practice? It's easier to understand by looking at
examples where mquery **doesn't** work well:

### bad case 1

```yara
rule MAL_RedLeaves_Apr18_1 {
   meta:
      description = "Detects RedLeaves malware"
      author = "Florian Roth"
      reference = "https://www.accenture.com/t20180423T055005Z__w__/se-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf"
      date = "2018-05-01"
      hash1 = "f6449e255bc1a9d4a02391be35d0dd37def19b7e20cfcc274427a0b39cb21b7b"
      hash2 = "db7c1534dede15be08e651784d3a5d2ae41963d192b0f8776701b4b72240c38d"
      hash3 = "d956e2ff1b22ccee2c5d9819128103d4c31ecefde3ce463a6dea19ecaaf418a1"
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and (
         pe.imphash() == "7a861cd9c495e1d950a43cb708a22985" or
         pe.imphash() == "566a7a4ef613a797389b570f8b4f79df"
      )
}
```

There are three things checked here:

- First two bytes are 0x4d and 0x5a
- File is smaller than 1MB
- PE imphash is either "7a861cd9c495e1d950a43cb708a22985" or "566a7a4ef613a797389b570f8b4f79df".

You probably see where this is going - all of these conditions are ignored.
That's because mquery doesn't care about 2-byte fragments (or their location in the file), or file
size, and can't compute imphash. It won't be able to speed up this YARA rule, and will end up running YARA on every file in the dataset (slow!).

### bad case 2

```yara
rule APT17_Malware_Oct17_Gen {
   meta:
      description = "Detects APT17 malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "https://goo.gl/puVc9q"
      date = "2017-10-03"
      hash1 = "0375b4216334c85a4b29441a3d37e61d7797c2e1cb94b14cf6292449fb25c7b2"
      hash2 = "07f93e49c7015b68e2542fc591ad2b4a1bc01349f79d48db67c53938ad4b525d"
      hash3 = "ee362a8161bd442073775363bf5fa1305abac2ce39b903d63df0d7121ba60550"
   strings:
      $x1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NETCLR 2.0.50727)" fullword ascii
      $x2 = "http://%s/imgres?q=A380&hl=en-US&sa=X&biw=1440&bih=809&tbm=isus&tbnid=aLW4-J8Q1lmYBM" ascii

      $s1 = "hWritePipe2 Error:%d" fullword ascii
      $s2 = "Not Support This Function!" fullword ascii
      $s3 = "Cookie: SESSIONID=%s" fullword ascii
      $s4 = "http://0.0.0.0/1" fullword ascii
      $s5 = "Content-Type: image/x-png" fullword ascii
      $s6 = "Accept-Language: en-US" fullword ascii
      $s7 = "IISCMD Error:%d" fullword ascii
      $s8 = "[IISEND=0x%08X][Recv:] 0x%08X %s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and (
            pe.imphash() == "414bbd566b700ea021cfae3ad8f4d9b9" or
            1 of ($x*) or
            6 of them
         )
      )
}
```

This is a very similar case, but a bit more sinister. This rule will check,
file magic, filesize, and that:

- either file contains one of `$x*` strings
- or file contains `6 of them``
- OR `pe.imphash() == "414bbd566b700ea021cfae3ad8f4d9b9"`

The last condition spoils everything for mquery. Since mquery can't speed it up,
it will have to run yara on every file, in case the imphash matches. In this case, 
consider removing that imphash condition - it will make the query much more
mquery-friendly.

### good cases

What works well then? Everything with at least one reasonably-long string.

For example, this rule:

```yara
rule MiniRAT_Gen_1 {
   meta:
      description = "Detects Mini RAT malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "https://www.eff.org/deeplinks/2018/01/dark-caracal-good-news-and-bad-news"
      date = "2018-01-22"
      hash1 = "091ae8d5649c4e040d25550f2cdf7f1ddfc9c698e672318eb1ab6303aa1cf85b"
      hash2 = "b6ac374f79860ae99736aaa190cce5922a969ab060d7ae367dbfa094bfe4777d"
      hash3 = "ba4e063472a2559b4baa82d5272304a1cdae6968145c5ef221295c90e88458e2"
      hash4 = "ed97719c008422925ae21ff34448a8c35ee270a428b0478e24669396761d0790"
      hash5 = "675c3d96070dc9a0e437f3e1b653b90dbc6700b0ec57379d4139e65f7d2799cd"
   strings:
      $x1 = "\\Mini rat\\" ascii
      $x2 = "\\Projects\\ali\\Clever Components v7\\" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and 1 of them
}
```

Will work great, because even though two conditions can't be
optimised, Mquery will get candidates by looking for files with two provided
strings, and later filter out the false positives efficiently.

# mquery internals

## How does it work?

YARA is pretty fast, but searching through large dataset for given
signature can take a lot of time. We pre-filter the results, so it is only
necessary to run YARA against a small fraction of binaries:

![mquery flowchart](docs/mquery-flowchart.png?raw=1)

Internally this is implemented with a n-gram database called
[ursadb](https://github.com/CERT-Polska/ursadb/).
See [readme](https://github.com/CERT-Polska/ursadb/) for more details.

In short, we look for short (3-4) byte fragments in indexed files, and we can
tell (almost) immediately which files contain given 3-byte pattern. So for
example if you have files:

```
echo "abcde" > abcde
echo "abcxy" > abcxy
echo "asdfg" > xbcdx
```

And rule:

```
rule example
{
    strings:
        $test = "abcd"
    condition:
        $test
}
```

We parse it internally to `"abc" AND "bcd"`, execute both parts of the query
separately and merge the result.

# Known limitations and design decisions.

Mquery's goal is to accelerate Yara queries. It should **always** return the
same results as running Yara on the dataset naively. If it doesn't, please
report a bug.

Because of the specifics of the database engine, we only accelerate a pretty
naive subset of Yara. Additionaly false positives are possible during the
filtering stage. So we still have to re-check all the potential
results with the real Yara binary.

By the way, for parsing yara rules we use and highly recommend
[yaramod](https://github.com/avast/yaramod) library by Avast.

To give you a rough idea what works and what didn't, examples of the
accelerator limitations:

1. Counting strings:

```
rule CountExample
{
    strings:
        $a = "dummy1"
        $b = "dummy2"

    condition:
        #a == 6 and #b > 10
}
```

Is parsed to `("dummy1" AND "dummy2")`. Counting occurences is done by Yara on
the later stage.

2. `at` construct:

```
rule AtExample
{
    strings:
        $a = "dummy1"
        $b = "dummy2"

    condition:
        $a at 100 and $b at 200
}
```

Is parsed to `("dummy1" AND "dummy2")`. Verifying the location is done by Yara
on the later stage.

3. `in` construct:

```
rule InExample
{
    strings:
        $a = "dummy1"
        $b = "dummy2"

    condition:
        $a in (0..100) and $b in (100..filesize)
}
```

Is parsed to `("dummy1" AND "dummy2")`. Again, further verification
will be done in a second stage.


4. Variables:

```
rule FileSizeExample
{
    condition:
       filesize > 200KB
}
```

This is parsed to `()`. We don't accelerate file size queries, so
*all the files* will have to be scanned with yara rule.

Similarly we can't speed up other expressions like:

```
rule IsPE
{
  condition:
     // MZ signature at offset 0 and ...
     uint16(0) == 0x5A4D and

     uint32(uint32(0x3C)) == 0x00004550
}
```

In general, everything that doesn't have an explicit string will not get
accelerated. This is by design - speeding up arbitrarly complex expressions
is out of scope (and probably impossible).

5. `x of y` construct

This will work like you could expect:

```
rule OfExample1
{
    strings:
        $a = "dummy1"
        $b = "dummy2"
        $c = "dummy3"

    condition:
        2 of ($a,$b,$c)
}
```

6. Multiple rules.

```
rule Rule1
{
    strings:
        $a = "dummy1"

    condition:
        $a
}

rule Rule2
{
    strings:
        $a = "dummy2"

    condition:
        $a and Rule1
}
```

This is not supported yet, but it's limitation we're aware of and will
fix in a nearest release. The same goes for private rules feature.

# How to write efficient Yara rules.

If you've read the previous two paragraphs, you probably have a rough idea
what will work and what won't.

- Long strings are where mquery really shines. Let's take the emotet rule:

```
rule emotet4_basic
{
    meta:
        author = "cert.pl"
    strings:
        $emotet4_rsa_public = {
            8d ?? ?? 5? 8d ?? ?? 5? 6a 00 68 00 80 00 00 ff 35 [4] ff
            35 [4] 6a 13 68 01 00 01 00 ff 15 [4] 85
        }
        $emotet4_cnc_list = { 39 ?? ?5 [4] 0f 44 ?? (FF | A3)}
    condition:
        all of them
}
```

This is parsed to the following expression:

```
min 2 of ({8D} & {8D} & {6A006800800000FF35} & {FF35} & {6A136801000100FF15} & {85}, {39} & {0F44})
```

Strings shorter than 3 characters are ignored by all the index types, so
this is further degenerated to:

```
min 2 of ({6A006800800000FF35} & {6A136801000100FF15}, ())
```

And this is equivalent to:

```
{6A006800800000FF35} & {6A136801000100FF15}
```

And yet this is usually pretty fast to query. But few more question marks in
the rule could cripple mquery performance.

- Parser is your friend. If your query runs too slow, check the query plan.

## Known performance limits

TODO: document

 - Max dataset size supported by ursadb
 - Estimated disk space needed per index
 - Estimated required RAM
 - Estimated CPU needed for indexing and querying data

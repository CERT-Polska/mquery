# mquery.py

Automate yara hunts and download of the results.

## Usage

```
$ python3 utils/mquery.py --help
usage: mquery.py [-h] (--yara YARA | --job JOB) [--mquery MQUERY]
                 [--print-filenames] [--print-matches] [--save SAVE]

optional arguments:
  -h, --help         show this help message and exit
  --yara YARA        Yara rule to use for query
  --job JOB          Job ID to print or download
  --mquery MQUERY    Change mquery server address
  --print-filenames  Also print filenames
  --print-matches    Also print matched rules
  --save SAVE        Download samples and save to the provided directory
```

## Example

You can provide either a yara rule (`--yara` parameter) or existing job id
(`--job` parameter). The script will then create a new job or download existing
one, and return all the results as a list of hashes, optionally with filenames
(`--print-filenames`) and matched rules (`--print-matches`). There is also an
option to save samples to a local directory (with `--save DIRNAME`).

For example, to start a new job:

```
$ python3 utils/mquery.py --yara rule.yar
89b27295b3ed353e38ab67c1d21d44578461413249d28d960f1c6fb4195dbb1b
dacdab7b47f0788b20d33a44500cd3396d47894f37e32d0bd54aa2dbb4e5eed0
387e6f8912fb8ded6bca4d16c464bc186ad03759529b7ba8b19a54b590c13ab1
98b7b3faab88ff62720af747195156a3694131aa2fd760753ff48b044da310d4
fcc7183658c7a6f92a580e3ea4ee8f3987b58a4fec08a0a826f5aee2226cda53
ed04594b5bae61d40b8da8c81d9a0cf1b4aba44144f06cca674e0ea98d691dd5
442e658f0adaf384170cddc735d86cb3d5d6f5a6932af77d4080a88551790b53
b2695a80ce56561577ee5b7f31f4b3119782e4b45fad599b33c153acf202a129
0abae63ce933d3f458cd710302a800a87b67bb643a5917098ec97a820dd7232f
4cfda945446db1d2d65fcce3de5322c679ce1b26c3205fb76f2d05ed19d86bf5
```

Use existing job ID, print more information, and save files locally:

```
$ python3 utils/mquery.py --job H3PAW4YF68T0 --print-matches --save test
89b27295b3ed353e38ab67c1d21d44578461413249d28d960f1c6fb4195dbb1b test
dacdab7b47f0788b20d33a44500cd3396d47894f37e32d0bd54aa2dbb4e5eed0 test
387e6f8912fb8ded6bca4d16c464bc186ad03759529b7ba8b19a54b590c13ab1 test
98b7b3faab88ff62720af747195156a3694131aa2fd760753ff48b044da310d4 test
fcc7183658c7a6f92a580e3ea4ee8f3987b58a4fec08a0a826f5aee2226cda53 test
ed04594b5bae61d40b8da8c81d9a0cf1b4aba44144f06cca674e0ea98d691dd5 test
442e658f0adaf384170cddc735d86cb3d5d6f5a6932af77d4080a88551790b53 test
b2695a80ce56561577ee5b7f31f4b3119782e4b45fad599b33c153acf202a129 test
0abae63ce933d3f458cd710302a800a87b67bb643a5917098ec97a820dd7232f test
4cfda945446db1d2d65fcce3de5322c679ce1b26c3205fb76f2d05ed19d86bf5 test

$ ls test | wc -l
10
```

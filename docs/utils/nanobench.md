# nanobench.py

Run performance tests on a local ursadb instance

## Usage

```
$ python3 utils/nanobench.py --help
usage: nanobench.py [-h] [--ursadb URSADB] [--level {nano,mini,heavyduty}]

Simple benchmark utility.

optional arguments:
  -h, --help            show this help message and exit
  --ursadb URSADB       URL of the ursadb instance.
  --level {nano,mini,heavyduty}
                        How hard should the tests be.

```

## Example

```
$ python3 utils/nanobench.py
select "abc";                                                average     10.954 files: 110
select "abcdefgh";                                           average      2.150 files: 0
select "abc" & "qwe" & "zxc";                                average      1.060 files: 0
select "abc" | "qwe" | "zxc";                                average      6.789 files: 285
select min 1 of ("abc", "qwe", "zxc");                       average      1.128 files: 285
...
```

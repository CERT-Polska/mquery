Generation of regression tests files for Yara rules
=======

Test data should be formed in pairs of Yara rule file and result txt file:

E.g.: hex_simple_rule and hex_simple_rule.txt

**Generation of txt files from yara rule files in testdata dir:**

When in src of main mquery directory:

```
python3 -m tests.yararules.generate_yaraparse_result_files
```

**Generation of txt file with file name:**

When in src of main mquery directory:

```
python3 -m tests.yararules.generate_yaraparse_result_files {file_name}
```

\* In {} give name of the file you want to generate txt file from.

All result files will be generated in tests/yararules/testdata directory.

Notice: To run the generation script yaramod needs to be installed.

import argparse
import os
from lib.yaraparse import parse_yara
from lib.yaraparse import combine_rules


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Geenerating result files or file from yara rule file."
    )

    parser.add_argument("file_name", nargs="?", help="File name", default="")

    args = parser.parse_args()

    current_path = os.path.abspath(os.path.dirname(__file__))
    testdir = current_path + "/testdata/"

    if args.file_name:
        with open(testdir + args.file_name) as f:
            data = f.read()

        rules = parse_yara(data)

        result_txt = testdir + args.file_name + ".txt"
        with open(result_txt, "w") as fp:
            fp.write(combine_rules(rules).query + "\n")
    else:
        yara_files = [f for f in os.listdir(testdir) if ".txt" not in f]

        for file in yara_files:
            with open(testdir + file) as f:
                data = f.read()
            rules = parse_yara(data)

            result_txt = testdir + file + ".txt"
            with open(result_txt, "w") as fp:
                fp.write(combine_rules(rules).query + "\n")


if __name__ == "__main__":
    main()

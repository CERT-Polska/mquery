import argparse
import os
from lib.yaraparse import parse_yara  # type: ignore
from lib.yaraparse import combine_rules  # type: ignore

current_path = os.path.abspath(os.path.dirname(__file__))
testdir = current_path + "/testdata/"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate result files or file from yara rule file."
    )

    parser.add_argument("file_name", nargs="?", help="File name", default="")

    args = parser.parse_args()

    if args.file_name:
        with open(testdir + args.file_name) as f:
            data = f.read()

        result_txt = testdir + args.file_name + ".txt"
        write_rules_to_file(data, result_txt)

    else:
        yara_files = [f for f in os.listdir(testdir) if ".txt" not in f]

        for file in yara_files:
            with open(testdir + file) as f:
                data = f.read()

            result_txt = testdir + file + ".txt"
            write_rules_to_file(data, result_txt)


def write_rules_to_file(data, result_txt):
    rules = []
    try:
        rules = parse_yara(data)
        with open(result_txt, "w") as fp:
            fp.write(combine_rules(rules).query + "\n")
    except Exception as e:
        with open(result_txt, "w") as fp:
            fp.write(str(e) + "\n")


if __name__ == "__main__":
    main()

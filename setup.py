#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from pathlib import Path

include_front = (Path(__file__).parent / "src/mqueryfront/build").is_dir()
front_packages = [
    "mquery.mqueryfront.build",
    "mquery.mqueryfront.build.monaco-vs",
    "mquery.mqueryfront.build.monaco-vs.editor",
    "mquery.mqueryfront.build.monaco-vs.base.worker",
    "mquery.mqueryfront.build.monaco-vs.base.browser.ui.codicons.codicon",
    "mquery.mqueryfront.build.static.css",
    "mquery.mqueryfront.build.static.js",
    "mquery.mqueryfront.build.static.media",
]

setup(
    name="mquery",
    version="1.4.0",
    description="DRAKRUN",
    package_dir={"mquery": "src"},
    packages=[
        "mquery",
        "mquery.plugins",
        "mquery.lib",
        "mquery.utils",
    ] + (front_packages if include_front else []),
    package_data={'': ['./**']},
    # include_package_data=True,
    install_requires=open("requirements.txt").read().splitlines(),
    scripts=[
        "src/scripts/mquery-daemon",
    ],
    classifiers=[
        "Programming Language :: Python",
        "Operating System :: OS Independent",
    ],
)

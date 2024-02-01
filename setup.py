#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name="mquery",
    version="1.4.0",
    description="Blazingly fast Yara queries for malware analysts",
    packages=[
        "mquery",
        "mquery.lib",
        "mquery.plugins",
        "mquery.models",
    ],
    package_dir={"mquery": "src"},
    include_package_data=True,
    install_requires=open("requirements.txt").read().splitlines(),
    scripts=[
        "src/scripts/mquery-daemon",
    ],
    classifiers=[
        "Programming Language :: Python",
        "Operating System :: OS Independent",
    ],
)

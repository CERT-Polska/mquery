#!/usr/bin/env python

from setuptools import setup

setup(
    name="mquery",
    version="1.6.0",
    description="Blazingly fast Yara queries for malware analysts",
    packages=[
        "mquery",
        "mquery.lib",
        "mquery.plugins",
        "mquery.models",
        "mquery.migrations",
        "mquery.migrations.versions",
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

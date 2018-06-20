#!/usr/bin/env python
from setuptools import setup

setup(name="kintyre-speedtest-agent",
      version="0.3.0",
      description="Kintyre Shinnecock speedtest agent",
      author="Lowell Alleman",
      author_email="lowell@kintyre.co",
      url="https://github.com/Kintyre/shinnecock-agent",
      py_modules=[
        "kintyre_speedtest",
      ],
      install_requires=[
        "speedtest-cli",
        "ifcfg",
        "requests",
      ],
      entry_points={
        "console_scripts" : [
            "kinytre-speedtest = kintyre_speedtest:main",
        ]
      },
    )

#!/usr/bin/env python
from setuptools import setup

setup(name="KintyreSpeedTestStandalone",
      version="0.0.1",
      description="Kintyre Shinnecock standalone speedtest client",
      author="Lowell Alleman",
      author_email="lowell@kintyre.co",
      url="https://github.com/Kintyre/shinnecock-standalone-client",
      py_modules=[
        "speedtest_ext",
      ],
      install_requires=[ 
        "speedtest-cli",
        "ifcfg",
        "requests", 
      ],
      entry_points={
        "console_scripts" : [
            "kinytre_speedtest = speedtest_ext:main",
        ]
      },
    )


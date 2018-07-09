#!/usr/bin/env python
from io import open
from setuptools import setup

# Causes circular dependency issues (requires ifcfg/speedtest_cli to be installed first)
#from kintyre_speedtest import JSON_FORMAT_VER as ver

# Eventually version should be moved to it's own file.
def get_ver():
    import re
    content = open("kintyre_speedtest.py", encoding="utf-8").read()
    mo = re.search(r'[\r\n]JSON_FORMAT_VER\s*=\s*u?"([^"]+)"', content)
    return mo.group(1)


setup(name="kintyre-speedtest-agent",
      version=get_ver(),
      description="Kintyre Shinnecock speedtest agent",
      long_description=open("README.md").read(),
      long_description_content_type="text/markdown",
      author="Lowell Alleman",
      author_email="lowell@kintyre.co",
      url="https://github.com/Kintyre/shinnecock-agent",
      classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: End Users/Desktop",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Topic :: Communications",
        "Topic :: Internet",
        "Topic :: System :: Networking :: Monitoring",
      ],
      keywords='splunk speedtest',
      license="Apache Software License",
      zip_safe=False,
      py_modules=[
        "kintyre_speedtest",
      ],
      install_requires=[
        "speedtest-cli",
        "ifcfg>=0.17.0",
        "requests",
      ],
      entry_points={
        "console_scripts" : [
            "kintyre-speedtest = kintyre_speedtest:cli",
        ]
      },
    )

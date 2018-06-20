#!/usr/bin/env python
from setuptools import setup

from kintyre_speedtest import JSON_FORMAT_VER as ver


setup(name="kintyre-speedtest-agent",
      version=ver,
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
        "ifcfg",
        "requests",
      ],
      entry_points={
        "console_scripts" : [
            "kinytre-speedtest = kintyre_speedtest:main",
        ]
      },
    )

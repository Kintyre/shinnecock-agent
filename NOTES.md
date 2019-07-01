

# Release checklist

 1. Determine if this should be a major, minor, or patch release.
 1. Run `bumpversion part`  (where part is major, minor or patch).
    This will update the version number in `kintyre_speedtest.py`,
    create a new commit, and tag.
 1. Run `git push origin master --tags` to push both the code changes
    and the new tag.
 1. Travis CI will automatically build and publish the release to PyPI.


Legacy/local package release can be completed by:

 1. Make release:  `python setup sdist bdist_wheel`
 1. Upload:  `twine upload dist/*`\

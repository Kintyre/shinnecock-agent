

# Release checklist

 1. Pick a new version:  (major.minor.patch)
 1. Update version in `kintyre_speedtest.py`
 1. Commit
 1. Create tag in the form:   `v#.#.#` (major.minor.patch)
 1. Push
 1. Make release:  `python setup sdist bdist_wheel`
 1. Upload:  `twine upload dist/*`

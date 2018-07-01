# Maintainers

This file describes how this project is maintained. When making changes to the master
branch, this file tells you who needs to review a pull request and who has the right
to merge it. Additionally, there are other relevant sections describing how to do the
maintenance.

## Project Maintainer

* [Paul Greenberg](https://github.com/greenpau)

## Documentation Management

Before cutting a release, the maintainer MUST validate that she or he has
`pandoc` and `Sphinx` installed.

```
sudo yum -y install pandoc
sudo pip install Sphinx
```

As part of the project's regular build, a maintainer builds documentation with Sphinx.
The maintainer MUST validate the quality of the documentation by building and testing
the documentation in an exposed Docker container.

```
cd docs && make html && docker build -t greenpau/ndmtk-docs . && \
 docker run --rm -p 8000:8000 greenpau/ndmtk-docs
```

The documentation is available via TCP port `8000` of the docker host.


## Pull Request Management

When a Pull Request (PR) passes CI tests and the community successfully resolved any
issues raised during the peer review of the PR, the PR is ready for a merger.

## Release Management

First, the maintainer MUST change the value of the `PLUGIN_VER` in
`Makefile`, because the variable is used to change version references
across the entire project, e.g. CI and Dockerfile references.

```
PLUGIN_VER=0.2.0
```

After that, the maintainer runs `make` to update version references and
create new documentation.:

```bash
make package
git add .
git commit -m 'release: 0.2.0'
```

Then, the maintainer creates a release PR.

The work on release management happens on the main repository, not its fork.

A maintainer should have the following information before cutting a release:
- New release version
- Release name

Next, the maintainer tags the release with an appropriate version and name.
The maintainer pushes the tags to upstream.

```bash
git tag -a v0.2.0 -m "Toucan Release"
git push
git push --tags
```

Next, the maintainer should upload the new release to Test PyPi.

Once the maintainer validated that Test PyPi looks as expected, the maintainer
pushes the code to the main PyPi repository.

## PyPi Management

Initially, the maintainer registered the package with PyPi and TestPyPi with:

```
python setup.py sdist
python setup.py register -r pypi
python setup.py register -r pypitest
```

The names `pypi` and `pypitest` are references from `~/.pypirc` configuration file:

```
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
repository = https://upload.pypi.org/legacy/
username = USERNAME
password = PASSWORD

[testpypi]
repository: https://test.pypi.org/legacy/
username = USERNAME
password = PASSWORD
```

Prior to uploading the module to PyPi, test it with PyPi Test:

```
twine upload --repository testpypi dist/*
```

Once successfully tested, upload it to [PyPi](https://pypi.org):

```
twine upload --repository pypi dist/*
```

.PHONY: docker-build docker-run docker-clean build run clean connect docs

export USER
PLUGIN_NAME="ndmtk"
PLUGIN_NAME_EGG := $(subst -,_,$(PLUGIN_NAME))
PLUGIN_VER=0.2.0
DOCKER_IMAGE_NAME="greenpau/ndmtk"
DOCKER_CONTAINER_NAME="ndmtk"
DOCKER_CONTAINER_SHELL="/bin/sh"
DOCKER_BINARY='docker'
ifneq "${USER}" "root"
  DOCKER_BINARY='sudo docker'
endif

all:
	@echo 'the only available options are: build, run, clean, and status' || false

build:
	@cp -R demo/ docker/alpine/demo
	@cp -R dist/ docker/alpine/dist
	@cd docker/alpine && \
	eval ${DOCKER_BINARY} build -t ${DOCKER_IMAGE_NAME} .
	@rm -rf docker/alpine/{demo,dist}/

run:
	@eval ${DOCKER_BINARY} run -d -t --name=${DOCKER_CONTAINER_NAME} ${DOCKER_IMAGE_NAME} && \
	echo "'"${DOCKER_IMAGE_NAME}"' container was started successfully!" || \
	(echo "failed to start '"${DOCKER_IMAGE_NAME}"'" && \
	eval ${DOCKER_BINARY} inspect --format='ExitCode: {{.State.ExitCode}}' ${DOCKER_CONTAINER_NAME} && \
	eval ${DOCKER_BINARY} inspect --format='Log file: {{.LogPath}}' ${DOCKER_CONTAINER_NAME})

clean:
	@eval ${DOCKER_BINARY} stop ${DOCKER_CONTAINER_NAME} || true
	@eval ${DOCKER_BINARY} rm ${DOCKER_CONTAINER_NAME} || true

status:
	@eval ${DOCKER_BINARY} ps --all | egrep ${DOCKER_CONTAINER_NAME}
	@eval ${DOCKER_BINARY} inspect --format=\"ExitCode: {{.State.ExitCode}}\" ${DOCKER_CONTAINER_NAME} || echo "no such container" && false
	@eval ${DOCKER_BINARY} inspect --format=\"Log file: {{.LogPath}}\" ${DOCKER_CONTAINER_NAME}
	@eval ${DOCKER_BINARY} exec -i -t ${DOCKER_CONTAINER_NAME} hostname

connect:
	@echo ${DOCKER_BINARY} exec -i -t ${DOCKER_CONTAINER_NAME} ${DOCKER_CONTAINER_SHELL}

package:
	@sed -i 's/    VERSION:.*/    VERSION: \x27${PLUGIN_VER}\x27/' circle.yml
	@sed -i 's/pkg_ver =.*/pkg_ver = \x27${PLUGIN_VER}\x27;/' setup.py
	@sed -i 's/-[0-9]\.[0-9]\.[0-9].tar.gz/-${PLUGIN_VER}.tar.gz/;' docker/alpine/Dockerfile
	@sed -i 's/-[0-9]\.[0-9]\.[0-9].tar.gz/-${PLUGIN_VER}.tar.gz/;' docker/centos/Dockerfile
	@sed -i 's/^version =.*/version = u\x27${PLUGIN_VER}\x27/' ./docs/conf.py
	@sed -i 's/^release =.*/release = u\x27${PLUGIN_VER}\x27/' ./docs/conf.py
	@docs/markdown.sh
	@pandoc --from=markdown --to=rst --output=${PLUGIN_NAME}/README.rst README.md
	@sed -i 's/:arrow._up: //' ${PLUGIN_NAME}/README.rst
	@sed -i 's/images\/ndmtk\.png/images\/ndmtk_pypi.png/' ${PLUGIN_NAME}/README.rst
	@cp LICENSE.txt ${PLUGIN_NAME}/LICENSE.txt
	@rm -rf dist/
	@python setup.py sdist
	@rm -rf ${PLUGIN_NAME_EGG}.egg-info *.egg build/
	@find . -name \*.pyc -delete
	@tar -tvf dist/${PLUGIN_NAME}-${PLUGIN_VER}.tar.gz

docs:
	@rm -rf docs/_build/
	@cd docs && make html && cd ..
	@docs/markdown.sh
	@pandoc --from=markdown --to=rst --output=${PLUGIN_NAME}/README.rst README.md
	@sed -i 's/:arrow._up: //' ${PLUGIN_NAME}/README.rst
	@sed -i 's/images\/ndmtk\.png/images\/ndmtk_pypi.png/' ${PLUGIN_NAME}/README.rst
	@cp LICENSE.txt ${PLUGIN_NAME}/LICENSE.txt
	@cd docs && eval ${DOCKER_BINARY} build -t greenpau/ndmtk-docs .
	@echo "run 'docker run --rm -p 8000:8000 greenpau/ndmtk-docs' and review documentation at 'http://localhost:8000'"

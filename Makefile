include k8s.mk

setup:
	pip install -U pip
	pip install -e .[dev]
	pre-commit install

lint: format
	mypy platform_secrets tests

format:
ifdef CI
	pre-commit run --all-files --show-diff-on-failure
else
	pre-commit run --all-files
endif

test_unit:
	pytest -vv --cov=platform_secrets --cov-report xml:.coverage-unit.xml tests/unit

test_integration:
	pytest -vv --maxfail=3 --cov=platform_secrets --cov-report xml:.coverage-integration.xml tests/integration

docker_pull_test_images:
	@eval $$(minikube docker-env); \
	    docker pull ghcr.io/neuro-inc/platformauthapi:latest; \
	    docker tag ghcr.io/neuro-inc/platformauthapi:latest platformauthapi:latest

docker_build:
	rm -rf build dist
	pip install -U build
	python -m build
	docker build -t $(IMAGE_NAME):latest .

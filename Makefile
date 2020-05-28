IMAGE_NAME ?= platformsecrets
IMAGE_TAG ?= latest
ARTIFACTORY_TAG ?=$(shell echo "$(CIRCLE_TAG)" | awk -F/ '{print $$2}')
IMAGE ?= $(GKE_DOCKER_REGISTRY)/$(GKE_PROJECT_ID)/$(IMAGE_NAME)

PLATFORMAPI_TAG=6b56cbdb3ff7ce1cbbd5165bf38f1389902c8fba
PLATFORMAUTHAPI_TAG=e4aa342b8d145abc05cb795c3c07ce90ffdc1f59
PLATFORMCONFIG_TAG=cdbcae372da044f08fbbc9a2548049875ea9a479
PLATFORMCONFIGMIGRATIONS_TAG=cdbcae372da044f08fbbc9a2548049875ea9a479


ifdef CIRCLECI
    PIP_EXTRA_INDEX_URL ?= https://$(DEVPI_USER):$(DEVPI_PASS)@$(DEVPI_HOST)/$(DEVPI_USER)/$(DEVPI_INDEX)
else
    PIP_EXTRA_INDEX_URL ?= $(shell python pip_extra_index_url.py)
    MINIKUBE_SCRIPT="./minikube.sh"
endif
export PIP_EXTRA_INDEX_URL

include k8s.mk

setup:
	@echo "Using extra pip index: $(PIP_EXTRA_INDEX_URL)"
	pip install -r requirements/test.txt

lint:
	black --check platform_secrets tests setup.py
	flake8 platform_secrets tests setup.py
	mypy platform_secrets tests setup.py

format:
	isort -rc platform_secrets tests setup.py
	black platform_secrets tests setup.py

test_unit:
	pytest -vv --cov=platform_secrets --cov-report xml:.coverage-unit.xml tests/unit

test_integration:
	pytest -vv --maxfail=3 --cov=platform_secrets --cov-report xml:.coverage-integration.xml tests/integration

build:
	@docker build -f Dockerfile.k8s -t $(IMAGE_NAME):$(IMAGE_TAG) --build-arg PIP_EXTRA_INDEX_URL="$(PIP_EXTRA_INDEX_URL)" .

gke_login:
	sudo chown circleci:circleci -R $$HOME
	@echo $(GKE_ACCT_AUTH) | base64 --decode > $(HOME)//gcloud-service-key.json
	gcloud auth activate-service-account --key-file $(HOME)/gcloud-service-key.json
	gcloud config set project $(GKE_PROJECT_ID)
	gcloud --quiet config set container/cluster $(GKE_CLUSTER_NAME)
	gcloud config set $(SET_CLUSTER_ZONE_REGION)
	gcloud version
	docker version
	gcloud auth configure-docker

gke_docker_pull_test_images:
	docker pull $(GKE_DOCKER_REGISTRY)/$(GKE_PROJECT_ID)/platformapi:$(PLATFORMAPI_TAG)
	docker pull $(GKE_DOCKER_REGISTRY)/$(GKE_PROJECT_ID)/platformauthapi:$(PLATFORMAUTHAPI_TAG)
	docker pull $(GKE_DOCKER_REGISTRY)/$(GKE_PROJECT_ID)/platformconfig:$(PLATFORMCONFIG_TAG)
	docker pull $(GKE_DOCKER_REGISTRY)/$(GKE_PROJECT_ID)/platformconfig-migrations:$(PLATFORMCONFIGMIGRATIONS_TAG)
	docker tag $(GKE_DOCKER_REGISTRY)/$(GKE_PROJECT_ID)/platformapi:$(PLATFORMAPI_TAG) platformapi:latest
	docker tag $(GKE_DOCKER_REGISTRY)/$(GKE_PROJECT_ID)/platformauthapi:$(PLATFORMAUTHAPI_TAG) platformauthapi:latest
	docker tag $(GKE_DOCKER_REGISTRY)/$(GKE_PROJECT_ID)/platformconfig:$(PLATFORMCONFIG_TAG) platformconfig:latest
	docker tag $(GKE_DOCKER_REGISTRY)/$(GKE_PROJECT_ID)/platformconfig-migrations:$(PLATFORMCONFIG_TAG) platformconfig-migrations:latest

gke_docker_push: build
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(IMAGE):latest
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(IMAGE):$(CIRCLE_SHA1)
	docker push $(IMAGE)

_helm:
	curl https://raw.githubusercontent.com/kubernetes/helm/master/scripts/get | bash -s -- -v v2.11.0

gke_k8s_deploy: _helm
	gcloud --quiet container clusters get-credentials $(GKE_CLUSTER_NAME) $(CLUSTER_ZONE_REGION)
	helm -f deploy/platformmonitoringapi/values-$(HELM_ENV).yaml --set "IMAGE=$(IMAGE):$(CIRCLE_SHA1)" upgrade --install platformmonitoringapi deploy/platformmonitoringapi/ --wait --timeout 600

artifactory_docker_push: build
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(ARTIFACTORY_DOCKER_REPO)/$(IMAGE_NAME):$(ARTIFACTORY_TAG)
	docker login $(ARTIFACTORY_DOCKER_REPO) --username=$(ARTIFACTORY_USERNAME) --password=$(ARTIFACTORY_PASSWORD)
	docker push $(ARTIFACTORY_DOCKER_REPO)/$(IMAGE_NAME):$(ARTIFACTORY_TAG)

artifactory_helm_push: _helm
	mkdir -p temp_deploy/platformmonitoringapi
	cp -Rf deploy/platformmonitoringapi/. temp_deploy/platformmonitoringapi
	cp temp_deploy/platformmonitoringapi/values-template.yaml temp_deploy/platformmonitoringapi/values.yaml
	sed -i "s/IMAGE_TAG/$(ARTIFACTORY_TAG)/g" temp_deploy/platformmonitoringapi/values.yaml
	find temp_deploy/platformmonitoringapi -type f -name 'values-*' -delete
	helm init --client-only
	helm package --app-version=$(ARTIFACTORY_TAG) --version=$(ARTIFACTORY_TAG) temp_deploy/platformmonitoringapi/
	helm plugin install https://github.com/belitre/helm-push-artifactory-plugin
	helm push-artifactory $(IMAGE_NAME)-$(ARTIFACTORY_TAG).tgz $(ARTIFACTORY_HELM_REPO) --username $(ARTIFACTORY_USERNAME) --password $(ARTIFACTORY_PASSWORD)

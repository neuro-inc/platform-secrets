# platform-secrets

## Local Development

1. Install minikube (https://github.com/kubernetes/minikube#installation);
2. Authenticate local docker:
```shell
gcloud auth configure-docker  # part of `make gke_login`
```
3. Launch minikube:
```shell
./minikube.sh start
```
4. Make sure the kubectl tool uses the minikube k8s cluster:
```shell
minikube status
kubectl config use-context minikube
```
5. Apply minikube configuration and some k8s fixture services:
```shell
export GHCR_TOKEN=<ghcr-token>
./minikube.sh apply
```
6. Create a new virtual environment with Python 3.7:
```shell
python -m venv venv
source venv/bin/activate
```
7. Install testing dependencies:
```shell
make setup
```
8. Run the unit test suite:
```shell
make test_unit
```
9. Run the integration test suite:
```shell
make test_integration
```
10. Cleanup+shutdown minikube:
```shell
./minikube.sh clean
./minikube.sh stop
```

#!/usr/bin/env bash
set -o verbose


function minikube::start {
    echo "Starting minikube..."
    minikube config set WantUpdateNotification false
    minikube start --driver=docker --wait=all --wait-timeout=5m
    kubectl config use-context minikube
}

function minikube::apply_all_configurations {
    echo "Applying configurations..."
    kubectl config use-context minikube
    kubectl create secret docker-registry ghcr \
        --docker-server ghcr.io \
        --docker-username x-access-token \
        --docker-password $GHCR_TOKEN \
        --docker-email dev@apolo.us \
        --dry-run=client \
        --output yaml \
        | kubectl apply -f -
    kubectl apply -f tests/k8s/rb.default.gke.yml
    kubectl apply -f tests/k8s/platformapi.yml
}

function minikube::clean {
    echo "Cleaning up..."
    kubectl config use-context minikube
    kubectl delete -f tests/k8s/platformapi.yml
    kubectl delete -f tests/k8s/rb.default.gke.yml
}

function minikube::stop {
    echo "Stopping minikube..."
    kubectl config use-context minikube
    minikube::clean
    minikube stop
}

function check_service() { # attempt, max_attempt, service
    local attempt=1
    local max_attempts=$1
    local service=$2
    echo "Checking service $service..."
    until minikube service $service --url; do
	if [ $attempt == $max_attempts ]; then
	    echo "Can't connect to the container"
            exit 1
	fi
	sleep 1
	((attempt++))
    done
}

function minikube::apply {
    minikube status
    minikube::apply_all_configurations

    max_attempts=30
    check_service $max_attempts platformauthapi
}


case "${1:-}" in
    start)
        minikube::start
        ;;
    apply)
        minikube::apply
        ;;
    clean)
        minikube::clean
        ;;
    stop)
        minikube::stop
        ;;
esac

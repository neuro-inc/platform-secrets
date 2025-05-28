#!/usr/bin/env bash


function k8s::install_minikube {
    curl -LO https://github.com/kubernetes/minikube/releases/latest/download/minikube-linux-amd64
    sudo install minikube-linux-amd64 /usr/local/bin/minikube && rm minikube-linux-amd64
}

function k8s::start {
    minikube start \
        --driver=docker \
        --wait=all \
        --wait-timeout=5m
}

function k8s::apply_all_configurations {
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


function k8s::stop {
    sudo -E minikube stop || :
    sudo -E minikube delete || :
    sudo -E rm -rf ~/.minikube
    sudo rm -rf /root/.minikube
}


function k8s::test {
    kubectl delete jobs testjob1 2>/dev/null || :
    kubectl create -f tests/k8s/pod.yml
    for i in {1..300}; do
        if [ "$(kubectl get job testjob1 --template {{.status.succeeded}})" == "1" ]; then
            exit 0
        fi
        if [ "$(kubectl get job testjob1 --template {{.status.failed}})" == "1" ]; then
            exit 1
        fi
        sleep 1
    done
    echo "Could not complete test job"
    kubectl describe job testjob1
    exit 1
}

case "${1:-}" in
    install)
        k8s::install_kubectl
        ;;
    start)
        k8s::start
        ;;
    apply)
        k8s::apply_all_configurations
        ;;
    stop)
        k8s::stop
        ;;
    test)
        k8s::test
        ;;
esac

# On Windows, this file must be run within WSL.
# The .kubeconfig associated with the WSL kubectl is *NOT* the same as the one used in Windows. 
# Verify cluster access within WSL using 'kubectl config get-contexts' and, if  necessary, add the required context using e.g. 'aws --region {aws.region} eks update-kubeconfig --name {cluster.name}'. If the cluster was created via script-runner 'eks-cluster-create' then the kubeconfig files will be configured correctly.

# Docker build and deployment actions require additional parameters to be supplied to the make command line.
# Command line format: 'make ... PARAM1={Value1} PARAM2={Value2}'
# For docker-build, docker-push, deploy:
#	- REPO_URI - Required parameter. AWS URI of the repo into which deploy the image. (This will also name the locally created Docker image.)
#   - TAG - Optional parameter. Tag identifying the specific image to be used. If not specified, defaults to the value of appVersion in Chart.yaml.
# For deploy, additionally:
#   - CLUSTER_ARN - Required parameter. The ARN that identifies the K8s context into which deployment should occur.
# 	- ROLE_ARN - Required parmameter. The AWS ARN of the IAM role granting access to read Nodes. Can be generated using the script-runner script 'acmCertificateAgent-prepare-config'
#   - NAMESPACE - Required parameter. The kubernetes namespace into which the controller will be deployed.
#   - NAME_PREFIX - Optional parameter. Prefix to be applied to the standard name of objects created in K8S. Default is unset. acmCertificateAgent is intended to run as a singleton at the cluster level.

# := syntax means expression is evaluated immediately.
TAG:=${shell grep -Po '(?<=appVersion:).+$$' Chart.yaml | sed -n "s/^\([^\"']*[\"']\(.*\)[\"'][^\"']*\|\s*\([^\"'].*[^\s\"']*\)\s*\)$$/\2\3/ p"}

AWS_REGION:=${shell echo ${REPO_URI} | grep -Po '(?<=ecr\.)(?:[^-]+-)+[0-9]+'}
AWS_ACCOUNTID:=${shell echo ${REPO_URI} | grep -Po '(?<=^)[0-9]+'}
AWS_REGISTRY:=${shell echo ${REPO_URI} | grep -Po '^[^\/]+'}

ifneq ($(NAME_PREFIX),)
NAME=${NAME_PREFIX}-acm-certificate-agent
else
NAME=acm-certificate-agent
endif

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: helm-debug
helm-debug: #Write out debugging informaiton and generate the intermediate yaml file for the Helm chart.
	${call ndef,NAMESPACE}
	${call ndef,TAG}
	${call ndef,NAME}
	helm template --namespace ${NAMESPACE} --set image.repository="(Will be substituted by makefile parameter REPO_URI)",image.tag=${TAG},serviceAccount.iamRoleArn="(Will be substituted by makefile parameter ROLE_ARN)" ${NAME} . --debug > debug.yaml

##@ Build

.PHONY: build
build: fmt vet ## Build manager binary.
	go build -o bin/manager main.go

.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	${call ndef,REPO_URI}
	${call ndef,TAG}
	docker build -t ${REPO_URI}:${TAG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	${call ndef,AWS_REGION}
	${call ndef,AWS_REGISTRY}
	${call ndef,REPO_URI}
	${call ndef,TAG}
	aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${AWS_REGISTRY}
	docker push ${REPO_URI}:${TAG}

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: deploy
deploy: ## Deploy controller to the K8s cluster specified by {CLUSTER_ARN}.
	${call ndef,CLUSTER_ARN}
	${call ndef,NAMESPACE}
	${call ndef,REPO_URI}
	${call ndef,TAG}
	${call ndef,ROLE_ARN}
	${call ndef,NAME}
	helm install --kube-context ${CLUSTER_ARN} --namespace ${NAMESPACE} --set image.repository=${REPO_URI},image.tag=${TAG},serviceAccount.iamRoleArn=${ROLE_ARN} ${NAME} .

.PHONY: undeploy
undeploy: ## Undeploy controller from the K8s cluster specified by {CLUSTER_ARN}. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	${call ndef,CLUSTER_ARN}
	${call ndef,NAMESPACE}
	${call ndef,NAME}
	helm uninstall --kube-context ${CLUSTER_ARN} --namespace ${NAMESPACE} ${NAME}

##@ Build Dependencies

## Helpers

# Guard to ensure required user configurable parameters have been supplied. Call using '${call ndef,{PARAMETER_NAME}}'
ndef = $(if $(value $(1)),,$(error Required parameter '$(1)' not set))
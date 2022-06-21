# acm-certificate-agent
TODO

<br/>

## Description
TODO

<br/>

## Cluster installation

### Prerequisites
You will need:
- An AWS EKS cluster with at least one node group, and the ARN associated with this cluster.
- An AWS ECR repository in which to deploy the operator image, and the URI associated with this repository. 
- Local installations of golang, kubectl, aws-cli and helm. On Windows, these should be installed within WSL.
- Local installation of script-runner, if intending to use scripted IAM role/policy creation.

    **NOTE:** The .kubeconfig associated with the WSL kubectl is *NOT* the same as the one used in Windows. 
Verify cluster access within WSL using `kubectl config get-contexts` and, if  necessary, add the required context using e.g. `aws --region {aws.region} eks update-kubeconfig --name {cluster.name}`. 

### Procedure

1. Create an IAM role and associated policy that grants permission for the relevant EC2 operations.
   
    ```
    script-runner scripts\nodeInstanceDecorator-prepare-config -p "cluster.arn:{CLUSTER_ARN}"
    ```

    Note the ARN of the role that is created.


2. Build and push the operator image to ECR.
	
    ```sh
    make docker-build docker-push REPO_URI={REPOSITORY_URI}
    ```

    **NOTE:** On Windows, run this command within WSL.
	
3. Deploy the operator to the cluster.

    ```sh
    make deploy REPO_URI={REPOSITORY_URI} CLUSTER_ARN={CLUSTER_ARN} ROLE_ARN={ROLE_ARN}
    ```
    
    **NOTE:** On Windows, run this command within WSL.

    Existing worker nodes should be processed and their corresponding EC@ instance names updated automatically. You can view these names using e.g. the AWS EC2 web  console or CLI.

## Uninstallation
Remove the operator from the cluster using:

```sh
make undeploy
```

<br/>

## How it works
This project uses the Kubernetes [Operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)

It was built from a kubebuilder project and subsequently modified to use Helm.

It uses [Controllers](https://kubernetes.io/docs/concepts/architecture/controller/) 
which provides a reconcile function responsible for synchronizing resources until the desired state is reached on the cluster.

**NOTE:** Run `make --help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

<br/>

## Debugging 
To debug the Helm chart and inspect the intermediate yaml file that is created run:

```sh
make helm-debug
```

Output will be generated as `debug.yaml`


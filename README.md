# keystone-k8s-auth
[![null](https://charmhub.io/keystone-k8s-auth/badge.svg)](https://charmhub.io/keystone-k8s-auth)

## Description

This charmed operator manages the Keystone K8s Auth component of the OpenStack
Cloud Provider.

## Usage

The charm requires keystone credentials and connection information, which
can be provided via the `keystone` relation from the [Keystone charm](https://charmhub.io/keystone).

## Deployment

### The full process

```bash
juju deploy charmed-kubernetes
juju config kubernetes-control-plane allow-privileged=true
juju deploy keystone-k8s-auth
juju integrate keystone-k8s-auth:certificates easyrsa:client
juju integrate keystone-k8s-auth:kube-control kubernetes-control-plane:kube-control
juju integrate keystone-k8s-auth:keystone     keystone:identity-credentials
juju integrate keystone-k8s-auth:juju-info    kubernetes-control-plane:juju-info
```

You must also tell the cluster on which it is deployed that it will be
acting as an authentication and authorization provider.
For Charmed Kubernetes, you'll need to configure the auth settings

### Optional Configuration

**release**
This charm comes packed with support for multiple versions of the keystone-k8s-auth deployment. 
By default it will choose the latest if unspecified, but can be specifically tuned if desired
to an existing known release at the time of the charm build. 

One can list which release are available in the charm using the action:

```sh
juju run keystone-k8s-auth list-versions
```

**keystone-ssl-ca**
This charm by default will pick up the root ca from the `certificates` relation in order to 
contact keystone if it is using https. If keystone exists in another model, one may override
the keystone CA certificate using this configuration.

```sh
juju config keystone-k8s-auth keystone-ssl-ca=$(cat /path/to/ca.cert)
```

**replicas**
This charm by default will install 2 replica pods in the deployment, but this be changed for less or 
more pods are required.

```sh
juju config keystone-k8s-auth replicas=1
```


### Authentication or Authorization
```bash
# find the service ip in the cluster, apply as the authn webhook
service_url=$(juju run keystone-k8s-auth/leader get-service-url | yq '.service-url')
juju config kubernetes-control-plane authn-webhook-endpoint="${service_url}"
```

### Authorization

For authorization, you'll need to build a [webhook_config](https://github.com/kubernetes/cloud-provider-openstack/blob/master/examples/webhook/keystone-apiserver-webhook.yaml) file.

```bash
juju run keystone-k8s-auth/leader generate-webhook-config | yq '.webhook-config' > webhook
juju config kubernetes-control-plane authorization-webhook-config-file="$(cat webhook)"
juju config kubernetes-control-plane authorization-mode="Node,Webhook,RBAC"
```

### Removing

Before removing, ensure the control-plane is ignoring the service

```bash
juju config kubernetes-control-plane \
    --reset authorization-webhook-config-file \
    --reset authorization-mode \
    --reset authn-webhook-endpoint
juju remove-application keystone-k8s-auth
```

## Contributing

Please see the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines
on enhancements to this charm following best practice guidelines, and
[CONTRIBUTING.md](https://github.com/canonical/keystone-k8s-auth-operator/blob/main/CONTRIBUTING.md)
for developer guidance.

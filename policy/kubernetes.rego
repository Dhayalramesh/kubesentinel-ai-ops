# Conftest policy-as-code for the manifests in k8s/.  Run:  conftest test k8s/ --policy policy/
package main

import rego.v1

workloads := {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}

pod_spec := input.spec.template.spec if input.kind in workloads

containers contains c if some c in pod_spec.containers

pinned(image) if regex.match(`(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})$`, image)

deny contains msg if {
	some c in containers
	endswith(c.image, ":latest")
	msg := sprintf("%s/%s: container %q uses the :latest tag", [input.kind, input.metadata.name, c.name])
}

deny contains msg if {
	some c in containers
	not pinned(c.image)
	msg := sprintf("%s/%s: container %q image must have a pinned tag or digest", [input.kind, input.metadata.name, c.name])
}

deny contains msg if {
	some c in containers
	c.securityContext.privileged == true
	msg := sprintf("%s/%s: container %q must not be privileged", [input.kind, input.metadata.name, c.name])
}

deny contains msg if {
	some c in containers
	not c.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("%s/%s: container %q needs readOnlyRootFilesystem: true", [input.kind, input.metadata.name, c.name])
}

deny contains msg if {
	some c in containers
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("%s/%s: container %q must set allowPrivilegeEscalation: false", [input.kind, input.metadata.name, c.name])
}

deny contains msg if {
	some c in containers
	not c.resources.limits.memory
	msg := sprintf("%s/%s: container %q needs a memory limit", [input.kind, input.metadata.name, c.name])
}

deny contains msg if {
	some c in containers
	not c.resources.limits.cpu
	msg := sprintf("%s/%s: container %q needs a CPU limit", [input.kind, input.metadata.name, c.name])
}

deny contains msg if {
	input.kind in workloads
	not pod_spec.securityContext.runAsNonRoot == true
	msg := sprintf("%s/%s: pod must set runAsNonRoot: true", [input.kind, input.metadata.name])
}

deny contains msg if {
	input.kind in workloads
	not pod_spec.automountServiceAccountToken == false
	msg := sprintf("%s/%s: automountServiceAccountToken must be false unless the workload needs the API", [input.kind, input.metadata.name])
}

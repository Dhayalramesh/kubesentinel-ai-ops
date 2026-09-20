package main

import rego.v1

good := {
	"kind": "Deployment",
	"metadata": {"name": "ok"},
	"spec": {"template": {"spec": {
		"automountServiceAccountToken": false,
		"securityContext": {"runAsNonRoot": true},
		"containers": [{
			"name": "c",
			"image": "ghcr.io/x/y:1.2.3",
			"securityContext": {"readOnlyRootFilesystem": true, "allowPrivilegeEscalation": false},
			"resources": {"limits": {"cpu": "1", "memory": "1Gi"}},
		}],
	}}},
}

test_good_deployment_passes if count(deny) == 0 with input as good

test_latest_tag_denied if {
	bad := json.patch(good, [{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value": "x/y:latest"}])
	count(deny) > 0 with input as bad
}

test_untagged_denied if {
	bad := json.patch(good, [{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value": "x/y"}])
	count(deny) > 0 with input as bad
}

test_privileged_denied if {
	bad := json.patch(good, [{"op": "add", "path": "/spec/template/spec/containers/0/securityContext/privileged", "value": true}])
	count(deny) > 0 with input as bad
}

test_missing_limits_denied if {
	bad := json.patch(good, [{"op": "remove", "path": "/spec/template/spec/containers/0/resources/limits/memory"}])
	count(deny) > 0 with input as bad
}

test_root_denied if {
	bad := json.patch(good, [{"op": "replace", "path": "/spec/template/spec/securityContext/runAsNonRoot", "value": false}])
	count(deny) > 0 with input as bad
}

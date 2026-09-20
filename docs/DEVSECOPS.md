# DevSecOps notes

## Pipeline
Defined in `.github/workflows/`. `ci.yml` runs lint and tests. `devsecops.yml` runs SAST, secrets, SCA, IaC,
policy-as-code, SBOM and a vulnerability gate, and is scheduled weekly so new CVEs are caught without code changes.
`container.yml` builds the image, scans it, and pushes to GHCR only if the scan passed. `k8s-e2e.yml` deploys the image
to a kind cluster in a namespace that enforces the Pod Security `restricted` profile, then checks that the pod runs
as UID 10001 with a read-only root filesystem.

## Why actions are pinned by commit SHA
Mutable tags can be moved. In March 2026 attackers force-pushed nearly all version tags of
`aquasecurity/trivy-action` to malicious commits (advisory GHSA-69fq-xp46-6x23 on the aquasecurity/trivy repository).
Workflows referencing a tag silently ran attacker code. Here every third-party action is pinned to a full commit SHA
with the version in a comment, Trivy is additionally pinned to a specific binary version, and Gitleaks and Conftest are
installed as checksum-verified release binaries instead of third-party actions.

**Before you rely on a pinned SHA, verify it** (compare against the project's release page). Dependabot opens PRs to
bump actions; review each bump instead of auto-merging.

## Baseline exceptions
- `CKV_K8S_43` (image digest) is skipped by annotation in `k8s/deployment.yaml`: the digest only exists after the image
  is pushed, so the release process adds it. A tag is still required by `policy/kubernetes.rego`.
- The ZAP job is informational: Streamlit renders over websockets, so a baseline scan sees little.

## Enforcement in a cluster
`k8s/policies/kyverno-policies.yaml` enforces the same rules at admission time (needs Kyverno installed).

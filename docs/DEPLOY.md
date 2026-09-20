# Deploying KubeSentinel

## 1. Streamlit Community Cloud (free, recommended for the live demo)
1. Push this repo to GitHub (public).
2. Go to https://share.streamlit.io, sign in with GitHub, click **Create app**.
3. Repository: `Dhayalramesh/kubesentinel-ai-ops`, branch `main`, main file `app.py`.
4. **Advanced settings**: pick Python 3.12, then paste into *Secrets*:
   ```toml
   GROQ_API_KEY = "gsk_your_key_here"
   ```
   Leave the secret out to run the mock baseline (clearly labelled in the UI).
5. Deploy. Free apps sleep when idle; the first visit after a sleep takes a few seconds.

The demo is read-only: no cluster access, dry-run only, a per-session cap on LLM runs, and a mock fallback when the
API errors or rate-limits. Use a Groq key you can rotate.

## 2. Docker
```bash
docker build -t kubesentinel-ai-ops .
docker run --rm -p 8501:8501 -e GROQ_API_KEY=... kubesentinel-ai-ops     # or -e KUBESENTINEL_FORCE_MOCK=1
```

## 3. Kubernetes (kind, minikube or a real cluster)
```bash
kind create cluster
docker build -t kubesentinel-ai-ops:local . && kind load docker-image kubesentinel-ai-ops:local
sed -i 's#ghcr.io/dhayalramesh/kubesentinel-ai-ops:0.1.0#kubesentinel-ai-ops:local#; s#imagePullPolicy: Always#imagePullPolicy: IfNotPresent#' k8s/deployment.yaml
kubectl apply -k k8s/
kubectl -n kubesentinel create secret generic kubesentinel-groq --from-literal=GROQ_API_KEY=...   # optional
kubectl -n kubesentinel port-forward svc/kubesentinel 8501:80
```
Do not commit the modified `deployment.yaml`; the workflow does the same substitution on its own checkout.

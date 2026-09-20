FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app.py ./
COPY kubesentinel ./kubesentinel
COPY evals/RESULTS.md ./evals/RESULTS.md
COPY evals/results ./evals/results
COPY .streamlit ./.streamlit

# Numeric non-root user so Kubernetes can verify runAsNonRoot
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
    && chown -R 10001:10001 /app
USER 10001

EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=4).status == 200 else 1)"

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]

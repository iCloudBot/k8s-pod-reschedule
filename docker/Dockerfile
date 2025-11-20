FROM python:3.12-alpine AS builder

RUN apk add binutils && \
    pip install --index-url https://mirrors.aliyun.com/pypi/simple/ --trusted-host mirrors.aliyun.com --no-cache-dir pyinstaller

WORKDIR /app
COPY main.py pod-reschedule.py

RUN pyinstaller --onefile pod-reschedule.py

FROM python:3.12-alpine

LABEL maintainer="hello@yjh.me"
LABEL description="Kubernetes Pod Auto Reschedule Controller"

COPY --from=builder /app/dist/pod-reschedule /usr/bin/pod-reschedule

RUN apk upgrade --no-cache && \
    apk add tzdata curl --no-cache && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime  && \
    curl -L -o /usr/bin/kubectl "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    chmod +x /usr/bin/kubectl && \
    mkdir /logs /kube

ENV CHECK_INTERVAL=90 \
    POD_ABNORMAL_THRESHOLD=300 \
    LOG_DIR=/logs \
    SCALE_WAIT_SECONDS=5 \
    MONITOR_NAMESPACES="" \
    EXCLUDE_NAMESPACES="kube-system,kube-public,kube-node-lease"

CMD ["pod-reschedule"]
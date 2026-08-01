# The binary is cross-compiled on the host (see dev/deploy.sh) and copied in.
FROM gcr.io/distroless/static-debian12:nonroot
COPY bin/cilock-k8s /cilock-k8s
ENTRYPOINT ["/cilock-k8s"]

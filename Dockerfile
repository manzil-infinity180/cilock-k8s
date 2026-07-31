# The binary is cross-compiled on the host (see `make image`) because the Go
# module graph reaches into a local rookery/cilock checkout via replace
# directives that are outside the Docker build context.
FROM gcr.io/distroless/static-debian12:nonroot
COPY bin/cilock-k8s /cilock-k8s
ENTRYPOINT ["/cilock-k8s"]

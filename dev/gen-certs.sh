#!/usr/bin/env bash
# Generate a throwaway CA and a serving certificate for the webhook service.
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p .tls
cd .tls

SVC="cilock-webhook.cilock-system.svc"

if [ -f tls.crt ] && openssl x509 -checkend 3600 -noout -in tls.crt >/dev/null 2>&1; then
  echo "webhook TLS certs already present"
  exit 0
fi

openssl req -nodes -new -x509 -days 365 -keyout ca.key -out ca.crt \
  -subj "/CN=cilock-k8s webhook CA" 2>/dev/null

openssl req -nodes -new -newkey rsa:2048 -keyout tls.key -out tls.csr \
  -subj "/CN=${SVC}" 2>/dev/null

openssl x509 -req -days 365 -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out tls.crt \
  -extfile <(printf "subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth" "${SVC}") 2>/dev/null

echo "generated webhook TLS certs in dev/.tls"

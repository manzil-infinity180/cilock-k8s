.PHONY: build test e2e dev-up dev-prepare dev-deploy dev-test dev-down

build:
	go build ./...

test:
	go test ./...

# Full local demo: cluster + registry, attest demo image, deploy webhook, run
# the admission e2e.
e2e: dev-up dev-prepare dev-deploy dev-test

dev-up:
	./dev/kind-up.sh

dev-prepare:
	./dev/gen-certs.sh
	./dev/attest-demo.sh

dev-deploy:
	./dev/deploy.sh

dev-test:
	./dev/e2e.sh

dev-down:
	./dev/down.sh

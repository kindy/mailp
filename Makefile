
GO ?= go
BUILD_OPTS ?= -trimpath
GOFLAGS ?=
GO_LDFLAGS :=
# GO_LDFLAGS += -s -w
# GO_LDFLAGS += -X main.Version=$(VERSION)
GO_LDFLAGS += $(GO_EXTRA_LDFLAGS)

.PHONY: help
help:
	echo "make mailp - build mailp binary"
	echo "make gen-testcert - generate cert for unit test (not required)"

.PHONY: mailp
mailp:
	$(GO) build $(BUILD_OPTS) $(GOFLAGS) -ldflags "$(GO_LDFLAGS)" -o $@

.PHONY: gen-testcert
gen-testcert:
	openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 \
		-out mailp-test.cert \
		-keyout mailp-test.key \
		-subj "/CN=mailp-test.local"

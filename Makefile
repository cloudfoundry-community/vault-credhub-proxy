APP_NAME       :=vault-credhub-proxy
DESTDIR        ?=/usr/local
RELEASE_ROOT   ?=builds
TARGETS        ?=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
APP_PATH       ?=./$(APP_NAME)
TEST_PATH      ?=./ci/script/tests

GO_LDFLAGS := -ldflags="-X main.Version=$(VERSION)"

.PHONY: use build test testbuild install require-% release-% clean
use:
	@echo "Using $(shell $(APP_PATH) -v 2>&1) at location $(APP_PATH)"

vet:
	go vet $(go list ./... | grep -v vendor)

build: vet
	go build $(GO_LDFLAGS) -o $(APP_PATH)
	#$(APP_PATH) -v

test:
	go test -v ./...

testbuild: $(if $(wildcard $(APP_PATH)),use,build)
	$(TEST_PATH) $(APP_PATH)

install: build
	mkdir -p $(DESTDIR)/bin
	cp $(APP_PATH) $(DESTDIR)/bin

require-%:
	@ if [ "${${*}}" = "" ]; then \
		echo "Environment variable $* not set"; \
		exit 1; \
	fi

RELEASES := $(foreach target,$(TARGETS),release-$(target)-$(APP_NAME))

release-all: $(RELEASES)

define build-target
release-$(1)/$(2)-$(APP_NAME): require-VERSION
	@echo "Building $(APP_NAME) $(VERSION) ($(1)/$(2)) ..." 
	GOOS=$(1) GOARCH=$(2) go build -o $(RELEASE_ROOT)/$(APP_NAME)-$(VERSION)-$(1)-$(2)$(if $(patsubst windows,,$(1)),,.exe) $(GO_LDFLAGS)
	@ls -la $(RELEASE_ROOT)/$(APP_NAME)-$(VERSION)-$(1)-$(2)$(if $(patsubst windows,,$(1)),,.exe)
	@echo ""
endef

$(foreach target,$(TARGETS),$(eval $(call build-target,$(word 1, $(subst /, ,$(target))),$(word 2, $(subst /, ,$(target))))))

clean:
	rm -rf $(APP_PATH) $(RELEASE_ROOT) 

.DEFAULT_GOAL := release-all

# get repo dir path
REPO_DIR := $(shell pwd)

##@ Help
.PHONY: help
help: ## Display this help screen
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)


##@ Dependencies

BUILD_IMAGE ?= kindlingproject/kernel-builder:latest

# check if build docker image exists, if not exit download it from docker hub
# check if linux-headers are installed, if not exit download them from kernel.org
.PHONY: deps
deps: ## Install dependencies
	@echo "Installing dependencies..."; \
        if [ -z "$(shell docker images -q $(BUILD_IMAGE))" ]; then \
		echo "Downloading build image..."; \
		docker pull $(BUILD_IMAGE); \
	else \
		echo "Build image already exists"; \
	fi
	@echo "Checking for linux-headers...";
	if [ -z "$(shell dpkg -l | grep linux-headers-$(shell uname -r))" ]; then \
		echo "Downloading linux-headers..."; \
		sudo apt-get install linux-headers-$(shell uname -r); \
	else \
		echo "Linux-headers already installed"; \
	fi


##@ Build

OUTPUT_DIR ?= $(REPO_DIR)/kindling-falcolib-probe

# build and tar the output
.PHONY: build
build: deps ## Build kernel
	@echo "Building falcolib-probe..."
	@docker run --rm -it \
	    -v /usr:/host/usr \
	    -v /lib/modules:/host/lib/modules \
		-v $(REPO_DIR):/source \
		$(BUILD_IMAGE)
	@echo "Packaging falcolib-probe..."; \
        tar -cvzf kindling-falcolib-probe.tar.gz $(OUTPUT_DIR)


.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	@rm -rf $(OUTPUT_DIR)
	@rm -rf kindling-falcolib-probe.tar.gz


##@ Test
.PHONY: simple
simple: ## simple test

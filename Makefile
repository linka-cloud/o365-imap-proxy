# Copyright 2022 Linka Cloud  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

MODULE = go.linka.cloud/wirego

VERSION_SUFFIX = $(shell git diff --quiet || echo "-dev")
VERSION = $(shell git describe --tags --exact-match 2> /dev/null || echo "`git describe --tags $$(git rev-list --tags --max-count=1) 2> /dev/null || echo v0.0.0`-`git rev-parse --short HEAD 2>/dev/null`")$(VERSION_SUFFIX)
TAG = $(shell git describe --tags --exact-match 2> /dev/null)

version: ## Show the current program version
	@echo $(VERSION)

IMAGE = linkacloud/o365-imap-proxy

.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	@docker build -t $(IMAGE):$(VERSION) .
ifneq ($(TAG),)
	@docker tag $(IMAGE):$(VERSION) $(IMAGE):latest
endif

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	@docker push $(IMAGE):$(VERSION)
ifneq ($(TAG),)
	@docker push $(IMAGE):latest
endif

.PHONY: docker
docker: docker-build docker-push ## Build and push docker image to the registry.


help: ## Display this help.
	@ggrep -Eh '\s##\s' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

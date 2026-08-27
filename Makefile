.PHONY: test e2e docker-test docker-e2e docker-build shell syntax

## Run everything locally.
test:
	bundle exec rspec

## Run only the end-to-end SAML flows locally.
e2e:
	bundle exec rspec spec/e2e

docker-build:
	docker compose build

## Run everything in Docker (what CI runs).
docker-test: docker-build
	docker compose run --rm test

## Run only the end-to-end flows in Docker.
docker-e2e: docker-build
	docker compose run --rm e2e

shell: docker-build
	docker compose run --rm test bash

## Parse every file under the oldest Ruby the gemspec supports.
## The CI matrix still runs Ruby 2.5, so spec/ must avoid 3.0+ syntax
## (endless methods, hash shorthand, ...) until the floor is raised.
MIN_RUBY ?= 2.5
syntax:
	@docker run --rm --platform linux/amd64 -v "$(PWD)":/app -w /app ruby:$(MIN_RUBY)-slim \
	  bash -c 'fail=0; for f in $$(find lib spec -name "*.rb"); do \
	    ruby -c "$$f" >/dev/null || { echo "FAIL $$f"; fail=1; }; done; \
	    [ $$fail -eq 0 ] && echo "all files parse under Ruby $(MIN_RUBY)"'

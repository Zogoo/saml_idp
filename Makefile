.PHONY: test e2e docker-test docker-e2e docker-build shell

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

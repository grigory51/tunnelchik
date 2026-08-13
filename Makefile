.PHONY: test vet build release

test:
	go test -race ./...

vet:
	go vet ./...

build:
	go build -o tunnelchik/tunnelchik ./tunnelchik

BUMP ?= patch
release:
	@test -z "$$(git status --porcelain)" || { echo "error: working tree is dirty"; exit 1; }
	@last=$$(git tag --list 'v*' --sort=-v:refname | head -1); \
	last=$${last:-v0.0.0}; \
	ver=$${last#v}; \
	major=$${ver%%.*}; rest=$${ver#*.}; minor=$${rest%%.*}; patch=$${rest#*.}; \
	case "$(BUMP)" in \
	  major) major=$$((major+1)); minor=0; patch=0 ;; \
	  minor) minor=$$((minor+1)); patch=0 ;; \
	  patch) patch=$$((patch+1)) ;; \
	  *) echo "error: BUMP must be major|minor|patch"; exit 1 ;; \
	esac; \
	next="v$$major.$$minor.$$patch"; \
	echo "$$last -> $$next"; \
	git tag -a "$$next" -m "$$next" && git push origin "$$next"

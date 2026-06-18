.PHONY: build clean

build:
	go build -o cloakid cmd/cloakid/main.go

install: build
	cp cloakid /usr/local/bin/

clean:
	rm -f cloakid

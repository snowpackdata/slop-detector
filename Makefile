.PHONY: build run clean

build:
	swiftc -O -o slop-detector SlopDetector.swift -framework Cocoa -framework Carbon

run: build
	./slop-detector

clean:
	rm -f slop-detector

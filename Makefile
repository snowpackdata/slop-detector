.PHONY: build run clean setup

MODEL_URL = https://github.com/snowpackdata/slop-detector/releases/download/model-v1.0/slop-detector-model.tar.gz

build:
	swiftc -O -o slop-detector SlopDetector.swift -framework Cocoa -framework Carbon -framework CoreML

setup:
	@if [ -d "model/SlopDetectorModel.mlpackage" ]; then \
		echo "Model already installed."; \
	else \
		echo "Downloading model (117 MB)..."; \
		mkdir -p model; \
		curl -L --progress-bar $(MODEL_URL) | tar xz -C model; \
		echo "Model installed at model/"; \
	fi

run: build setup
	./slop-detector

clean:
	rm -f slop-detector
	rm -rf model/

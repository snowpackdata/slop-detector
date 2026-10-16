.PHONY: build run clean setup app install

MODEL_URL = https://github.com/snowpackdata/slop-detector/releases/download/model-v1.0/slop-detector-model.tar.gz
APP_NAME = Slop Detector.app

build:
	swiftc -O -o slop-detector SlopDetector.swift -framework Cocoa -framework Carbon -framework CoreML

setup:
	@if [ -d "model/SlopDetectorModel.mlpackage" ]; then \
		echo "Model already installed."; \
	else \
		echo "Downloading model (117 MB)..."; \
		mkdir -p model; \
		curl -L --progress-bar $(MODEL_URL) | tar xz -C model; \
		echo "Model installed."; \
	fi

app: build setup
	@echo "Packaging $(APP_NAME)..."
	@rm -rf "$(APP_NAME)"
	@mkdir -p "$(APP_NAME)/Contents/MacOS"
	@mkdir -p "$(APP_NAME)/Contents/Resources"
	@cp slop-detector "$(APP_NAME)/Contents/MacOS/"
	@cp Info.plist "$(APP_NAME)/Contents/"
	@cp AppIcon.icns "$(APP_NAME)/Contents/Resources/"
	@cp -R model "$(APP_NAME)/Contents/Resources/model"
	@codesign --force --deep --sign - "$(APP_NAME)"
	@echo "Built $(APP_NAME)"

install: app
	@echo "Installing to /Applications..."
	@rm -rf "/Applications/$(APP_NAME)"
	@cp -R "$(APP_NAME)" "/Applications/$(APP_NAME)"
	@echo "Installed. Open from Spotlight or /Applications."

run: build setup
	./slop-detector

clean:
	rm -f slop-detector
	rm -rf model/
	rm -rf "$(APP_NAME)"

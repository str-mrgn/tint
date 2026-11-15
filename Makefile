GOBGP_VERSION := 3.30.0
BIN_DIR := bin

.PHONY: all image tint openpcc gobgp clean

all: gobgp tint openpcc

image:
	docker build -t srv6-router:latest .

tint:
	mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/tint ./cmd/tint

openpcc:
	mkdir -p $(BIN_DIR)
	$(MAKE) -C openpcc
	cp -f openpcc/build/srv6-pcc $(BIN_DIR)/srv6-pcc

gobgp:
	mkdir -p $(BIN_DIR)
	@if [ ! -f $(BIN_DIR)/gobgpd ]; then \
		echo "Downloading GoBGP v$(GOBGP_VERSION)..."; \
		wget -qO /tmp/gobgp.tar.gz https://github.com/osrg/gobgp/releases/download/v$(GOBGP_VERSION)/gobgp_$(GOBGP_VERSION)_linux_amd64.tar.gz; \
		tar -xzf /tmp/gobgp.tar.gz -C $(BIN_DIR) gobgp gobgpd; \
		rm -f /tmp/gobgp.tar.gz; \
	fi

clean:
	rm -rf $(BIN_DIR)
	$(MAKE) -C openpcc clean

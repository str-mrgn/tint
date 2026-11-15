CC = gcc
CFLAGS = -Wall -Wextra -g -O2 -pthread
LDFLAGS = -pthread

SRCDIR = src
INCDIR = include
BUILDDIR = build

SOURCES = $(SRCDIR)/main.c \
          $(SRCDIR)/pcc/pcep_client.c \
          $(SRCDIR)/kernel/netlink_route.c \
          $(SRCDIR)/srv6/path_manager.c

OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(BUILDDIR)/%.o)
TARGET = $(BUILDDIR)/srv6-pcc

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJECTS)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $^
	@echo "Build complete: $(TARGET)"

$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(INCDIR) -c -o $@ $<

clean:
	rm -rf $(BUILDDIR)
	@echo "Clean complete"

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/
	@echo "Installation complete"

run: $(TARGET)
	$(TARGET) -p fc00::1 -l fc00::2 -P 4189

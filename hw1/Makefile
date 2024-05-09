CC := gcc
CFLAGS := -shared -fPIC
LDLIBS := -ldl

logger.so: logger.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

.PHONY: clean

clean:
	rm -f logger.so

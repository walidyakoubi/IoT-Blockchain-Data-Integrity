CONTIKI_PROJECT = udp-client
all: $(CONTIKI_PROJECT)

# tinyAES: provides AES_init_ctx + AES_ECB_encrypt, used by ccm.h
PROJECT_SOURCEFILES += aes.c
CFLAGS += -Os

CONTIKI = /home/the_jacobi/contiki-ng
include $(CONTIKI)/Makefile.include
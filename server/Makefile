INCLUDES= -I$(HOME)/include -I$(PWD)/../common
STATIC_LIBS= $(addprefix $(HOME)/lib/, librpc.a librho.a)

#CPPFLAGS= $(INCLUDES) -DRHO_DEBUG -DRHO_TRACE -DNSM_DO_BENCH
#CPPFLAGS= $(INCLUDES) -DNSM_DO_BENCH
CPPFLAGS= $(INCLUDES)
CFLAGS= -Wall -Werror -Wextra
LDFLAGS= $(STATIC_LIBS) -lssl -lcrypto -lpthread

OBJS= nsmserver.o nsm_util.o

nsmserver: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

nsmserver.o: nsmserver.c ../common/nsm.h ../common/nsm_util.h

nsm_util.o: ../common/nsm_util.c
	$(CC) -c -o $@ $(CPPFLAGS) $(CFLAGS) $< 

clean:
	rm -f nsmserver $(OBJS)

.PHONY: clean

# Utilities
#----------------------------------------------------------
RM= rm -f 
MKDIR= mkdir -p
INSTALL= install -p
INSTALL_DATA= $(INSTALL) -m 0644

# If you don't have install, you can use "cp" instead.
# 
# INSTALL= cp -p
# INSTAL_EXEC= $(INSTALL)
# INSTAL_DATA= $(INSTALL)
#
# Install Location
# See, also, the local target
#----------------------------------------------------------
INSTALL_TOP= /usr/local
INSTALL_LIB= $(INSTALL_TOP)/lib

# Library to install
#----------------------------------------------------------
TO_LIB= nsm-engine.so


#CFLAGS = -fPIC -Wall -Werror -I $(HOME)/include -I $(PWD)/../common \
		 -DNSM_DO_BENCH
CFLAGS = -fPIC -Wall -Werror -I $(HOME)/include -I $(PWD)/../common
STATIC_PIC_LIBS=$(addprefix $(HOME)/lib/,librpc-pic.a librho-pic.a)

SHARED_LIB= nsm-engine.so
OBJS= nsm-engine.o nsm_util.o

$(SHARED_LIB): $(OBJS)
	$(CC) -shared -o $@ $(OBJS) $(STATIC_PIC_LIBS) -lcrypto

nsm-engine.o: nsm-engine.c
	$(CC) $(CFLAGS) -o $@ -c $^
nsm_util.o: ../common/nsm_util.c
	$(CC) $(CFLAGS) -o $@ -c $^

clean:
	$(RM) $(SHARED_LIB) $(OBJS)

install:
	$(MKDIR) $(INSTALL_LIB)
	$(INSTALL_DATA) $(TO_LIB) $(INSTALL_LIB)

uninstall:
	cd $(INSTALL_LIB) && $(RM) $(TO_LIB)


test:
	openssl engine -t -v -c -pre NSM_SERVER:unix:///tmp/talkingheads $(PWD)/nsm-engine.so

.PHONY: clean test install

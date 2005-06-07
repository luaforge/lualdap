# $Id: Makefile,v 1.24 2005-06-07 17:06:30 tomas Exp $

T= lualdap
V= 1.0
CONFIG= ./config

include $(CONFIG)

AR= ar rcu
RANLIB= ranlib

OBJS= src/lualdap.o $(COMPAT_DIR)/compat-5.1.o
LIB= src/lib$T-$V.a


dynamic: src/$(LIBNAME)
src/$(LIBNAME): $(OBJS)
	export MACOSX_DEPLOYMENT_TARGET="10.3"; $(CC) $(CFLAGS) $(LIB_OPTION) -o src/$(LIBNAME) $(OBJS) -lldap

lib: $(LIB)
 $(LIB): $(OBJS)
	$(AR) $@ $(OBJS)
	$(RANLIB) $@

$(COMPAT_DIR)/compat-5.1.o: $(COMPAT_DIR)/compat-5.1.c
	$(CC) -c $(CFLAGS) -o $@ $(COMPAT_DIR)/compat-5.1.c

install: dynamic src/$(LIBNAME)
	mkdir -p $(LUA_LIBDIR)
	cp src/$(LIBNAME) $(LUA_LIBDIR)
	ln -f -s $(LUA_LIBDIR)/$(LIBNAME) $(LUA_LIBDIR)/$T.so

clean:
	rm -f $(OBJS) $(LIB) src/$(LIBNAME)

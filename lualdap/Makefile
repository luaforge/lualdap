# System's libraries directory (where binary libraries are installed)
LUA_LIB_DIR= /usr/local/lib/lua/5.0
# OS dependent
#LIB_EXT= .so
LIB_EXT= .dylib
#LIB_OPTION= -shared #for Linux
LIB_OPTION= -dynamiclib #for MacOS X

# On FreeBSD systems, the following line should be commented
DLLIB= -ldl

COMPAT_DIR= ../compat
WARN= -O2 -Wall -fPIC -W -Waggregate-return -Wcast-align -Wmissing-prototypes -Wnested-externs -Wshadow -Wwrite-strings -ansi
#WARN= -Wall -Wmissing-prototypes -Wmissing-declarations -ansi
INCS= -I/usr/local/include/lua5 -I$(COMPAT_DIR)
LIBS_DIR= -L/usr/lib
LIBS= $(LIBS_DIR) -llua -llualib -lm $(DLLIB)
CFLAGS= $(WARN) $(INCS)
CC= gcc

T= lualdap
V= 1.0
VERSION= $Vb
PKG= lualdap-$(VERSION)
DIST_DIR= $(PKG)
TAR_FILE= $(PKG).tar.gz
ZIP_FILE= $(PKG).zip
SRCS= README Makefile \
	lualdap.c lualdap.def loader.tmpl \
	test.lua \
	index.html manual.html license.html lualdap.png 

AR= ar rcu
RANLIB= ranlib

OBJS= lualdap.o compat-5.1.o
LIB= lib$T$(VERSION).a
LIBNAME= lib$T$(VERSION)$(LIB_EXT)

dist: dist_dir
	tar -czf $(TAR_FILE) $(DIST_DIR);
	zip -lq $(ZIP_FILE) $(DIST_DIR)/*
	rm -rf $(DIST_DIR)

dist_dir:
	mkdir $(DIST_DIR);
	cp $(SRCS) $(DIST_DIR);

lib: $(LIB)
 $(LIB): $(OBJS)
	$(AR) $@ $(OBJS)
	$(RANLIB) $@

dynamic: $(LIBNAME)
$(LIBNAME): $(OBJS)
	$(CC) $(CFLAGS) $(LIB_OPTION) -o $(LIBNAME) $(OBJS) $(LIBS) -lldap

install: lib $(LIBNAME)
	mkdir -p $(LUA_LIB_DIR)
	cp $(LIBNAME) $(LUA_LIB_DIR)
	cd $(LUA_LIB_DIR); ln -f -s $(LIBNAME) $T$(LIB_EXT)

compat-5.1.o: $(COMPAT_DIR)/compat-5.1.c
	$(CC) -c $(CFLAGS) -o $@ $(COMPAT_DIR)/compat-5.1.c

clean:
	rm -f $(OBJS) $(LIB) $(SO) $(DYLIB) $(DLL) $(TAR_FILE) $(ZIP_FILE)

# $Id: Makefile,v 1.15 2004-11-09 14:11:56 tomas Exp $

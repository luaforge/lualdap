# System's libraries directory (where binary libraries are installed)
LIB_DIR= /usr/lib
#LIB_EXT= .so
LIB_EXT= .dylib
#LIB_OPTION= -shared
LIB_OPTION= -dynamiclib

# On FreeBSD systems, the following line should be commented
DLLIB= -ldl

COMPAT_DIR= ../compat
WARN= -O2 -Wall -fPIC -W -Waggregate-return -Wcast-align -Wmissing-prototypes -Wnested-externs -Wshadow -Wwrite-strings -ansi
#WARN= -Wall -Wmissing-prototypes -Wmissing-declarations -ansi
INCS= -I/usr/local/include/lua5 -I$(COMPAT_DIR)
LIBS_DIR=
LIBS= -L$(LIB_DIR) -llua -llualib -lm $(DLLIB)
CFLAGS= $(WARN) $(INCS)
CC= gcc

T= lualdap
V= 1.0
VERSION= $Vb
PKG= lualdap-$(VERSION)
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

dist:
	mkdir $(PKG);
	cp $(SRCS) $(PKG);
	tar -czf $(TAR_FILE) $(PKG);
	zip -lq $(ZIP_FILE) $(PKG)/*
	rm -rf $(PKG)

lib: $(LIB)
 $(LIB): $(OBJS)
	$(AR) $@ $(OBJS)
	$(RANLIB) $@

dynamic: $(LIBNAME)
$(LIBNAME): $(OBJS)
	$(CC) $(CFLAGS) $(LIB_OPTION) -o $(LIBNAME) $(OBJS) $(LIBS) -lldap

#so: $(SO)
#$(SO): $(OBJ)
#	gcc -o $@ -shared $(OBJ) $(LIBS_DIR) $(LIBS)

#dylib: $(DYLIB)
#$(DYLIB): $(OBJ)
#	libtool -dynamic -compatibility_version $V -current_version $V -o $@ $(OBJ) $(LIBS_DIR) $(LIBS) -lcc_dynamic -lc

install: lib $(LIBNAME)
	mkdir -p $(LIB_DIR)
	cp $(LIBNAME) $(LIB_DIR)
	ln -f -s $(LIB_DIR)/$(LIBNAME) $(LIB_DIR)/$T$(LIB_EXT)

compat-5.1.o: $(COMPAT_DIR)/compat-5.1.c
	$(CC) -c $(CFLAGS) -o $@ $(COMPAT_DIR)/compat-5.1.c

clean:
	rm -f $(OBJS) $(LIB) $(SO) $(DYLIB) $(DLL) $(TAR_FILE) $(ZIP_FILE)

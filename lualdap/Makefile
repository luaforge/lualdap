COMPAT_DIR= ../compat
WARN= -Wall -Wmissing-prototypes -Wmissing-declarations -ansi
INCS= -I/usr/local/include/lua5 -I$(COMPAT_DIR)
LIBS_DIR=
LIBS= -llua -llualib -lm -lldap -ldl
CFLAGS= -g $(MYCFLAGS) $(WARN) $(INCS) $(DEFS)

V= 1.0
VERSION= $Va
PKG= lualdap-$(VERSION)
TAR_FILE= $(PKG).tar.gz
ZIP_FILE= $(PKG).zip
SRCS= README Makefile \
	lualdap.c lualdap.def loader.tmpl \
	test.lua \
	index.html manual.html license.html lualdap.png 

AR= ar rcu
RANLIB= ranlib

OBJ= lualdap.o compat-5.1.o
LIB= liblualdap$(VERSION).a
SO= liblualdap$(VERSION).so
DYLIB= liblualdap$(VERSION).dylib
DLL= lualdap$(VERSION).dll

dist:
	mkdir $(PKG);
	cp $(SRCS) $(PKG);
	tar -czf $(TAR_FILE) $(PKG);
	zip -lq $(ZIP_FILE) $(PKG)/*
	rm -rf $(PKG)

lib: $(LIB)
 $(LIB): $(OBJ)
	$(AR) $@ $(OBJ)
	$(RANLIB) $@

so: $(SO)
$(SO): $(OBJ)
	sed -e "s/LIB_NAME/$(SO)/" loader.tmpl > lualdap.lua
	gcc -o $@ -shared $(OBJ) $(LIBS_DIR) $(LIBS)

dylib: $(DYLIB)
$(DYLIB): $(OBJ)
	sed -e "s/LIB_NAME/$(DYLIB)/" loader.tmpl > lualdap.lua
	#gcc -o $@ -dynamiclib $(OBJ) $(LIBS_DIR) $(LIBS)
	libtool -dynamic -compatibility_version $V -current_version $V -o $@ $(OBJ) $(LIBS_DIR) $(LIBS) -lcc_dynamic -lc

compat-5.1.o: $(COMPAT_DIR)/compat-5.1.c
	$(CC) -c $(CFLAGS) -o $@ $(COMPAT_DIR)/compat-5.1.c

clean:
	rm -f $(OBJ) $(LIB) $(SO) $(DYLIB) $(DLL) $(TAR_FILE) $(ZIP_FILE)

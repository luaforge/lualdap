WARN= -Wall -Wmissing-prototypes -Wmissing-declarations -ansi
INCS= -I/usr/local/include/lua5
LIBS_DIR=
LIBS= -llua.5.0 -llualib.5.0 -lm -lldap -ldl
CFLAGS= -g $(MYCFLAGS) $(WARN) $(INCS) $(DEFS)

VERSION= 1.0a
PKG= lualdap-$(VERSION)
TAR_FILE= $(PKG).tar.gz
ZIP_FILE= $(PKG).zip
SRCS= README Makefile \
	lualdap.c loader.tmpl \
	test.lua \
	index.html manual.html lua.png 

AR= ar rcu
RANLIB= ranlib

OBJ= lualdap.o
LIB= liblualdap.$(VERSION).a
SO= liblualdap.$(VERSION).so
DYLIB= liblualdap.$(VERSION).dylib
DLL= lualdap.$(VERSION).dll

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
	gcc -o $@ -dynamiclib $(OBJ) $(LIBS_DIR) $(LIBS)

clean:
	rm -f $(OBJ) $(LIB) $(SO) $(DYLIB) $(DLL)

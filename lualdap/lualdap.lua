if not lualdap and loadlib then
	local libname = "liblualdap.1.0a.dylib"
	local libopen = "lualdap_libopen"
	local init, err1, err2 = loadlib (libname, libopen)
	assert (init, (err1 or '')..(err2 or ''))
	init ()
end

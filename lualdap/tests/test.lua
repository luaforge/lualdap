#!/usr/local/bin/lua
-- LuaLDAP test file.
-- $Id: test.lua,v 1.1 2003-06-15 11:56:00 tomas Exp $

function print_attrs (attrs)
	io.write (string.format (" [dn] : %s\n", attrs.dn))
	for name, values in pairs (attrs) do
		if name ~= "dn" then
			io.write ("["..name.."] : ")
			if type (values) == "table" then
				for i = 1, (table.getn (values)-1) do
					io.write (values[i]..",")
				end
				io.write (values[table.getn(values)])
			else
				io.write (values)
			end
			io.write ("\n")
		end
	end
end

require"lualdap"

if table.getn(arg) < 1 then
	print (string.format ("Usage %s host[:port] base", arg[0]))
	os.exit()
end

local hostname = arg[1]
--local who = arg[2]
--local password = arg[3]
local base = arg[2]
local filter = arg[3] or "objectclass=*"
local attribs = {}
for n = 4, table.getn(arg) do
	attribs[n-3] = arg[n]
end

assert (lualdap, "couldn't load LDAP library")
local ld = assert (lualdap.open_simple (hostname, who, password))
assert (ld:close () == 1, "couldn't close connection")
assert (pcall (ld.close, ld) == false)

local ld = assert (lualdap.open_simple (hostname, who, password))

-- search
--for msg, attrs in ld:search_attribs (base, "subtree", filter, attribs) do
	--print_attrs (attrs)
--end
--print ("search ok")

-- compare
--print("compare", ld:compare ("videoID=676DE,ou=video,dc=teste,dc=br", "videoTitulo", "Tecnologias de Video Digital"))

-- modify
print("modify", ld:modify ("videoID=676DE,ou=video,dc=teste,dc=br", {
	{ op = "a", type = "videoTitulo", values = "Tecnologias de Video Digital" },
}))


--[[
print"!!!"

for msg, attrs in ld:search_attribs (base, "subtree", filter, { "videoID" }) do
	print_attrs (attrs)
end

print"!!!"

local iter1, state1, first1 = ld:search_attribs (base, "subtree", filter, { "dn", "objectClass", "videoTitulo", })
local iter2, state2, first2 = ld:search_attribs (base, "subtree", filter, { "dn", "videoID", "videoTitulo", })

local m1,a1 = iter1 (state1, first1)
io.write ("\n 1 >")
print_attrs (a1)
local m2,a2 = iter2 (state2, first2)
io.write ("\n 2 >")
print_attrs (a2)
m1,a1 = iter1 (state1, m1)
io.write ("\n 3 >")
print_attrs (a1)
m2,a2 = iter2 (state2, m2)
io.write ("\n 4 >")
print_attrs (a2)
--]]

assert (ld:close () == 1, "couldn't close connection")
print("ok")

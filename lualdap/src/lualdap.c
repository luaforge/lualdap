/*
** LuaLDAP
** $Id: lualdap.c,v 1.8 2003-08-12 14:37:56 tomas Exp $
*/

#include <stdlib.h>
#include <string.h>

#include <ldap.h>

#include <lua.h>
#include <lauxlib.h>


#define LUALDAP_PREFIX "LuaLDAP: "
#define LUALDAP_TABLENAME "lualdap"
#define LUALDAP_CONNECTION_METATABLE "LuaLDAP connection"
#define LUALDAP_SEARCH_METATABLE "LuaLDAP search"

#define LUALDAP_MOD_ADD (LDAP_MOD_ADD | LDAP_MOD_BVALUES)
#define LUALDAP_MOD_DEL (LDAP_MOD_DELETE | LDAP_MOD_BVALUES)
#define LUALDAP_MOD_REP (LDAP_MOD_REPLACE | LDAP_MOD_BVALUES)

/* Maximum number of attributes managed in an operation */
#ifndef LUALDAP_MAX_ATTRS
#define LUALDAP_MAX_ATTRS 100
#endif

/* Size of buffer of NULL-terminated arrays of pointers to struct values */
#ifndef LUALDAP_ARRAY_VALUES_SIZE
#define LUALDAP_ARRAY_VALUES_SIZE (2 * LUALDAP_MAX_ATTRS)
#endif

/* Maximum number of values structures */
#ifndef LUALDAP_MAX_VALUES
#define LUALDAP_MAX_VALUES (LUALDAP_ARRAY_VALUES_SIZE / 2)
#endif


/* LDAP connection information */
typedef struct {
	int        closed;
	int        version; /* LDAP version */
	LDAP      *ld;      /* LDAP connection */
} conn_data;


/* LDAP search context information */
typedef struct {
	int      closed;
	int      conn;        /* conn_data reference */
	int      msgid;
} search_data;


/* LDAP attribute modification structure */
typedef struct {
	LDAPMod   *attrs[LUALDAP_MAX_ATTRS + 1];
	LDAPMod    mods[LUALDAP_MAX_ATTRS];
	int        ai;
	BerValue  *values[LUALDAP_ARRAY_VALUES_SIZE];
	int        vi;
	BerValue   bvals[LUALDAP_MAX_VALUES];
	int        bi;
} attrs_data;


int lualdap_libopen (lua_State *L);


/*
** Typical error situation.
*/
static int faildirect (lua_State *L, const char *errmsg) {
    lua_pushnil (L);
    lua_pushstring (L, errmsg);
    return 2;
}


/*
** Get a connection object from the first stack position.
*/
static conn_data *getconnection (lua_State *L) {
	conn_data *conn = (conn_data *)luaL_checkudata (L, 1, LUALDAP_CONNECTION_METATABLE);
	luaL_argcheck(L, conn!=NULL, 1, LUALDAP_PREFIX"LDAP connection expected");
	luaL_argcheck(L,!conn->closed,1,LUALDAP_PREFIX"LDAP connection is closed");
	return conn;
}


/*
** Get a search object from the first upvalue position.
*/
static search_data *getsearch (lua_State *L) {
	search_data *search = (search_data *)luaL_checkudata (L, lua_upvalueindex (1), LUALDAP_SEARCH_METATABLE);
	luaL_argcheck (L, search!=NULL, 1, LUALDAP_PREFIX"LDAP search expected");
	luaL_argcheck (L,!search->closed,1,LUALDAP_PREFIX"LDAP search is closed");
	return search;
}


/*
** Set metatable of userdata on top of the stack.
*/
static void lualdap_setmeta (lua_State *L, char *name) {
	luaL_getmetatable (L, name);
	lua_setmetatable (L, -2);
}


/*
** Initialize attributes structure.
*/
static void init_attrs (attrs_data *attrs) {
	attrs->ai = 0;
	attrs->attrs[0] = NULL;
	attrs->vi = 0;
	attrs->values[0] = NULL;
	attrs->bi = 0;
}


/*
** Copy a string on top of the stack to the next berval array position.
*/
static void str2bvals (lua_State *L, int str, attrs_data *attrs) {
	attrs->bvals[attrs->bi].bv_len = lua_strlen (L, str);
	attrs->bvals[attrs->bi].bv_val = (char *)lua_tostring (L, str);
	attrs->bi++;
}


/*
** Store a pointer to new berval.
*/
static void new_value (attrs_data *attrs) {
	attrs->values[attrs->vi] = &attrs->bvals[attrs->bi];
	attrs->vi++;
}


/*
** Store a NULL pointer to end attributes list.
*/
static void last_value (attrs_data *attrs) {
	attrs->values[attrs->vi] = NULL;
	attrs->vi++;
}


/*
** Create a NULL-terminated array of berval strings from a Lua table.
** It also works for one string (instead of a table with a unique value).
** @param tab stack index of the table (or string).
** @return NULL-terminated array of berval strings.
*/
static int table2bervalarray (lua_State *L, int tab, attrs_data *attrs) {
	if (lua_isstring (L, tab)) {
		if (LUALDAP_ARRAY_VALUES_SIZE < (attrs->vi + 1) ||
				LUALDAP_MAX_VALUES < attrs->bi)
			return faildirect (L, LUALDAP_PREFIX"too many attributes/values");
		/* store pointer to new berval */
		new_value (attrs);
		str2bvals (L, -1, attrs);
	} else if (lua_istable (L, tab)) {
		int i;
		int n = luaL_getn (L, tab);
		if (LUALDAP_ARRAY_VALUES_SIZE < (attrs->vi + n + 1) ||
				LUALDAP_MAX_VALUES < (attrs->bi + n))
			return faildirect (L, LUALDAP_PREFIX"too many attributes/values");
		for (i = 1; i <= n; i++) {
			new_value (attrs);
			lua_rawgeti (L, tab, i); /* push table element */
			if (lua_isstring (L, -1))
				str2bvals (L, -1, attrs);
			else
				return luaL_error (L, LUALDAP_PREFIX"invalid value (string expected, got %s)", lua_typename(L, lua_type(L, -1)));
		}
		lua_pop (L, n);
	} else
		return luaL_error (L, LUALDAP_PREFIX"invalid argument #%d", tab);
	last_value (attrs);
	return 0;
}


/*
** Convert a Lua table into an array of modifications.
** An array of modifications is a NULL-terminated array of LDAPMod's.
*/
static int table2attrarray (lua_State *L, int tab, int op, attrs_data *attrs) {
	lua_pushnil (L); /* first key for lua_next */
	while (lua_next (L, tab) != 0) {
		if ((!lua_isnumber (L, -2)) && (lua_isstring (L, -2))) {
			if (LUALDAP_MAX_ATTRS < attrs->ai)
				return faildirect (L, LUALDAP_PREFIX"too many attributes/values");
			attrs->mods[attrs->ai].mod_op = op;
			attrs->mods[attrs->ai].mod_type = (char *)lua_tostring (L, -2);
			attrs->mods[attrs->ai].mod_bvalues = &attrs->values[attrs->vi];
			if (table2bervalarray (L, lua_gettop(L), attrs))
				return 2;
			attrs->attrs[attrs->ai] = &attrs->mods[attrs->ai];
			attrs->ai++;
		}
		lua_pop (L, 1); /* pop value and leave last key on top of the stack */
	}
	attrs->attrs[attrs->ai] = NULL;
	return 0;
}

/* !!!!!!! */

/*
** Copy a string or a table of strings from Lua to a NULL-terminated array
** of C-strings.
*/
static int table2strarray (lua_State *L, int tab, char *array[], int limit) {
	if (lua_isstring (L, tab)) {
		if (limit < 2)
			return faildirect (L, LUALDAP_PREFIX"too many arguments");
		array[0] = (char *)lua_tostring (L, tab);
		array[1] = NULL;
	} else if (lua_istable (L, tab)) {
		int i;
		int n = luaL_getn (L, tab);
		if (limit < (n+1))
			return luaL_error (L, LUALDAP_PREFIX"too many arguments");

		for (i = 0; i < n; i++) {
			lua_rawgeti (L, tab, i+1); /* push table element */
			if (lua_isstring (L, -1))
				array[i] = (char *)lua_tostring (L, -1);
			else {
				return luaL_error (L, LUALDAP_PREFIX"invalid value #%d", i+1);
			}
		}
		array[n] = NULL;
		/*lua_pop (L, n);*/
	} else 
		return luaL_error (L, LUALDAP_PREFIX"bad argument #%d (table or string expected, got %s)", tab, lua_typename (L, tab));
	return 0;
}


/*
** Unbind from the directory.
** @param #1 LDAP connection.
** @return 1 in case of success; nothing when already closed.
*/
static int lualdap_close (lua_State *L) {
	conn_data *conn = getconnection (L);
	if (conn->closed)
		return 0;
	conn->closed = 1;
	if (conn->ld) {
		ldap_unbind (conn->ld);
		conn->ld = NULL;
	}
	lua_pushnumber (L, 1);
	return 1;
}


/*
** Add a new entry to the directory.
** @param #1 LDAP connection.
** @param #2 String with new entry's DN.
** @param #3 Table with new entry's attributes and values.
** @return ??
*/
static int lualdap_add (lua_State *L) {
	conn_data *conn = getconnection (L);
	const char *dn = luaL_check_string (L, 2);
	attrs_data attrs;
	init_attrs (&attrs);
	if (lua_istable (L, 3))
		if (table2attrarray(L, 3, LUALDAP_MOD_ADD, &attrs))
			return 2;
	int rc = ldap_add_ext_s (conn->ld, dn, attrs.attrs, NULL, NULL);
	if (rc == LDAP_SUCCESS) {
		lua_pushboolean (L, 1);
		return 1;
	} else
		return faildirect (L, ldap_err2string (rc));
}


/*
** Compare a value against an entry.
** @param #1 LDAP connection.
** @param #2 String with entry's DN.
** @param #3 String with attribute's name.
** @param #4 String with attribute's value.
** @return Boolean.
*/
static int lualdap_compare (lua_State *L) {
	conn_data *conn = getconnection (L);
	const char *dn = luaL_check_string (L, 2);
	const char *attr = luaL_check_string (L, 3);
	BerValue bvalue;
	int rc;

	/* Perform the comparison operation */
	bvalue.bv_val = (char *)luaL_check_string (L, 4);
	bvalue.bv_len = lua_strlen (L, 4);
	rc = ldap_compare_ext_s (conn->ld, dn, attr, &bvalue, NULL, NULL);
	if (rc == LDAP_COMPARE_TRUE) {
		lua_pushboolean (L, 1);
		return 1;
	} else if (rc == LDAP_COMPARE_FALSE) {
		lua_pushboolean (L, 0);
		return 1;
	} else
		return faildirect (L, ldap_err2string (rc));
}


/*
** Delete an entry.
** @param #1 LDAP connection.
** @param #2 String with entry's DN.
** @return Boolean.
*/
static int lualdap_delete (lua_State *L) {
	conn_data *conn = getconnection (L);
	const char *dn = luaL_check_string (L, 2);
	int rc = ldap_delete_ext_s (conn->ld, dn, NULL, NULL);
	if (rc == LDAP_SUCCESS) {
		lua_pushboolean (L, 1);
		return 1;
	} else
		return faildirect (L, ldap_err2string (rc));
}


/*
** Convert a string into an internal LDAP_MOD operation code.
*/
static int op2code (const char *s) {
	switch (*s) {
		case '+':
			return LUALDAP_MOD_ADD;
		case '-':
			return LUALDAP_MOD_DEL;
		case '=':
			return LUALDAP_MOD_REP;
		default:
			return 0;
	}
}


/*
** Modify an entry.
** @param #1 LDAP connection.
** @param #2 String with entry's DN.
** @param #3 Table with modifications to apply.
** @return Boolean.
*/
static int lualdap_modify (lua_State *L) {
	conn_data *conn = getconnection (L);
	const char *dn = luaL_check_string (L, 2);
	attrs_data attrs;
	int param = 3;
	while (lua_istable (L, param)) {
		int rc, op;
		init_attrs (&attrs);
		/* get operation ('+','-','=' operations allowed) */
		lua_rawgeti (L, param, 1);
		if (lua_isstring (L, -1))
			op = op2code (lua_tostring (L, -1));
		else
			op = 0;
		if (!op)
			return luaL_error (L, LUALDAP_PREFIX"forgotten operation on argument #%d", param);
		if (table2attrarray (L, param, op, &attrs))
			return 2;
		rc = ldap_modify_ext_s (conn->ld, dn, attrs.attrs, NULL, NULL);
		if (rc != LDAP_SUCCESS)
			return luaL_error (L,
				LUALDAP_PREFIX"error while modification set #%d: %s",
				param-2, ldap_err2string (rc));
		param++;
	}
	lua_pushboolean (L, 1);
	return 1;
}


/*
** Push an attribute value (or a table of values) on top of the stack.
** @param entry Current entry.
** @param attr Name of entry's attribute to get values from.
** @return 1 in case of success.
*/
static int pushvalues (lua_State *L, LDAP *ld, LDAPMessage *entry, char *attr) {
	int i, n;
	BerValue **vals = ldap_get_values_len (ld, entry, attr);
	if ((n = ldap_count_values_len (vals)) == 1)
		lua_pushlstring (L, vals[0]->bv_val, vals[0]->bv_len);
	else { /* Multiple values */
		lua_newtable (L);
		for (i = 0; i < n; i++) {
			lua_pushlstring (L, vals[i]->bv_val, vals[i]->bv_len);
			lua_rawseti (L, -2, i+1);
		}
	}
	ldap_value_free_len (vals);
	return 1;
}


/*
** Store entry's distinguished name at the given table.
** @param entry Current entry.
** @param tab Absolute stack index of the table.
*/
static void setdn (lua_State *L, LDAP *ld, LDAPMessage *entry, int tab) {
	char *dn = ldap_get_dn (ld, entry);
	lua_pushstring (L, "dn");
	lua_pushstring (L, dn);
	lua_rawset (L, tab);
	ldap_memfree (dn);
}


/*
** Store entry's attributes and values at the given table.
** @param entry Current entry.
** @param tab Absolute stack index of the table.
*/
static void setattribs (lua_State *L, LDAP *ld, LDAPMessage *entry, int tab) {
	char *attr;
	BerElement *ber = NULL;
	for (attr = ldap_first_attribute (ld, entry, &ber);
		attr != NULL;
		attr = ldap_next_attribute (ld, entry, ber))
	{
		lua_pushstring (L, attr);
		pushvalues (L, ld, entry, attr);
		lua_rawset (L, tab); /* tab[attr] = vals */
		ldap_memfree (attr);
	}
	if (ber)
		ber_free (ber, 0);
}


/*
** Retrieve next message...
** @return #1 current entry (or nil if no more entries).
** @return #2 table with entry's attributes and values.
*/
static int next_message (lua_State *L) {
	search_data *search = getsearch (L);
	conn_data *conn;
	struct timeval *timeout = NULL; /* ??? function parameter ??? */
	LDAPMessage *res;
	int rc;

	lua_rawgeti (L, LUA_REGISTRYINDEX, search->conn);
	conn = (conn_data *)lua_touserdata (L, -1); /* get connection */

	rc = ldap_result (conn->ld, search->msgid, LDAP_MSG_ONE, timeout, &res);
	if (rc == 0)
		return faildirect (L, LUALDAP_PREFIX"result timeout expired");
	else if (rc == -1)
		return faildirect (L, LUALDAP_PREFIX"result error");

	if (rc == LDAP_RES_SEARCH_RESULT) /* last message => nil */
		lua_pushnil (L);
	else {
		LDAPMessage *msg = ldap_first_message (conn->ld, res);
		switch (ldap_msgtype (msg)) {
			case LDAP_RES_SEARCH_ENTRY: {
				int tab;
				LDAPMessage *entry = ldap_first_entry (conn->ld, msg);

				lua_newtable (L);
				tab = lua_gettop (L);
				setdn (L, conn->ld, entry, tab);
				setattribs (L, conn->ld, entry, tab);
				break;
			}
			case LDAP_RES_SEARCH_REFERENCE: {
				/*LDAPMessage *ref = ldap_first_reference (conn->ld, msg);*/
				lua_pushnil (L);
				break;
			}
			case LDAP_RES_SEARCH_RESULT:
				lua_pushnil (L);
				break;
			default:
				return luaL_error (L, LUALDAP_PREFIX"error on search result chain");
		}
	}
	ldap_msgfree (res);
	return 1;
}




/*
** Convert a string to one of the possible scopes of the search.
*/
static int string2scope (const char *s) {
	switch (*s) {
		case 'b':
			return LDAP_SCOPE_BASE;
		case 'o':
			return LDAP_SCOPE_ONELEVEL;
		case 's':
			return LDAP_SCOPE_SUBTREE;
		default:
			return LDAP_SCOPE_DEFAULT;
	}
}


/*
**
*/
static int lualdap_search_close (lua_State *L) {
	search_data *search = getsearch (L);
	if (search->closed)
		return 0;
	luaL_unref (L, LUA_REGISTRYINDEX, search->conn);
	lua_pushnumber (L, 1);
	return 1;
}


/*
** Create a search object.
*/
static void create_search (lua_State *L, int conn_index, int msgid) {
	search_data *search = (search_data *)lua_newuserdata (L, sizeof (search_data));
	lualdap_setmeta (L, LUALDAP_SEARCH_METATABLE);
	search->closed = 0;
	search->conn = LUA_NOREF;
	search->msgid = msgid;
	lua_pushvalue (L, conn_index);
	search->conn = luaL_ref (L, LUA_REGISTRYINDEX);
}


/*
** Perform a search operation.
** @param #1 LDAP connection.
** @param #2 String with base entry's DN.
** @param #3 String with search scope.
** @param #4 String with search filter.
** @param #5 Table with names of attributes to retrieve.
** @return #1 Function to iterate over the result entries.
** @return #2 LDAP connection.
** @return #3 nil as first entry.
** The search result is defined as an upvalue of the iterator.
*/
static int lualdap_search (lua_State *L) {
	conn_data *conn = getconnection (L);
	const char *base = luaL_check_string (L, 2);
	int scope = string2scope (luaL_check_string (L, 3));
	const char *filter = luaL_check_string (L, 4);
	char *attrs[LUALDAP_MAX_ATTRS];
	int attrsonly = 0;	/* types and values. parameter? */
	int msgid;
	int rc;
	struct timeval *timeout = NULL; /* ??? function parameter ??? */
	int sizelimit = LDAP_NO_LIMIT; /* ??? function parameter ??? */

	if (lua_istable (L, 5)) {
		if (table2strarray (L, 5, attrs, LUALDAP_MAX_ATTRS))
			return 2;
	} else
		attrs[0] = NULL;
	rc = ldap_search_ext (conn->ld, base, scope, filter, attrs, attrsonly,
		NULL, NULL, timeout, sizelimit, &msgid);
	if (rc != LDAP_SUCCESS)
		return faildirect (L, ldap_err2string (rc));

	create_search (L, 1, msgid);
	lua_pushcclosure (L, next_message, 1);
	lua_pushnil (L);
	lua_pushnil (L);
	return 3;
}


/*
** Create a metatable.
*/
static int lualdap_createmeta (lua_State *L) {
	const luaL_reg methods[] = {
		{"close", lualdap_close},
		{"add", lualdap_add},
		{"compare", lualdap_compare},
		{"delete", lualdap_delete},
		{"modify", lualdap_modify},
		{"search", lualdap_search},
		{NULL, NULL}
	};

	if (!luaL_newmetatable (L, LUALDAP_CONNECTION_METATABLE))
		return 0;

	/* define methods */
	luaL_openlib (L, NULL, methods, 0);

	/* define metamethods */
	lua_pushliteral (L, "__gc");
	lua_pushcfunction (L, lualdap_close);
	lua_settable (L, -3);

	lua_pushliteral (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushliteral (L, "__metatable");
	lua_pushliteral(L,LUALDAP_PREFIX"you're not allowed to get this metatable");
	lua_settable (L, -3);

	if (!luaL_newmetatable (L, LUALDAP_SEARCH_METATABLE))
		return 0;

	lua_pushliteral (L, "__gc");
	lua_pushcfunction (L, lualdap_search_close);
	lua_settable (L, -3);

	lua_pushliteral (L, "__metatable");
	lua_pushliteral(L,LUALDAP_PREFIX"you're not allowed to get this metatable");
	lua_settable (L, -3);

	return 0;
}


/*
** Open and initialize a connection to a server.
** @param #1 String with hostname.
** @param #2 String with username.
** @param #3 String with password.
** @return #1 Userdata with connection structure.
*/
static int lualdap_open_simple (lua_State *L) {
	const char *host = luaL_check_string (L, 1);
	/*const char *who = luaL_check_string (L, 2);*/
	const char *who = luaL_optstring (L, 2, NULL);
	const char *password = luaL_optstring (L, 3, NULL);
	conn_data *conn = (conn_data *)lua_newuserdata (L, sizeof(conn_data));
	int err;

	/* Initialize */
	lualdap_setmeta (L, LUALDAP_CONNECTION_METATABLE);
	conn->version = 0;
	conn->closed = 0;
	conn->ld = ldap_init (host, LDAP_PORT);
	if (!conn->ld)
		return faildirect(L,LUALDAP_PREFIX"Error connecting to server");
	/* Set protocol version */
	conn->version = LDAP_VERSION3;
	if (ldap_set_option (conn->ld, LDAP_OPT_PROTOCOL_VERSION, &conn->version)
		!= LDAP_OPT_SUCCESS)
		return faildirect(L, LUALDAP_PREFIX"Error setting LDAP version");
	/* Bind to a server */
	err = ldap_bind_s (conn->ld, who, password, LDAP_AUTH_SIMPLE);
	if (err != LDAP_SUCCESS)
		return faildirect (L, ldap_err2string (err));

	return 1;
}


/*
** Create ldap table and register the open method.
*/
int lualdap_libopen (lua_State *L) {
	lualdap_createmeta (L);

	lua_newtable (L);
	lua_pushliteral (L, "open_simple");
	lua_pushcfunction (L, lualdap_open_simple);
	lua_rawset (L, -3);
	lua_setglobal (L, LUALDAP_TABLENAME);

/*
lua_pushcfunction (L, lualdap_modify);
lua_setglobal (L, "modify");
*/
	
	return 0;
}

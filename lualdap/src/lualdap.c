/*
** LuaLDAP
** $Id: lualdap.c,v 1.4 2003-06-16 16:41:15 tomas Exp $
*/

#include <stdlib.h>
#include <string.h>

#include <ldap.h>

#include <lua.h>
#include <lauxlib.h>


#define LUALDAP_PREFIX "LuaLDAP: "
#define LUALDAP_TABLENAME "lualdap"
#define LUALDAP_METATABLE "LuaLDAP connection"


typedef struct {
	int           closed;
	int           version; /* LDAP version */
	LDAP         *ld;      /* LDAP connection */
} conn_data;


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
** Get a connection object.
*/
static conn_data *getconnection (lua_State *L) {
	conn_data *conn = (conn_data *)luaL_checkudata (L, 1, LUALDAP_METATABLE);
	luaL_argcheck(L, conn!=NULL, 1, LUALDAP_PREFIX"LDAP connection expected");
	luaL_argcheck(L,!conn->closed,1,LUALDAP_PREFIX"LDAP connection is closed");
	return conn;
}


/*
** Copy a Lua string to a C string optionally indicating length.
*/
static char *luastrcpy (lua_State *L, int index, size_t *length) {
	size_t len = lua_strlen (L, index);
	char *str = malloc (len * sizeof(char));
	memcpy (str, lua_tostring (L, index), len);
	if (length)
		*length = len;
	return str;
}


/*
** Create a NULL-terminated array of C-strings from a Lua table.
** It also works for one string (instead of a table with a unique value).
** @param tab stack index of the table (or string).
** @return NULL-terminated array of C-strings.
*/
static char **table2strarray (lua_State *L, int tab) {
	char **array;
	int i;
	int n;
	if (lua_istable (L, tab)) {
		n = luaL_getn (L, tab);
		array = malloc ((n+1) * sizeof(char *));
		for (i = 0; i < n; i++) {
			lua_rawgeti (L, tab, i+1); /* push table element */
			if (lua_isstring (L, -1))
				array[i] = luastrcpy (L, -1, NULL);
			else {
				luaL_error (L, LUALDAP_PREFIX"invalid value");
			}
		}
		lua_pop (L, n);
	} else if (lua_isstring (L, tab)) {
		array = malloc (2 * sizeof(char *));
		array[0] = luastrcpy (L, -1, NULL);
	}
	array[n] = NULL;
	return array;
}


/*
** Free a NULL-terminated array of C-strings.
*/
static void free_strarray (char **array) {
	if (array) {
		int i;
		for (i = 0; array[i] != NULL; i++)
			free (array[i]);
		free (array);
	}
}


/*
** Create a NULL-terminated array of berval strings from a Lua table.
** It also works for one string (instead of a table with a unique value).
** @param tab stack index of the table (or string).
** @return NULL-terminated array of berval strings.
*/
static BerValue **table2bervalarray (lua_State *L, int tab) {
	BerValue **array;
	int i;
	int n;
	if (lua_istable (L, tab)) {
		n = luaL_getn (L, tab);
		array = malloc ((n+1) * sizeof(BerValue *));
		for (i = 0; i < n; i++) {
			lua_rawgeti (L, tab, i+1); /* push table element */
			if (lua_isstring (L, -1)) {
				array[i] = (BerValue *)malloc (sizeof (BerValue));
				array[i]->bv_val = luastrcpy (L, -1, &(array[i]->bv_len));
			} else {
				luaL_error (L, LUALDAP_PREFIX"invalid value");
			}
		}
		lua_pop (L, n);
	} else if (lua_isstring (L, tab)) {
		n = 1;
		array = (BerValue **)malloc (2 * sizeof(BerValue *));
		array[0] = (BerValue *)malloc (sizeof (BerValue));
		array[0]->bv_val = luastrcpy (L, -1, &(array[0]->bv_len));
	}
	array[n] = NULL;
	return array;
}


/*
** Free a NULL-terminated array of bervalstrings.
*/
static void free_bervalarray (BerValue **array) {
	if (array) {
		int i;
		for (i = 0; array[i] != NULL; i++) {
			free (array[i]->bv_val);
			free (array[i]);
		}
		free (array);
	}
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
** Counts the number of string keys of a given table.
*/
static size_t nstrkeys (lua_State *L, int tab) {
	int n = 0;
	lua_pushnil (L);
	while (lua_next(L, tab) != 0) {
		lua_pop (L, 1);
		if (lua_isstring (L, -1))
			n++;
	}
	return n;
}


/*
** Convert a pair (string, value) into a LDAPMod structure.
** Assume that string is at index -2 and value at -1.
*/
static LDAPMod *attr2mod (lua_State *L, int op) {
	LDAPMod *mod = (LDAPMod *)malloc (sizeof (LDAPMod));
	mod->mod_op = op;
	mod->mod_type = luastrcpy (L, -2, NULL);
	mod->mod_bvalues = table2bervalarray (L, lua_gettop(L));
	return mod;
}


/*
** Free an LDAPMod structure.
*/
static void free_mod (LDAPMod *mod) {
	if (mod->mod_type)
		free (mod->mod_type);
	free_bervalarray (mod->mod_bvalues);
	free (mod);
}


/*
** Convert a Lua table into an array of attributes.
** An array of attributes is a NULL-terminated array of LDAPMod's.
*/
static LDAPMod **table2attrarray (lua_State *L, int tab) {
	LDAPMod **array;
	size_t n = nstrkeys (L, tab);
	array = (LDAPMod **)malloc ((n+1) * sizeof (LDAPMod *));
	array[n] = NULL;
	n = 0;
	lua_pushnil (L);
	while (lua_next (L, tab) != 0) {
		if (lua_isstring (L, -1)) {
			array[n] = attr2mod (L, LDAP_MOD_ADD);
			n++;
		}
		lua_pop (L, 1);
	}
	return array;
}


/*
** Free an LDAPMod array.
*/
static void free_attrarray (LDAPMod **array) {
	int i;
	for (i = 0; array[i] != NULL; i++)
		free_mod (array[i]);
	free (array);
}


/*
** Add a new entry to the directory.
** @param #1 LDAP connection.
** @param #2 String with new entry's DN.
** @param #3 Table with new entry's attributes and values.
** @return ??
*/
static int lualdap_add (lua_State *L) {
	conn_data *conn = (conn_data *)getconnection (L);
	const char *dn = luaL_check_string (L, 2);
	LDAPMod **attrs = table2attrarray (L, 3);
	int rc = ldap_add_ext_s (conn->ld, dn, attrs, NULL, NULL);
	free_attrarray (attrs);
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
	conn_data *conn = (conn_data *)getconnection (L);
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
	conn_data *conn = (conn_data *)getconnection (L);
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
		case 'a':
			return LDAP_MOD_ADD | LDAP_MOD_BVALUES;
		case 'd':
			return LDAP_MOD_DELETE | LDAP_MOD_BVALUES;
		case 'r':
			return LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
		default:
			return 0; /* never reached */
	}
}


/*
** Convert a table into a NULL-terminated array of berval.
*/
static BerValue **table2bervals (lua_State *L, int tab) {
	BerValue **values;
	int i;
	int n = luaL_getn (L, tab);
	values = (BerValue **)malloc ((n+1) * sizeof(BerValue *));
	for (i = 0; i < n; i++) {
		const char *s;
		size_t len;
		lua_rawgeti (L, tab, i+1);
		s = luaL_checklstring (L, -1, &len);
		values[i]->bv_val = malloc (len);
		memcpy (values[i]->bv_val, lua_tostring (L, -1), len);
		values[i]->bv_len = len;
	}
	values[n] = NULL;
	lua_pop (L, n);
	return values;
}


/*
** Convert a table into an LDAPMod structure.
*/
static LDAPMod *table2ldapmod (lua_State *L, int tab, int i) {
	const char *s;
	size_t len;
	LDAPMod *mod;
	/* check table */
	lua_rawgeti (L, tab, i);
	luaL_checktype (L, -1, LUA_TTABLE);
	tab = lua_gettop (L);
	mod = (LDAPMod *)malloc (sizeof (LDAPMod));
	/* get modification operation */
	lua_pushstring (L, "op");
	lua_rawget (L, tab);
	s = luaL_checklstring (L, -1, &len);
	mod->mod_op = op2code (s);
	/* get type of the attribute to modify */
	lua_pushstring (L, "type");
	lua_rawget (L, tab);
	s = luaL_checklstring (L, -1, &len);
	mod->mod_type = malloc (len);
	memcpy (mod->mod_type, s, len);
	/* get the values to add, delete or replace. */
	lua_pushstring (L, "values");
	lua_rawget (L, tab);
	if (lua_istable (L, -1))
		/* a set of values */
		mod->mod_bvalues = table2bervals (L, lua_gettop (L));
	else {
		/* just one value */
		size_t len;
		const char *s = luaL_checklstring (L, -1, &len);
		mod->mod_bvalues = (BerValue **)malloc (2 * sizeof (BerValue *));
		mod->mod_bvalues[0] = (BerValue *)malloc (sizeof (BerValue));
		mod->mod_bvalues[0]->bv_val = (char *)malloc (len * sizeof (char));
		memcpy (mod->mod_bvalues[0]->bv_val, s, len);
		mod->mod_bvalues[0]->bv_len = len;
		mod->mod_bvalues[1] = NULL;
	}
	lua_pop (L, 4);
	return mod;
}


/*
** Build an array of modifications.
*/
static LDAPMod **getmods (lua_State *L, int tab) {
	LDAPMod **mods;
	int i, n;
	luaL_checktype (L, tab, LUA_TTABLE);
	n = luaL_getn (L, tab);
	mods = (LDAPMod **)malloc ((n+1) * sizeof (LDAPMod **));
	for (i = 0; i < n; i++) {
		mods[i] = table2ldapmod (L, tab, i+1);
	}
	mods[n] = NULL;
	return mods;
}


/*
** Free modifications array.
*/
static void freemods (LDAPMod **mods) {
	int i;
	for (i = 0; mods[i] != NULL; i++) {
		int j;
		for (j = 0; mods[i]->mod_bvalues[j] != NULL; j++)
			free (mods[i]->mod_bvalues[j]->bv_val);
			free (mods[i]->mod_bvalues[j]);
		free (mods[i]->mod_type);
		free (mods[i]->mod_bvalues);
		free (mods[i]);
	}
	free (mods);
}


/*
** Modify an entry.
** @param #1 LDAP connection.
** @param #2 String with entry's DN.
** @param #3 Table with modifications to apply.
** @return Boolean.
*/
static int lualdap_modify (lua_State *L) {
	conn_data *conn = (conn_data *)getconnection (L);
	const char *dn = luaL_check_string (L, 2);
	LDAPMod **mods = getmods (L, 3);
	int rc = ldap_modify_ext_s (conn->ld, dn, mods, NULL, NULL);
	freemods (mods);
	if (rc == LDAP_SUCCESS) {
		lua_pushboolean (L, 1);
		return 1;
	} else
		return faildirect (L, ldap_err2string (rc));
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
			lua_rawseti (L, -2, i);
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
** Retrieve the next message and all of its attributes and values.
** @param #1 LDAP connection.
** @param #2 previous entry (or nil if first call).
** @return #1 current entry (or nil if no more entries).
** @return #2 table with entry's attributes and values.
*/
static int search_entries (lua_State *L) {
	conn_data *conn = (conn_data *)lua_touserdata (L, 1);
	LDAPMessage *entry;

	/* get next (or first) entry */
	if (lua_isnil (L, 2)) /* first call */
		entry = ldap_first_entry (conn->ld,
			(LDAPMessage *)lua_topointer (L, lua_upvalueindex (1)));
	else /* get next message */
		entry = ldap_next_entry (conn->ld, (LDAPMessage *)lua_topointer(L,2));

	if (entry == NULL) { /* no more messages */
		ldap_msgfree ((LDAPMessage *)lua_topointer (L, lua_upvalueindex(1)));
		lua_pushnil (L);
		return 1;
	} else { /* build table of attributes and its values */
		int tab;
		lua_pushlightuserdata (L, entry); /* push current entry */
		lua_newtable (L);
		tab = lua_gettop (L);
		setdn (L, conn->ld, entry, tab);
		setattribs (L, conn->ld, entry, tab);
		return 2;
	}
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
static int lualdap_search_attribs (lua_State *L) {
	conn_data *conn = (conn_data *)getconnection (L);
	const char *base = luaL_check_string (L, 2);
	int scope = string2scope (luaL_check_string (L, 3));
	const char *filter = luaL_check_string (L, 4);
	char **attrs = NULL;
	int attrsonly = 0;	/* types and values. parameter? */
	int msgid;
	int rc;
	LDAPMessage *res;
	struct timeval *timeout = NULL; /* ??? function parameter ??? */
	int sizelimit = LDAP_NO_LIMIT; /* ??? function parameter ??? */

	if (lua_istable (L, 5))
		attrs = table2strarray (L, 5);
	rc = ldap_search_ext (conn->ld, base, scope, filter, attrs, attrsonly,
		NULL, NULL, timeout, sizelimit, &msgid);
	free_strarray (attrs);
	if (rc != LDAP_SUCCESS)
		return faildirect (L, ldap_err2string (rc));

	rc = ldap_result (conn->ld, LDAP_RES_ANY, LDAP_MSG_ALL, timeout, &res);
	if (rc == 0)
		return faildirect (L, LUALDAP_PREFIX"result timeout expired");
	else if (rc == -1)
		return faildirect (L, LUALDAP_PREFIX"result error");

	lua_pushlightuserdata (L, res); /* push result as upvalue for iterator */
	lua_pushcclosure (L, search_entries, 1); /* push iterator function */
	lua_pushvalue (L, 1); /* push connection as "state" to iterator */
	lua_pushnil (L); /* push nil as "initial value" for iterator */

	return 3;
}


/*
** Set metatable of userdata on top of the stack.
*/
static void lualdap_setmeta (lua_State *L) {
	luaL_getmetatable (L, LUALDAP_METATABLE);
	lua_setmetatable (L, -2);
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
		{"search_attribs", lualdap_search_attribs},
		{NULL, NULL}
	};

	if (!luaL_newmetatable (L, LUALDAP_METATABLE))
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
	lualdap_setmeta (L);
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
	
	return 0;
}

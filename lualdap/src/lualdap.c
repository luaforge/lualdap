/*
** LuaLDAP
** $Id: lualdap.c,v 1.1 2003-06-15 11:55:59 tomas Exp $
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


typedef struct {
	int           closed;
	LDAPMessage  *res;    /* LDAP result message */
	LDAPMessage  *msg;    /* LDAP current message */
} search_data;


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
** Unbind from the directory.
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
** Push an attribute value (or a table of values) on top of the stack.
*/
static int pushvalues (lua_State *L, LDAP *ld, LDAPMessage *entry, char *attr) {
	int i, n;
	struct berval **vals = ldap_get_values_len (ld, entry, attr);
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
*/
static void setdn (lua_State *L, LDAP *ld, LDAPMessage *entry, int tab) {
	char *dn = ldap_get_dn (ld, entry);
	lua_pushstring (L, "dn");
	lua_pushstring (L, dn);
	lua_rawset (L, tab-2);
	ldap_memfree (dn);
}


/*
** 
*/
static int search_entries (lua_State *L) {
	conn_data *conn = (conn_data *)lua_touserdata (L, 1);
	LDAPMessage *entry = (LDAPMessage *)lua_topointer (L, 2);

	if (lua_isnil (L, 2)) { /* first call */
		LDAPMessage *res = (LDAPMessage *)lua_topointer (L, lua_upvalueindex (1));
		entry = ldap_first_entry (conn->ld, res);
	} else { /* get next message */
		entry = (LDAPMessage *)lua_topointer (L, -1);
		entry = ldap_next_entry (conn->ld, entry);
	}

	if (entry == NULL) { /* no more messages */
		LDAPMessage *res = (LDAPMessage *)lua_topointer (L, lua_upvalueindex (1));
		ldap_msgfree (res);
		lua_pushnil (L);
		return 1;
	} else { /* build table of attributes and its values */
		char *attr;
		BerElement *ber = NULL;
		lua_pushlightuserdata (L, entry);
		lua_newtable (L);
		setdn (L, conn->ld, entry, -1);
		for (attr = ldap_first_attribute (conn->ld, entry, &ber);
			attr != NULL;
			attr = ldap_next_attribute (conn->ld, entry, ber))
		{
			lua_pushstring (L, attr);
			pushvalues (L, conn->ld, entry, attr);
			lua_rawset (L, -3); /* attrs[attr] = vals */
			ldap_memfree (attr);
		}
		if (ber)
			ber_free (ber, 0);
		return 2;
	}
}


/*
**
*/
static int search_iter (lua_State *L) {
	LDAPMessage *res;
	conn_data *conn = (conn_data *)lua_touserdata (L, lua_upvalueindex(1));
	struct timeval *timeout = NULL; /* ??? function parameter ??? */
	int rc;
	LDAPMessage *msg;

	rc = ldap_result (conn->ld, LDAP_RES_ANY, LDAP_MSG_ALL, timeout, &res);
	for (msg = ldap_first_message (conn->ld, res);
		msg != NULL;
		msg = ldap_next_message (conn->ld, msg))
	{
printf("%X (%d)\n",(int)msg, ldap_msgtype(msg));
		switch (ldap_msgtype (msg)) {
			case LDAP_RES_SEARCH_ENTRY: {
				char *a;
				BerElement *ber = NULL;
				for (a = ldap_first_attribute (conn->ld, msg, &ber);
					a != NULL;
					a = ldap_next_attribute (conn->ld, msg, ber))
				{
					int i, n;
					struct berval **vals = ldap_get_values_len (conn->ld, msg, a);
char s[10];
strncpy (s, a, 9);
printf (">>> %s\n", s);
					n = ldap_count_values_len (vals);
					for (i = 0; i < n; i++) {
char s[10];
memcpy (s, vals[i]->bv_val, 9);
printf (">>>> %s\n", s);
/*
						lua_pushlstring (L, vals[i].bv_val, vals[i].bv_len);
*/
					}
					ldap_value_free_len (vals);
					ldap_memfree (a);
				}
				break;
			}
			case LDAP_RES_SEARCH_REFERENCE:
printf("> ref\n");
				break;
			case LDAP_RES_EXTENDED:
printf("> ext\n");
				break;
			case LDAP_RES_EXTENDED_PARTIAL:
printf("> ext par\n");
				break;
			case LDAP_RES_SEARCH_RESULT:
printf("> result\n");
				break;
/*
			case LDAP_RES_INTERMEDIATE_RESP:
printf("> inter\n");
				break;
*/
		}
	}
	ldap_msgfree (res);
	return 0;
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
** Create an array of strings from a Lua table.
*/
static char **get_attribs (lua_State *L, int tab) {
	char **attrs;
	int i;
	int n = luaL_getn (L, tab);
	attrs = malloc ((n+1) * sizeof(char *));
	for (i = 0; i < n; i++) {
		lua_rawgeti (L, tab, i+1);
		if (lua_isstring (L, -1)) {
			int len = lua_strlen (L, -1);
			attrs[i] = malloc (len);
			memcpy (attrs[i], lua_tostring (L, -1), len);
		}
	}
	attrs[n] = NULL;
	lua_pop (L, n);
	return attrs;
}


/*
** Perform a search operation.
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

	if (lua_istable (L, 5))
		attrs = get_attribs (L, 5);
	rc = ldap_search_ext (conn->ld, base, scope, filter, attrs, attrsonly,
		NULL /* serverctrls */, NULL /* clientctrls */, NULL /* timeout */,
		-1 /* sizelimit */, &msgid);
	if (attrs) {
		int i;
		for (i = 0; attrs[i] != NULL; i++)
			free (attrs[i]);
		free (attrs);
	}
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
** Compare a value against an entry.
*/
static int lualdap_compare (lua_State *L) {
	conn_data *conn = (conn_data *)getconnection (L);
	const char *dn = luaL_check_string (L, 2);
	const char *attr = luaL_check_string (L, 3);
	struct berval bvalue;
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
**
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
** Convert a table in a NULL-terminated array of berval.
*/
static struct berval **table2bervals (lua_State *L, int tab) {
	struct berval **values;
	int i;
	int n = luaL_getn (L, tab);
	values = (struct berval **)malloc ((n+1) * sizeof(struct berval *));
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
** Convert a table to an LDAPMod structure.
*/
static LDAPMod *table2ldapmod (lua_State *L, int tab, int i) {
	const char *s;
	size_t len;
	LDAPMod *mod;

	lua_rawgeti (L, tab, i);
	luaL_checktype (L, -1, LUA_TTABLE);
	tab = lua_gettop (L);
	mod = (LDAPMod *)malloc (sizeof (LDAPMod));

	lua_pushstring (L, "op");
	lua_rawget (L, tab);
	s = luaL_checklstring (L, -1, &len);
	mod->mod_op = op2code (s);

	lua_pushstring (L, "type");
	lua_rawget (L, tab);
	s = luaL_checklstring (L, -1, &len);
	mod->mod_type = malloc (len);
	memcpy (mod->mod_type, s, len);

	lua_pushstring (L, "values");
	lua_rawget (L, tab);
	if (lua_istable (L, -1))
		mod->mod_bvalues = table2bervals (L, lua_gettop (L));
	else {
		size_t len;
		const char *s = luaL_checklstring (L, -1, &len);
		mod->mod_bvalues = (struct berval **)malloc (2 * sizeof (struct berval *));
		mod->mod_bvalues[0] = (struct berval *)malloc (sizeof (struct berval));
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

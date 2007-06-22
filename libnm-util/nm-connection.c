#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include "nm-connection.h"

static GHashTable *registered_setting_creators = NULL;

static void
register_default_creators (void)
{
	int i;
	const struct {
		const char *name;
		NMSettingCreateFn fn;
	} default_map[] = {
		{ "info",            nm_setting_info_new_from_hash      },
		{ "802-3-ethernet",  nm_setting_wired_new_from_hash     },
		{ "802-11-wireless", nm_setting_wireless_new_from_hash  },
		{ "ipv4",            nm_setting_ip4_config_new_from_hash },
		{ "802-11-wireless-security", nm_setting_wireless_security_new_from_hash  },
		{ NULL, NULL}
	};

	for (i = 0; default_map[i].name; i++)
		nm_setting_parser_register (default_map[i].name, default_map[i].fn);
}

void
nm_setting_parser_register (const char *name, NMSettingCreateFn creator)
{
	g_return_if_fail (name != NULL);
	g_return_if_fail (creator != NULL);
	
	if (!registered_setting_creators)
		registered_setting_creators = g_hash_table_new_full (g_str_hash, g_str_equal,
															 (GDestroyNotify) g_free, NULL);

	if (g_hash_table_lookup (registered_setting_creators, name))
		g_warning ("Already have a creator function for '%s', overriding", name);

	g_hash_table_insert (registered_setting_creators, g_strdup (name), creator);
}

void
nm_setting_parser_unregister (const char *name)
{
	if (registered_setting_creators)
		g_hash_table_remove (registered_setting_creators, name);
}

static void
parse_one_setting (gpointer key, gpointer value, gpointer user_data)
{
	NMConnection *connection = (NMConnection *) user_data;
	NMSettingCreateFn fn;
	NMSetting *setting;

	fn = (NMSettingCreateFn) g_hash_table_lookup (registered_setting_creators, key);
	if (fn) {
		setting = fn ((GHashTable *) value);
		if (setting)
			nm_connection_add_setting (connection, setting);
	} else
		g_warning ("Unknown setting '%s'", (char *) key);
}

NMConnection *
nm_connection_new (void)
{
	NMConnection *connection;

	if (!registered_setting_creators)
		register_default_creators ();

	connection = g_slice_new0 (NMConnection);
	connection->settings = g_hash_table_new (g_str_hash, g_str_equal);

	return connection;
}

NMConnection *
nm_connection_new_from_hash (GHashTable *hash)
{
	NMConnection *connection;

	g_return_val_if_fail (hash != NULL, NULL);

	if (!registered_setting_creators)
		register_default_creators ();

	connection = nm_connection_new ();
	g_hash_table_foreach (hash, parse_one_setting, connection);

	if (g_hash_table_size (connection->settings) < 1) {
		g_warning ("No settings found.");
		nm_connection_destroy (connection);
		return NULL;
	}

	if (!nm_settings_verify (connection->settings)) {
		nm_connection_destroy (connection);
		return NULL;
	}

	return connection;
}

void
nm_connection_add_setting (NMConnection *connection, NMSetting *setting)
{
	g_return_if_fail (connection != NULL);
	g_return_if_fail (setting != NULL);

	g_hash_table_insert (connection->settings, setting->name, setting);
}

NMSetting *
nm_connection_get_setting (NMConnection *connection, const char *setting_name)
{
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (setting_name != NULL, NULL);

	return (NMSetting *) g_hash_table_lookup (connection->settings, setting_name);
}

gboolean
nm_connection_compare (NMConnection *connection, NMConnection *other)
{
	if (!connection && !other)
		return TRUE;

	if (!connection || !other)
		return FALSE;

	/* FIXME: Implement */

	return FALSE;
}

static void
add_one_setting_to_hash (gpointer key, gpointer data, gpointer user_data)
{
	NMSetting *setting = (NMSetting *) data;
	GHashTable *connection_hash = (GHashTable *) user_data;
	GHashTable *setting_hash;

	setting_hash = nm_setting_to_hash (setting);
	if (setting_hash)
		g_hash_table_insert (connection_hash,
							 g_strdup (setting->name),
							 setting_hash);
}

GHashTable *
nm_connection_to_hash (NMConnection *connection)
{
	GHashTable *connection_hash;

	g_return_val_if_fail (connection != NULL, NULL);

	connection_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
											 (GDestroyNotify) g_free,
											 (GDestroyNotify) g_hash_table_destroy);

	g_hash_table_foreach (connection->settings, add_one_setting_to_hash, connection_hash);

	/* Don't send empty hashes */
	if (g_hash_table_size (connection_hash) < 1) {
		g_hash_table_destroy (connection_hash);
		connection_hash = NULL;
	}

	return connection_hash;
}

static char *
garray_to_string (GArray *array)
{
	GString *str;
	int i;
	char c;

	str = g_string_sized_new (array->len);
	for (i = 0; i < array->len; i++) {
		c = array->data[i];

		/* Convert NULLs to spaces to increase the readability. */
		if (c == '\0')
			c = ' ';
		str = g_string_append_c (str, c);
	}
	str = g_string_append_c (str, '\0');

	return g_string_free (str, FALSE);
}

static char *
gvalue_to_string (GValue *val)
{
	char *ret;
	GType type;
	GString *str;
	gboolean need_comma = FALSE;

	type = G_VALUE_TYPE (val);
	switch (type) {
	case G_TYPE_STRING:
		ret = g_strdup (g_value_get_string (val));
		break;
	case G_TYPE_INT:
		ret = g_strdup_printf ("%d", g_value_get_int (val));
		break;
	case G_TYPE_UINT:
		ret = g_strdup_printf ("%u", g_value_get_uint (val));
		break;
	case G_TYPE_BOOLEAN:
		ret = g_strdup_printf ("%s", g_value_get_boolean (val) ? "True" : "False");
		break;
	case G_TYPE_UCHAR:
		ret = g_strdup_printf ("%d", g_value_get_uchar (val));
		break;

	default:
		/* These return dynamic values and thus can't be 'case's */
		if (type == DBUS_TYPE_G_UCHAR_ARRAY)
			ret = garray_to_string ((GArray *) g_value_get_boxed (val));
		else if (type == dbus_g_type_get_collection ("GSList", G_TYPE_STRING)) {
			GSList *iter;

			str = g_string_new ("[");
			for (iter = g_value_get_boxed (val); iter; iter = iter->next) {
				if (need_comma)
					g_string_append (str, ", ");
				else
					need_comma = TRUE;

				g_string_append (str, (char *) iter->data);
			}
			g_string_append (str, "]");

			ret = g_string_free (str, FALSE);
		} else if (type == dbus_g_type_get_collection ("GPtrArray", DBUS_TYPE_G_UCHAR_ARRAY)) {
			/* Array of arrays of chars, like wireless seen-bssids for example */
			int i;
			GPtrArray *ptr_array;

			str = g_string_new ("[");

			ptr_array = (GPtrArray *) g_value_get_boxed (val);
			for (i = 0; i < ptr_array->len; i++) {
				ret = garray_to_string ((GArray *) g_ptr_array_index (ptr_array, i));

				if (need_comma)
					g_string_append (str, ", ");
				else
					need_comma = TRUE;

				g_string_append (str, ret);
				g_free (ret);
			}

			g_string_append (str, "]");
			ret = g_string_free (str, FALSE);
		} else
			ret = g_strdup_printf ("Value with type %s", g_type_name (type));
	}

	return ret;
}

static void
dump_setting_member (gpointer key, gpointer value, gpointer user_data)
{
	char *val_as_str;

	val_as_str = gvalue_to_string ((GValue *) value);
	g_message ("\t%s : '%s'", (char *) key, val_as_str);
	g_free (val_as_str);
}

static void
dump_setting (gpointer key, gpointer value, gpointer user_data)
{
	g_message ("Setting '%s'", (char *) key);
	g_hash_table_foreach ((GHashTable *) value, dump_setting_member, NULL);
	g_message ("-------------------");
}

void
nm_connection_dump (NMConnection *connection)
{
	GHashTable *hash;

	g_return_if_fail (connection != NULL);

	/* Convert the connection to hash so that we can introspect it */
	hash = nm_connection_to_hash (connection);
	g_hash_table_foreach (hash, dump_setting, NULL);
	g_hash_table_destroy (hash);
}

void
nm_connection_destroy (NMConnection *connection)
{
	g_return_if_fail (connection != NULL);

	g_hash_table_destroy (connection->settings);
	g_slice_free (NMConnection, connection);
}

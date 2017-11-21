/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include <linux/pkt_sched.h>

#include "nm-setting-tc-config.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-tc-config
 * @short_description: Describes connection properties for the Linux Traffic Control
 * @include: nm-setting-tc-config.h
 **/

/*****************************************************************************/

G_DEFINE_BOXED_TYPE (NMTCQdisc, nm_tc_qdisc, nm_tc_qdisc_dup, nm_tc_qdisc_unref)

struct NMTCQdisc {
	guint refcount;

	const char *kind;
	int family;
	int handle;
	int parent;
	int info;
};

/**
 * nm_tc_qdisc_new:
 * @kind: name of the queueing discipline
 * @family: address family (%AF_UNSPEC)
 * @handle: the queueing discipline handle
 * @parent: the parent class
 * @info: XXX
 * @error: location to store error, or %NULL
 *
 * Creates a new #NMTCQdisc object.
 *
 * Returns: (transfer full): the new #NMTCQdisc object, or %NULL on error
 *
 * Since: 1.12
 **/
NMTCQdisc *
nm_tc_qdisc_new (const char *kind,
                 int family,
                 int handle,
                 int parent,
                 int info,
                 GError **error)
{
	NMTCQdisc *qdisc;

	qdisc = g_slice_new0 (NMTCQdisc);
	qdisc->refcount = 1;

	qdisc->kind = g_intern_string (kind);
	qdisc->family = family;
	qdisc->handle = handle;
	qdisc->parent = parent;
	qdisc->info = info;

	return qdisc;
}

/**
 * nm_tc_qdisc_ref:
 * @qdisc: the #NMTCQdisc
 *
 * Increases the reference count of the object.
 *
 * Since: 1.12
 **/
void
nm_tc_qdisc_ref (NMTCQdisc *qdisc)
{
	g_return_if_fail (qdisc != NULL);
	g_return_if_fail (qdisc->refcount > 0);

	qdisc->refcount++;
}

/**
 * nm_tc_qdisc_unref:
 * @qdisc: the #NMTCQdisc
 *
 * Decreases the reference count of the object.  If the reference count
 * reaches zero, the object will be destroyed.
 *
 * Since: 1.12
 **/
void
nm_tc_qdisc_unref (NMTCQdisc *qdisc)
{
	g_return_if_fail (qdisc != NULL);
	g_return_if_fail (qdisc->refcount > 0);

	qdisc->refcount--;
	if (qdisc->refcount == 0)
		g_slice_free (NMTCQdisc, qdisc);
}

/**
 * nm_tc_qdisc_equal:
 * @qdisc: the #NMTCQdisc
 * @other: the #NMTCQdisc to compare @qdisc to.
 *
 * Determines if two #NMTCQdisc objects contain the same kind, family,
 * handle, parent and info.
 *
 * Returns: %TRUE if the objects contain the same values, %FALSE if they do not.
 *
 * Since: 1.12
 **/
gboolean
nm_tc_qdisc_equal (NMTCQdisc *qdisc, NMTCQdisc *other)
{
	g_return_val_if_fail (qdisc != NULL, FALSE);
	g_return_val_if_fail (qdisc->refcount > 0, FALSE);

	g_return_val_if_fail (other != NULL, FALSE);
	g_return_val_if_fail (other->refcount > 0, FALSE);

	if (   qdisc->kind != other->kind
	    || qdisc->family != other->family
	    || qdisc->handle != other->handle
	    || qdisc->parent != other->parent
	    || qdisc->info != other->info
	    || g_strcmp0 (qdisc->kind, other->kind) != 0)
		return FALSE;

	return TRUE;
}

/**
 * nm_tc_qdisc_dup:
 * @qdisc: the #NMTCQdisc
 *
 * Creates a copy of @qdisc
 *
 * Returns: (transfer full): a copy of @qdisc
 *
 * Since: 1.12
 **/
NMTCQdisc *
nm_tc_qdisc_dup (NMTCQdisc *qdisc)
{
	NMTCQdisc *copy;

	g_return_val_if_fail (qdisc != NULL, NULL);
	g_return_val_if_fail (qdisc->refcount > 0, NULL);

	copy = nm_tc_qdisc_new (qdisc->kind, qdisc->family,
	                        qdisc->handle, qdisc->parent, qdisc->info,
	                        NULL);

	return copy;
}

/**
 * nm_tc_qdisc_get_kind:
 * @qdisc: the #NMTCQdisc
 *
 * Returns:
 *
 * Since: 1.12
 **/
const char *
nm_tc_qdisc_get_kind (NMTCQdisc *qdisc)
{
	g_return_val_if_fail (qdisc != NULL, NULL);
	g_return_val_if_fail (qdisc->refcount > 0, NULL);

	return qdisc->kind;
}

/**
 * nm_tc_qdisc_set_kind:
 * @qdisc: the #NMTCQdisc
 * @kind: name of the queueing discipline
 *
 * Sets the name of the queueing discipline.
 * Internalizes the string.
 *
 * Since: 1.12
 **/
void
nm_tc_qdisc_set_kind (NMTCQdisc *qdisc, const char *kind)
{
	g_return_if_fail (qdisc != NULL);
	g_return_if_fail (qdisc->refcount > 0);

	qdisc->kind = g_intern_string (kind);
}

/**
 * nm_tc_qdisc_get_family:
 * @qdisc: the #NMTCQdisc
 *
 * Returns: name of the queueing discipline
 *
 * Since: 1.12
 **/
int
nm_tc_qdisc_get_family (NMTCQdisc *qdisc)
{
	g_return_val_if_fail (qdisc != NULL, AF_UNSPEC);
	g_return_val_if_fail (qdisc->refcount > 0, AF_UNSPEC);

	return qdisc->family;
}

/**
 * nm_tc_qdisc_set_family:
 * @qdisc: the #NMTCQdisc
 * @family: address family (%AF_UNSPEC)
 *
 * Sets the address family associated with the
 * queueing discipline.
 *
 * Since: 1.12
 **/
void
nm_tc_qdisc_set_family (NMTCQdisc *qdisc, int family)
{
	g_return_if_fail (qdisc != NULL);
	g_return_if_fail (qdisc->refcount > 0);

	qdisc->family = family;
}

/**
 * nm_tc_qdisc_get_handle:
 * @qdisc: the #NMTCQdisc
 *
 * Returns: the queueing discipline handle
 *
 * Since: 1.12
 **/
int
nm_tc_qdisc_get_handle (NMTCQdisc *qdisc)
{
	g_return_val_if_fail (qdisc != NULL, TC_H_UNSPEC);
	g_return_val_if_fail (qdisc->refcount > 0, TC_H_UNSPEC);

	return qdisc->handle;
}

/**
 * nm_tc_qdisc_set_handle:
 * @qdisc: the #NMTCQdisc
 * @handle: the queueing discipline handle
 *
 * Sets the queueing discipline handle.
 *
 * Since: 1.12
 **/
void
nm_tc_qdisc_set_handle (NMTCQdisc *qdisc, int handle)
{
	g_return_if_fail (qdisc != NULL);
	g_return_if_fail (qdisc->refcount > 0);

	qdisc->handle = handle;
}

/**
 * nm_tc_qdisc_get_parent:
 * @qdisc: the #NMTCQdisc
 *
 * Returns: the parent class
 *
 * Since: 1.12
 **/
int
nm_tc_qdisc_get_parent (NMTCQdisc *qdisc)
{
	g_return_val_if_fail (qdisc != NULL, TC_H_UNSPEC);
	g_return_val_if_fail (qdisc->refcount > 0, TC_H_UNSPEC);

	return qdisc->parent;
}

/**
 * nm_tc_qdisc_set_parent:
 * @qdisc: the #NMTCQdisc
 * @parent: the parent class
 *
 * Sets the parent class of the queueing discipline.
 *
 * Since: 1.12
 **/
void
nm_tc_qdisc_set_parent (NMTCQdisc *qdisc, int parent)
{
	g_return_if_fail (qdisc != NULL);
	g_return_if_fail (qdisc->refcount > 0);

	qdisc->parent = parent;
}

/**
 * nm_tc_qdisc_get_info:
 * @qdisc: the #NMTCQdisc
 *
 * Returns: XXX
 *
 * Since: 1.12
 **/
int
nm_tc_qdisc_get_info (NMTCQdisc *qdisc)
{
	g_return_val_if_fail (qdisc != NULL, TC_H_UNSPEC);
	g_return_val_if_fail (qdisc->refcount > 0, TC_H_UNSPEC);

	return qdisc->info;
}

/**
 * nm_tc_qdisc_set_info:
 * @qdisc: the #NMTCQdisc
 * @info: XXX
 *
 * XXX
 *
 * Since: 1.12
 **/
void
nm_tc_qdisc_set_info (NMTCQdisc *qdisc, int info)
{
	g_return_if_fail (qdisc != NULL);
	g_return_if_fail (qdisc->refcount > 0);

	qdisc->info = info;
}

/*****************************************************************************/

enum {
	PROP_0,
	PROP_QDISCS,

	LAST_PROP
};

/**
 * NMSettingTCConfig:
 *
 * Linux Traffic Contril Settings.
 *
 * Since: 1.12
 */
struct _NMSettingTCConfig {
        NMSetting parent;
	GPtrArray *qdiscs;
};

struct _NMSettingTCConfigClass {
        NMSettingClass parent;
};

G_DEFINE_TYPE_WITH_CODE (NMSettingTCConfig, nm_setting_tc_config, NM_TYPE_SETTING,
                         _nm_register_setting (TC_CONFIG, NM_SETTING_PRIORITY_IP))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_TC_CONFIG)

/**
 * nm_setting_tc_config_get_num_qdiscs:
 * @setting: the #NMSettingTCConfig
 *
 * Returns: the number of configured queueing disciplines
 *
 * Since: 1.12
 **/
guint
nm_setting_tc_config_get_num_qdiscs (NMSettingTCConfig *self)
{
	g_return_val_if_fail (NM_IS_SETTING_TC_CONFIG (self), 0);

	return self->qdiscs->len;
}

/**
 * nm_setting_tc_config_get_qdisc:
 * @setting: the #NMSettingTCConfig
 * @idx: index number of the qdisc to return
 *
 * Returns: (transfer none): the qdisc at index @idx
 *
 * Since: 1.12
 **/
NMTCQdisc *
nm_setting_tc_config_get_qdisc (NMSettingTCConfig *self, int idx)
{
	g_return_val_if_fail (NM_IS_SETTING_TC_CONFIG (self), NULL);
	g_return_val_if_fail (idx >= 0 && idx < self->qdiscs->len, NULL);

	return self->qdiscs->pdata[idx];
}

/**
 * nm_setting_tc_config_add_qdisc:
 * @setting: the #NMSettingTCConfig
 * @qdisc: the qdisc to add
 *
 * Appends a new qdisc and associated information to the setting.  The
 * given qdisc is duplicated internally and is not changed by this function.
 * If an identical qdisc (considering attributes as well) already exists, the
 * qdisc is not added and the function returns %FALSE.
 *
 * Returns: %TRUE if the qdisc was added; %FALSE if the qdisc was already known.
 *
 * Since: 1.12
 **/
gboolean
nm_setting_tc_config_add_qdisc (NMSettingTCConfig *self,
                                NMTCQdisc *qdisc)
{
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_TC_CONFIG (self), FALSE);
	g_return_val_if_fail (qdisc != NULL, FALSE);

	for (i = 0; i < self->qdiscs->len; i++) {
		if (nm_tc_qdisc_equal (self->qdiscs->pdata[i], qdisc))
			return FALSE;
	}

	g_ptr_array_add (self->qdiscs, nm_tc_qdisc_dup (qdisc));
	g_object_notify (G_OBJECT (self), NM_SETTING_TC_CONFIG_QDISCS);
	return TRUE;
}

/**
 * nm_setting_tc_config_remove_qdisc:
 * @setting: the #NMSettingTCConfig
 * @idx: index number of the qdisc
 *
 * Removes the qdisc at index @idx.
 *
 * Since: 1.12
 **/
void
nm_setting_tc_config_remove_qdisc (NMSettingTCConfig *self, int idx)
{
	g_return_if_fail (NM_IS_SETTING_TC_CONFIG (self));

	g_return_if_fail (idx >= 0 && idx < self->qdiscs->len);

	g_ptr_array_remove_index (self->qdiscs, idx);
	g_object_notify (G_OBJECT (self), NM_SETTING_TC_CONFIG_QDISCS);
}

/**
 * nm_setting_tc_config_remove_qdisc_by_value:
 * @setting: the #NMSettingTCConfig
 * @qdisc: the qdisc to remove
 *
 * Removes the first matching qdisc that matches @qdisc.
 *
 * Returns: %TRUE if the qdisc was found and removed; %FALSE if it was not.
 *
 * Since: 1.12
 **/
gboolean
nm_setting_tc_config_remove_qdisc_by_value (NMSettingTCConfig *self,
                                            NMTCQdisc *qdisc)
{
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_TC_CONFIG (self), FALSE);
	g_return_val_if_fail (qdisc != NULL, FALSE);

	for (i = 0; i < self->qdiscs->len; i++) {
		if (nm_tc_qdisc_equal (self->qdiscs->pdata[i], qdisc)) {
			g_ptr_array_remove_index (self->qdiscs, i);
			g_object_notify (G_OBJECT (self), NM_SETTING_TC_CONFIG_QDISCS);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_tc_config_clear_qdiscs:
 * @setting: the #NMSettingTCConfig
 *
 * Removes all configured queueing disciplines.
 *
 * Since: 1.12
 **/
void
nm_setting_tc_config_clear_qdiscs (NMSettingTCConfig *self)
{
	g_return_if_fail (NM_IS_SETTING_TC_CONFIG (self));

	g_ptr_array_set_size (self->qdiscs, 0);
	g_object_notify (G_OBJECT (self), NM_SETTING_TC_CONFIG_QDISCS);
}

/*****************************************************************************/

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingTCConfig *self = NM_SETTING_TC_CONFIG (object);

	switch (prop_id) {
	case PROP_QDISCS:
		g_ptr_array_unref (self->qdiscs);
		self->qdiscs = _nm_utils_copy_array (g_value_get_boxed (value),
		                                     (NMUtilsCopyFunc) nm_tc_qdisc_dup,
		                                     (GDestroyNotify) nm_tc_qdisc_unref);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingTCConfig *self = NM_SETTING_TC_CONFIG (object);

	switch (prop_id) {
	case PROP_QDISCS:
		g_value_take_boxed (value, _nm_utils_copy_array (self->qdiscs,
		                                                 (NMUtilsCopyFunc) nm_tc_qdisc_dup,
		                                                 (GDestroyNotify) nm_tc_qdisc_unref));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
finalize (GObject *object)
{
	NMSettingTCConfig *self = NM_SETTING_TC_CONFIG (object);

	g_ptr_array_unref (self->qdiscs);

	G_OBJECT_CLASS (nm_setting_tc_config_parent_class)->finalize (object);
}

static gboolean
compare_property (NMSetting *setting,
                  NMSetting *other,
                  const GParamSpec *prop_spec,
                  NMSettingCompareFlags flags)
{
	NMSettingTCConfig *a_tc_config = NM_SETTING_TC_CONFIG (setting);
	NMSettingTCConfig *b_tc_config = NM_SETTING_TC_CONFIG (other);
	NMSettingClass *parent_class;
	guint i;

	if (nm_streq (prop_spec->name, NM_SETTING_TC_CONFIG_QDISCS)) {
		if (a_tc_config->qdiscs->len != b_tc_config->qdiscs->len)
			return FALSE;
		for (i = 0; i < a_tc_config->qdiscs->len; i++) {
			if (!nm_tc_qdisc_equal (a_tc_config->qdiscs->pdata[i], b_tc_config->qdiscs->pdata[i]))
				return FALSE;
		}
		return TRUE;
	}

	/* Otherwise chain up to parent to handle generic compare */
	parent_class = NM_SETTING_CLASS (nm_setting_tc_config_parent_class);
	return parent_class->compare_property (setting, other, prop_spec, flags);
}

static void
nm_setting_tc_config_init (NMSettingTCConfig *self)
{
	self->qdiscs = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_tc_qdisc_unref);
}

/**
 * _qdiscs_to_variant:
 * @qdiscs: (element-type NMTCQdisc): an array of #NMTCQdisc objects
 *
 * Utility function to convert a #GPtrArray of #NMTCQdisc objects representing
 * TC qdiscs into a #GVariant of type 'aa{sv}' representing an array
 * of NetworkManager TC qdiscs.
 *
 * Returns: (transfer none): a new floating #GVariant representing @qdiscs.
 **/
static GVariant *
_qdiscs_to_variant (GPtrArray *qdiscs)
{
	GVariantBuilder builder;
	int i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aa{sv}"));

	if (qdiscs) {
		for (i = 0; i < qdiscs->len; i++) {
			NMTCQdisc *qdisc = qdiscs->pdata[i];
			GVariantBuilder qdisc_builder;

			g_variant_builder_init (&qdisc_builder, G_VARIANT_TYPE ("a{sv}"));

			g_variant_builder_add (&qdisc_builder, "{sv}",
			                       "kind",
			                       g_variant_new_string (nm_tc_qdisc_get_kind (qdisc)));

			g_variant_builder_add (&qdisc_builder, "{sv}",
			                       "family",
			                       g_variant_new_uint32 (nm_tc_qdisc_get_family (qdisc)));

			g_variant_builder_add (&qdisc_builder, "{sv}",
			                       "handle",
			                       g_variant_new_uint32 (nm_tc_qdisc_get_handle (qdisc)));

			g_variant_builder_add (&qdisc_builder, "{sv}",
			                       "parent",
			                       g_variant_new_uint32 (nm_tc_qdisc_get_parent (qdisc)));

			g_variant_builder_add (&qdisc_builder, "{sv}",
			                       "info",
			                       g_variant_new_uint32 (nm_tc_qdisc_get_info (qdisc)));

			g_variant_builder_add (&builder, "a{sv}", &qdisc_builder);
		}
	}

	return g_variant_builder_end (&builder);
}

/**
 * _qdiscs_from_variant:
 * @value: a #GVariant of type 'aa{sv}'
 *
 * Utility function to convert a #GVariant representing a list of TC qdiscs
 * into a #GPtrArray of * #NMTCQdisc objects.
 *
 * Returns: (transfer full) (element-type NMTCQdisc): a newly allocated
 *   #GPtrArray of #NMTCQdisc objects
 **/
static GPtrArray *
_qdiscs_from_variant (GVariant *value)
{
	GPtrArray *qdiscs;
	GVariantIter iter;
	GVariant *qdisc_var;
	const char *kind = NULL;
	int family = AF_UNSPEC;
	int handle = 0;
	int parent = 0;
	int info = 0;
	NMTCQdisc *qdisc;
	GError *error = NULL;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("aa{sv}")), NULL);

	g_variant_iter_init (&iter, value);
	qdiscs = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_tc_qdisc_unref);

	while (g_variant_iter_next (&iter, "@a{sv}", &qdisc_var)) {

		if (!g_variant_lookup (qdisc_var, "kind", "&s", &kind)) {
			g_warning ("Ignoring invalid qdisc");
			goto next;
		}

		g_variant_lookup (qdisc_var, "family", "u", &family);
		g_variant_lookup (qdisc_var, "handle", "u", &handle);
		g_variant_lookup (qdisc_var, "parent", "u", &parent);
		g_variant_lookup (qdisc_var, "info", "u", &info);

		qdisc = nm_tc_qdisc_new (kind, family, handle, parent, info, &error);
		if (!qdisc) {
			g_warning ("Ignoring invalid qdisc: %s", error->message);
			g_clear_error (&error);
			goto next;
		}

		g_ptr_array_add (qdiscs, qdisc);
next:
		g_variant_unref (qdisc_var);
	}

	return qdiscs;
}

static GVariant *
tc_qdiscs_get (NMSetting *setting,
               const char *property)
{
	GPtrArray *qdiscs;
	GVariant *ret;

	g_object_get (setting, NM_SETTING_TC_CONFIG_QDISCS, &qdiscs, NULL);
	ret = _qdiscs_to_variant (qdiscs);
	g_ptr_array_unref (qdiscs);

	return ret;
}

static gboolean
tc_qdiscs_set (NMSetting *setting,
               GVariant *connection_dict,
               const char *property,
               GVariant *value,
               NMSettingParseFlags parse_flags,
               GError **error)
{
	GPtrArray *qdiscs;

	qdiscs = _qdiscs_from_variant (value);
	g_object_set (setting, NM_SETTING_TC_CONFIG_QDISCS, qdiscs, NULL);
	g_ptr_array_unref (qdiscs);

	return TRUE;
}

static void
nm_setting_tc_config_class_init (NMSettingTCConfigClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	/* virtual methods */
	object_class->set_property     = set_property;
	object_class->get_property     = get_property;
	object_class->finalize         = finalize;
	parent_class->compare_property = compare_property;

	/* Properties */

	/**
	 * NMSettingTCConfig:qdiscs:
	 *
	 * Array of TC queuening disciplines.
	 *
	 * Element-Type: NMTCQdisc
	 **/
	g_object_class_install_property
		(object_class, PROP_QDISCS,
		 g_param_spec_boxed (NM_SETTING_TC_CONFIG_QDISCS, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READWRITE |
		                     NM_SETTING_PARAM_INFERRABLE |
		                     G_PARAM_STATIC_STRINGS));

	_nm_setting_class_override_property (parent_class,
	                                     NM_SETTING_TC_CONFIG_QDISCS,
	                                     G_VARIANT_TYPE ("aa{sv}"),
	                                     tc_qdiscs_get,
	                                     tc_qdiscs_set,
	                                     NULL);

}

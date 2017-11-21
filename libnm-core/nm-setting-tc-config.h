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

#ifndef NM_SETTING_TC_CONFIG_H
#define NM_SETTING_TC_CONFIG_H

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

NM_AVAILABLE_IN_1_12
typedef struct NMTCQdisc NMTCQdisc;

NM_AVAILABLE_IN_1_12
GType       nm_tc_qdisc_get_type   (void);

NM_AVAILABLE_IN_1_12
NMTCQdisc  *nm_tc_qdisc_new        (const char *kind,
                                    int family,
                                    int handle,
                                    int parent,
                                    int info,
                                    GError **error);

NM_AVAILABLE_IN_1_12
void        nm_tc_qdisc_ref        (NMTCQdisc *qdisc);
NM_AVAILABLE_IN_1_12
void        nm_tc_qdisc_unref      (NMTCQdisc *qdisc);
NM_AVAILABLE_IN_1_12
gboolean    nm_tc_qdisc_equal      (NMTCQdisc *qdisc,
                                    NMTCQdisc *other);

NM_AVAILABLE_IN_1_12
NMTCQdisc  *nm_tc_qdisc_dup        (NMTCQdisc  *qdisc);


NM_AVAILABLE_IN_1_12
const char *nm_tc_qdisc_get_kind   (NMTCQdisc *qdisc);
NM_AVAILABLE_IN_1_12
void        nm_tc_qdisc_set_kind   (NMTCQdisc *qdisc,
                                    const char *kind);
NM_AVAILABLE_IN_1_12
int         nm_tc_qdisc_get_family (NMTCQdisc *qdisc);
NM_AVAILABLE_IN_1_12
void        nm_tc_qdisc_set_family (NMTCQdisc *qdisc,
                                    int family);
NM_AVAILABLE_IN_1_12
int         nm_tc_qdisc_get_handle (NMTCQdisc *qdisc);
NM_AVAILABLE_IN_1_12
void        nm_tc_qdisc_set_handle (NMTCQdisc *qdisc,
                                    int handle);
NM_AVAILABLE_IN_1_12
int         nm_tc_qdisc_get_parent (NMTCQdisc *qdisc);
NM_AVAILABLE_IN_1_12
void        nm_tc_qdisc_set_parent (NMTCQdisc *qdisc,
                                    int parent);
NM_AVAILABLE_IN_1_12
int         nm_tc_qdisc_get_info   (NMTCQdisc *qdisc);
NM_AVAILABLE_IN_1_12
void        nm_tc_qdisc_set_info   (NMTCQdisc *qdisc,
                                    int info);

#define NM_TYPE_SETTING_TC_CONFIG            (nm_setting_tc_config_get_type ())
#define NM_SETTING_TC_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_TC_CONFIG, NMSettingTCConfig))
#define NM_SETTING_TC_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_TC_CONFIG, NMSettingTCConfigClass))
#define NM_IS_SETTING_TC_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_TC_CONFIG))
#define NM_IS_SETTING_TC_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_TC_CONFIG))
#define NM_SETTING_TC_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_TC_CONFIG, NMSettingTCConfigClass))

#define NM_SETTING_TC_CONFIG_SETTING_NAME    "tc"

#define NM_SETTING_TC_CONFIG_QDISCS          "qdiscs"

typedef struct _NMSettingTCConfigClass NMSettingTCConfigClass;

GType nm_setting_tc_config_get_type (void);

NM_AVAILABLE_IN_1_12
guint      nm_setting_tc_config_get_num_qdiscs        (NMSettingTCConfig *setting);
NM_AVAILABLE_IN_1_12
NMTCQdisc *nm_setting_tc_config_get_qdisc             (NMSettingTCConfig *setting,
                                                       int idx);
NM_AVAILABLE_IN_1_12
gboolean   nm_setting_tc_config_add_qdisc             (NMSettingTCConfig *setting,
                                                       NMTCQdisc *qdisc);
NM_AVAILABLE_IN_1_12
void       nm_setting_tc_config_remove_qdisc          (NMSettingTCConfig *setting,
                                                       int idx);
NM_AVAILABLE_IN_1_12
gboolean   nm_setting_tc_config_remove_qdisc_by_value (NMSettingTCConfig *setting,
                                                       NMTCQdisc *qdisc);
NM_AVAILABLE_IN_1_12
void       nm_setting_tc_config_clear_qdiscs          (NMSettingTCConfig *setting);

G_END_DECLS

#endif /* NM_SETTING_TC_CONFIG_H */

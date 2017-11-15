/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager audit support
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include <stdlib.h>
#include <syslog.h>
#include <linux/pkt_sched.h>

#include "platform/nm-linux-platform.h"
#include "platform/nmp-object.h"

#include "nm-test-utils-core.h"

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	GMainLoop *loop;
//	NMPObject *obj;

	if (!g_getenv ("G_MESSAGES_DEBUG"))
		g_setenv ("G_MESSAGES_DEBUG", "all", TRUE);
	if (!g_getenv ("NMTST_DEBUG"))
		g_setenv ("NMTST_DEBUG", "TRACE", TRUE);

	nmtst_init_with_logging (&argc, &argv, "DEBUG", "ALL");

	loop = g_main_loop_new (NULL, FALSE);

	nm_linux_platform_setup ();

	nm_platform_check_kernel_support (NM_PLATFORM_GET, ~((NMPlatformKernelSupportFlags) 0));


#if 0
+++ exited with 1 +++
[root@fedora27-2 NetworkManager]# strace -esendmsg -s4096 -f tc filter add dev dum0 parent 8003: matchall action simple sdata Hello
sendmsg(3, {msg_name={sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, msg_namelen=12, msg_iov=[{iov_base={{len=140, type=RTM_NEWTFILTER, flags=NLM_F_REQUEST|NLM_F_ACK|NLM_F_EXCL|NLM_F_CREATE, seq=1511268982, pid=0}, {tcm_family=AF_UNSPEC, tcm_ifindex=if_nametoindex("dum0"), tcm_handle=0, tcm_parent=2147680256, tcm_info=768}, [{{nla_len=13, nla_type=TCA_KIND}, "\x6d\x61\x74\x63\x68\x61\x6c\x6c\x00"}, {{nla_len=88, nla_type=TCA_OPTIONS}, "\x54\x00\x02\x00\x50\x00\x01\x00\x0b\x00\x01\x00\x73\x69\x6d\x70\x6c\x65\x00\x00\x40\x00\x02\x00\x18\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x24\x00\x03\x00\x48\x65\x6c\x6c\x6f\x00\x4c\x53\x5f\x43\x4f\x4c\x4f\x52\x53\x3d\x72\x73\x3d\x30\x3a\x64\x69\x3d\x33\x38\x3b\x35\x3b\x33\x33\x3a"}]}, iov_len=140}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 140
+++ exited with 0 +++
#endif

#if 0
sendmsg(3, {msg_name={sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, msg_namelen=12, msg_iov=[{iov_base={{len=140, type=RTM_NEWTFILTER, flags=NLM_F_REQUEST|NLM_F_ACK|NLM_F_EXCL|NLM_F_CREATE, seq=1511268982, pid=0},
{tcm_family=AF_UNSPEC, tcm_ifindex=if_nametoindex("dum0"), tcm_handle=0, tcm_parent=2147680256, tcm_info=768}, [{{nla_len=13, nla_type=TCA_KIND},
"\x6d\x61\x74\x63\x68\x61\x6c\x6c\x00"}, {{nla_len=88, nla_type=TCA_OPTIONS}, "\x54\x00\x02\x00\x50\x00\x01\x00\x0b\x00\x01\x00\x73\x69\x6d\x70\x6c\x65\x00\x00\x40\x00\x02\x00\x18\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x24\x00\x03\x00\x48\x65\x6c\x6c\x6f\x00\x4c\x53\x5f\x43\x4f\x4c\x4f\x52\x53\x3d\x72\x73\x3d\x30\x3a\x64\x69\x3d\x33\x38\x3b\x35\x3b\x33\x33\x3a"}]}, iov_len=140}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 140
#endif

#if 0
sendmsg(5, {msg_name={sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, msg_namelen=12, msg_iov=[{iov_base={{len=140, type=RTM_NEWTFILTER, flags=NLM_F_REQUEST|NLM_F_ACK|NLM_F_EXCL|NLM_F_CREATE, seq=9, pid=3493882573},
{tcm_family=AF_UNSPEC, tcm_ifindex=if_nametoindex("dum0"), tcm_handle=0, tcm_parent=2147680256, tcm_info=0}, [{{nla_len=13, nla_type=TCA_KIND}, "\x6d\x61\x74\x63\x68\x61\x6c\x6c\x00"}, {{nla_len=88, nla_type=TCA_OPTIONS}, "\x54\x00\x02\x00\x50\x00\x01\x00\x0b\x00\x01\x00\x73\x69\x6d\x70\x6c\x65\x00\x00\x40\x00\x02\x00\x18\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x24\x00\x03\x00\x4b\x76\x6f\x6b\x6f\x74\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"}]}, iov_len=140}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 140
#endif


g_printerr ("------------------\n");
{
	NMPlatformTfilter tfilter = {
		.ifindex = 43,
		.kind = "matchall",
		.addr_family = AF_UNSPEC,
		.handle = TC_H_UNSPEC,
		.parent = TC_H_MAKE (0x8003 << 16, 0),
		.info = TC_H_MAKE (0, htons(ETH_P_ALL)),
		.action.kind = "simple",
		.action.simple.str = "Hello",
	};

	if (nm_platform_tfilter_add (NM_PLATFORM_GET, NMP_NLM_FLAG_ADD, &tfilter) == NM_PLATFORM_ERROR_SUCCESS) {
		g_printerr ("QDISC GOOD\n");
//		nm_platform_tfilter_delete (NM_PLATFORM_GET, (NMPObject *)tfilter);
	} else {
		g_printerr ("QDISC BAD\n");
	}
}
g_printerr ("------------------\n");


#if 0
{
	gs_unref_ptrarray GPtrArray *plat_qdiscs = NULL;
	NMPLookup lookup;
	guint i;
	int ifindex = 71;

	plat_qdiscs = nm_platform_lookup_clone (NM_PLATFORM_GET,
						nmp_lookup_init_addrroute (&lookup,
									   NMP_OBJECT_TYPE_QDISC,
									   ifindex),
						NULL, NULL);

	g_printerr ("QDISC SYNC [%d] {%p}\n", ifindex, &lookup);

	if (plat_qdiscs) {
		g_printerr ("	<%d>\n", plat_qdiscs->len);
		for (i = 0; i < plat_qdiscs->len; i++) {
			NMPlatformQdisc *qdisc = g_ptr_array_index (plat_qdiscs, i);
			g_printerr ("	[%s]\n", nm_platform_qdisc_to_string (qdisc, NULL, 0));
		}
	}

	g_printerr ("XXXXXXXXXX===============\n");
	_exit (0);
}
#endif




#if 0
{
	const NMPlatformQdisc *qdisc = NULL;


	if (nm_platform_qdisc_add (NM_PLATFORM_GET, 26, "ingress", AF_UNSPEC, TC_H_MAKE(TC_H_INGRESS, 0), TC_H_INGRESS, 0, &qdisc) == NM_PLATFORM_ERROR_SUCCESS) {
		g_printerr ("QDISC GOOD\n");
		nm_platform_qdisc_delete (NM_PLATFORM_GET, (NMPObject *)qdisc);
	} else {
		g_printerr ("QDISC BAD\n");
	}
}
#endif

#if 0
{
	const NMPlatformAction *action = NULL;
	if (nm_platform_action_add (NM_PLATFORM_GET, &action) == NM_PLATFORM_ERROR_SUCCESS) {
		g_printerr ("ACTION GOOD\n");
	} else {
		g_printerr ("ACTION BAD\n");
	}
}
#endif

#if 0
{
	const NMPlatformTfilter *filter = NULL;
	if (nm_platform_tfilter_add (NM_PLATFORM_GET, &filter) == NM_PLATFORM_ERROR_SUCCESS) {
		g_printerr ("FILTER GOOD\n");
	} else {
		g_printerr ("FILTER BAD\n");
	}
}
#endif

#if 0
if (nm_platform_ip4_address_add (NM_PLATFORM_GET, 1, 0x01020304, 32, 0x00000000, 0xffffffff, 0xffffffff, 0, NULL)) {
	g_printerr ("GOOD\n");
} else {
	g_printerr ("BAD\n");
}
#endif


//nm_platform_link_dummy_add (NM_PLATFORM_GET, "kvokot", NULL);

//	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	return EXIT_SUCCESS;
}

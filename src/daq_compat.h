/*
** daq_compat.h -- bundled replacement for the libdaq headers.
**
** barnyard2 reads events from unified2 spool files; it never opens a DAQ
** module and never links against libdaq.  The only things it ever needed
** from that package were the DAQ_PktHdr_t type (of which it only uses the
** ts/caplen/pktlen members) and the DLT_* constants from <sfbpf_dlt.h>.
**
** libdaq 2.x is no longer packaged by current distributions (it is absent
** from Debian 13), so those two definitions are provided here instead.  If
** a real libdaq is installed, configure will detect it and decode.h will
** include the system headers rather than this file.
*/

#ifndef __DAQ_COMPAT_H__
#define __DAQ_COMPAT_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <sys/time.h>

/* DLT_* values shared with libpcap. */
#include <pcap.h>

/*
** Layout-compatible with libdaq 2.x DAQ_PktHdr_t.  The leading
** ts/caplen/pktlen members are also laid out identically to
** struct pcap_pkthdr, which barnyard2 has historically relied on.
*/
typedef struct _daq_pkthdr
{
    struct timeval ts;          /* Timestamp */
    uint32_t caplen;            /* Length of the captured portion */
    uint32_t pktlen;            /* Length of the packet on the wire */
    int32_t ingress_index;      /* Index of the receiving interface */
    int32_t egress_index;       /* Index of the transmitting interface */
    int32_t ingress_group;      /* Index of the receiving group */
    int32_t egress_group;       /* Index of the transmitting group */
    uint32_t flags;             /* Flags for the packet */
    uint32_t opaque;            /* Opaque context value */
    void *priv_ptr;             /* Private data pointer */
    uint32_t address_space_id;  /* Unique address space ID */
} DAQ_PktHdr_t;

/*
** Snort's sfbpf carried a handful of DLT values that libpcap does not
** define.  The numbers below match <sfbpf_dlt.h> from daq 2.0.x.
*/
#ifndef DLT_IEEE805
#define DLT_IEEE805 7           /* ARCNET */
#endif

#ifndef DLT_LANE8023
#define DLT_LANE8023 8          /* LANE 802.3 */
#endif

#ifndef DLT_OLD_PFLOG
#define DLT_OLD_PFLOG 17        /* OpenBSD pflog, pre-3.4 format */
#endif

#ifndef DLT_I4L_RAWIP
#define DLT_I4L_RAWIP 130       /* ISDN4Linux raw IP */
#endif

#ifndef DLT_I4L_IP
#define DLT_I4L_IP 131          /* ISDN4Linux IP with Ethernet header */
#endif

#ifndef DLT_I4L_CISCOHDLC
#define DLT_I4L_CISCOHDLC 132   /* ISDN4Linux Cisco HDLC */
#endif

#endif /* __DAQ_COMPAT_H__ */

#ifndef lib_pcap_pcap_h
#define lib_pcap_pcap_h

#if defined(_MSC_VER)
  
  #if !defined(_MSC_FULL_VER)
   
    #if _MSC_VER > 1200
     
      #undef _MSC_VER
    #endif
  #endif
#endif

#include <pcap/funcattrs.h>

#include <pcap/pcap-inttypes.h>

#if defined(_WIN32)
  #include <winsock2.h>		/* u_int, u_char etc. */
  #include <io.h>		/* _get_osfhandle() */
#elif defined(MSDOS)
  #include <sys/types.h>	/* u_int, u_char etc. */
  #include <sys/socket.h>
#else /* UN*X */
  #include <sys/types.h>	/* u_int, u_char etc. */
  #include <sys/time.h>
#endif /* _WIN32/MSDOS/UN*X */

#include <pcap/socket.h>	/* for PCAP_SOCKET, as the active-mode rpcap APIs use it */

#ifndef PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap/bpf.h>
#endif

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

#define PCAP_ERRBUF_SIZE 256

#if BPF_RELEASE - 0 < 199406
typedef	int bpf_int32;
typedef	u_int bpf_u_int32;
#endif

typedef struct pcap pcap_t;
typedef struct pcap_dumper pcap_dumper_t;
typedef struct pcap_if pcap_if_t;
typedef struct pcap_addr pcap_addr_t;


struct pcap_file_header {
	bpf_u_int32 magic;
	u_short version_major;
	u_short version_minor;
	bpf_int32 thiszone;	/* not used - SHOULD be filled with 0 */
	bpf_u_int32 sigfigs;	/* not used - SHOULD be filled with 0 */
	bpf_u_int32 snaplen;	/* max length saved portion of each pkt */
	bpf_u_int32 linktype;	/* data link type (LINKTYPE_*) */
};


#define LT_LINKTYPE(x)			((x) & 0x0000FFFF)
#define LT_LINKTYPE_EXT(x)		((x) & 0xFFFF0000)
#define LT_RESERVED1(x)			((x) & 0x03FF0000)
#define LT_FCS_LENGTH_PRESENT(x)	((x) & 0x04000000)
#define LT_FCS_LENGTH(x)		(((x) & 0xF0000000) >> 28)
#define LT_FCS_DATALINK_EXT(x)		((((x) & 0xF) << 28) | 0x04000000)

typedef enum {
       PCAP_D_INOUT = 0,
       PCAP_D_IN,
       PCAP_D_OUT
} pcap_direction_t;


struct pcap_pkthdr {
	struct timeval ts;	/* time stamp */
	bpf_u_int32 caplen;	/* length of portion present */
	bpf_u_int32 len;	/* length of this packet (off wire) */
};

/*
 * As returned by the pcap_stats()
 */
struct pcap_stat {
	u_int ps_recv;		/* number of packets received */
	u_int ps_drop;		/* number of packets dropped */
	u_int ps_ifdrop;	/* drops by interface -- only supported on some platforms */
#ifdef _WIN32
	u_int ps_capt;		/* number of packets that reach the application */
	u_int ps_sent;		/* number of packets sent by the server on the network */
	u_int ps_netdrop;	/* number of packets lost on the network */
#endif /* _WIN32 */
};

#ifdef MSDOS
/*
 * As returned by the pcap_stats_ex()
 */
struct pcap_stat_ex {
       u_long  rx_packets;        /* total packets received       */
       u_long  tx_packets;        /* total packets transmitted    */
       u_long  rx_bytes;          /* total bytes received         */
       u_long  tx_bytes;          /* total bytes transmitted      */
       u_long  rx_errors;         /* bad packets received         */
       u_long  tx_errors;         /* packet transmit problems     */
       u_long  rx_dropped;        /* no space in Rx buffers       */
       u_long  tx_dropped;        /* no space available for Tx    */
       u_long  multicast;         /* multicast packets received   */
       u_long  collisions;

       /* detailed rx_errors: */
       u_long  rx_length_errors;
       u_long  rx_over_errors;    /* receiver ring buff overflow  */
       u_long  rx_crc_errors;     /* recv'd pkt with crc error    */
       u_long  rx_frame_errors;   /* recv'd frame alignment error */
       u_long  rx_fifo_errors;    /* recv'r fifo overrun          */
       u_long  rx_missed_errors;  /* recv'r missed packet         */

       /* detailed tx_errors */
       u_long  tx_aborted_errors;
       u_long  tx_carrier_errors;
       u_long  tx_fifo_errors;
       u_long  tx_heartbeat_errors;
       u_long  tx_window_errors;
     };
#endif


struct pcap_if {
	struct pcap_if *next;
	char *name;		/* name to hand to "pcap_open_live()" */
	char *description;	/* textual description of interface, or NULL */
	struct pcap_addr *addresses;
	bpf_u_int32 flags;	/* PCAP_IF_ interface flags */
};

#define PCAP_IF_LOOPBACK				0x00000001	/* interface is loopback */
#define PCAP_IF_UP					0x00000002	/* interface is up */
#define PCAP_IF_RUNNING					0x00000004	/* interface is running */
#define PCAP_IF_WIRELESS				0x00000008	/* interface is wireless (*NOT* necessarily Wi-Fi!) */
#define PCAP_IF_CONNECTION_STATUS			0x00000030	/* connection status: */
#define PCAP_IF_CONNECTION_STATUS_UNKNOWN		0x00000000	/* unknown */
#define PCAP_IF_CONNECTION_STATUS_CONNECTED		0x00000010	/* connected */
#define PCAP_IF_CONNECTION_STATUS_DISCONNECTED		0x00000020	/* disconnected */
#define PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE	0x00000030	/* not applicable */


struct pcap_addr {
	struct pcap_addr *next;
	struct sockaddr *addr;		/* address */
	struct sockaddr *netmask;	/* netmask for that address */
	struct sockaddr *broadaddr;	/* broadcast address for that address */
	struct sockaddr *dstaddr;	/* P2P destination address for that address */
};

typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *,
			     const u_char *);


#define PCAP_ERROR			-1	/* generic error code */
#define PCAP_ERROR_BREAK		-2	/* loop terminated by pcap_breakloop */
#define PCAP_ERROR_NOT_ACTIVATED	-3	/* the capture needs to be activated */
#define PCAP_ERROR_ACTIVATED		-4	/* the operation can't be performed on already activated captures */
#define PCAP_ERROR_NO_SUCH_DEVICE	-5	/* no such device exists */
#define PCAP_ERROR_RFMON_NOTSUP		-6	/* this device doesn't support rfmon (monitor) mode */
#define PCAP_ERROR_NOT_RFMON		-7	/* operation supported only in monitor mode */
#define PCAP_ERROR_PERM_DENIED		-8	/* no permission to open the device */
#define PCAP_ERROR_IFACE_NOT_UP		-9	/* interface isn't up */
#define PCAP_ERROR_CANTSET_TSTAMP_TYPE	-10	/* this device doesn't support setting the time stamp type */
#define PCAP_ERROR_PROMISC_PERM_DENIED	-11	/* you don't have permission to capture in promiscuous mode */
#define PCAP_ERROR_TSTAMP_PRECISION_NOTSUP -12  /* the requested time stamp precision is not supported */
#define PCAP_ERROR_CAPTURE_NOTSUP	-13	/* capture mechanism not available */


#define PCAP_WARNING			1	/* generic warning code */
#define PCAP_WARNING_PROMISC_NOTSUP	2	/* this device doesn't support promiscuous mode */
#define PCAP_WARNING_TSTAMP_TYPE_NOTSUP	3	/* the requested time stamp type is not supported */


#define PCAP_NETMASK_UNKNOWN	0xffffffff


#define PCAP_CHAR_ENC_LOCAL	0x00000000U	/* strings are in the local character encoding */
#define PCAP_CHAR_ENC_UTF_8	0x00000001U	/* strings are in UTF-8 */

PCAP_AVAILABLE_1_10
PCAP_API int	pcap_init(unsigned int, char *);


PCAP_AVAILABLE_0_4
PCAP_DEPRECATED("use 'pcap_findalldevs' and use the first device")
PCAP_API char	*pcap_lookupdev(char *);

PCAP_AVAILABLE_0_4
PCAP_API int	pcap_lookupnet(const char *, bpf_u_int32 *, bpf_u_int32 *, char *);

PCAP_AVAILABLE_1_0
PCAP_API pcap_t	*pcap_create(const char *, char *);

PCAP_AVAILABLE_1_0
PCAP_API int	pcap_set_snaplen(pcap_t *, int);

PCAP_AVAILABLE_1_0
PCAP_API int	pcap_set_promisc(pcap_t *, int);

PCAP_AVAILABLE_1_0
PCAP_API int	pcap_can_set_rfmon(pcap_t *);

PCAP_AVAILABLE_1_0
PCAP_API int	pcap_set_rfmon(pcap_t *, int);

PCAP_AVAILABLE_1_0
PCAP_API int	pcap_set_timeout(pcap_t *, int);

PCAP_AVAILABLE_1_2
PCAP_API int	pcap_set_tstamp_type(pcap_t *, int);

PCAP_AVAILABLE_1_5
PCAP_API int	pcap_set_immediate_mode(pcap_t *, int);

PCAP_AVAILABLE_1_0
PCAP_API int	pcap_set_buffer_size(pcap_t *, int);

PCAP_AVAILABLE_1_5
PCAP_API int	pcap_set_tstamp_precision(pcap_t *, int);

PCAP_AVAILABLE_1_5
PCAP_API int	pcap_get_tstamp_precision(pcap_t *);

PCAP_AVAILABLE_1_0
PCAP_API int	pcap_activate(pcap_t *);

PCAP_AVAILABLE_1_2
PCAP_API int	pcap_list_tstamp_types(pcap_t *, int **);

PCAP_AVAILABLE_1_2
PCAP_API void	pcap_free_tstamp_types(int *);

PCAP_AVAILABLE_1_2
PCAP_API int	pcap_tstamp_type_name_to_val(const char *);

PCAP_AVAILABLE_1_2
PCAP_API const char *pcap_tstamp_type_val_to_name(int);

PCAP_AVAILABLE_1_2
PCAP_API const char *pcap_tstamp_type_val_to_description(int);

#ifdef __linux__
PCAP_AVAILABLE_1_9
PCAP_API int	pcap_set_protocol_linux(pcap_t *, int);
#endif


#define PCAP_TSTAMP_HOST			0	/* host-provided, unknown characteristics */
#define PCAP_TSTAMP_HOST_LOWPREC		1	/* host-provided, low precision, synced with the system clock */
#define PCAP_TSTAMP_HOST_HIPREC			2	/* host-provided, high precision, synced with the system clock */
#define PCAP_TSTAMP_ADAPTER			3	/* device-provided, synced with the system clock */
#define PCAP_TSTAMP_ADAPTER_UNSYNCED		4	/* device-provided, not synced with the system clock */
#define PCAP_TSTAMP_HOST_HIPREC_UNSYNCED	5	/* host-provided, high precision, not synced with the system clock */

#define PCAP_TSTAMP_PRECISION_MICRO	0	/* use timestamps with microsecond precision, default */
#define PCAP_TSTAMP_PRECISION_NANO	1	/* use timestamps with nanosecond precision */

PCAP_AVAILABLE_0_4
PCAP_API pcap_t	*pcap_open_live(const char *, int, int, int, char *);

PCAP_AVAILABLE_0_6
PCAP_API pcap_t	*pcap_open_dead(int, int);

PCAP_AVAILABLE_1_5
PCAP_API pcap_t	*pcap_open_dead_with_tstamp_precision(int, int, u_int);

PCAP_AVAILABLE_1_5
PCAP_API pcap_t	*pcap_open_offline_with_tstamp_precision(const char *, u_int, char *);

PCAP_AVAILABLE_0_4
PCAP_API pcap_t	*pcap_open_offline(const char *, char *);

#ifdef _WIN32
  PCAP_AVAILABLE_1_5
  PCAP_API pcap_t  *pcap_hopen_offline_with_tstamp_precision(intptr_t, u_int, char *);

  PCAP_API pcap_t  *pcap_hopen_offline(intptr_t, char *);
  
  #ifndef BUILDING_PCAP
    #define pcap_fopen_offline_with_tstamp_precision(f,p,b) \
	pcap_hopen_offline_with_tstamp_precision(_get_osfhandle(_fileno(f)), p, b)
    #define pcap_fopen_offline(f,b) \
	pcap_hopen_offline(_get_osfhandle(_fileno(f)), b)
  #endif
#else /*_WIN32*/
  PCAP_AVAILABLE_1_5
  PCAP_API pcap_t	*pcap_fopen_offline_with_tstamp_precision(FILE *, u_int, char *);

  PCAP_AVAILABLE_0_9
  PCAP_API pcap_t	*pcap_fopen_offline(FILE *, char *);
#endif /*_WIN32*/

PCAP_AVAILABLE_0_4
PCAP_API void	pcap_close(pcap_t *);

PCAP_AVAILABLE_0_4
PCAP_API int	pcap_loop(pcap_t *, int, pcap_handler, u_char *);

PCAP_AVAILABLE_0_4
PCAP_API int	pcap_dispatch(pcap_t *, int, pcap_handler, u_char *);

PCAP_AVAILABLE_0_4
PCAP_API const u_char *pcap_next(pcap_t *, struct pcap_pkthdr *);

PCAP_AVAILABLE_0_8
PCAP_API int	pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const u_char **);

PCAP_AVAILABLE_0_8
PCAP_API void	pcap_breakloop(pcap_t *);

PCAP_AVAILABLE_0_4
PCAP_API int	pcap_stats(pcap_t *, struct pcap_stat *);

PCAP_AVAILABLE_0_4
PCAP_API int	pcap_setfilter(pcap_t *, struct bpf_program *);

PCAP_AVAILABLE_0_9
PCAP_API int	pcap_setdirection(pcap_t *, pcap_direction_t);

PCAP_AVAILABLE_0_7
PCAP_API int	pcap_getnonblock(pcap_t *, char *);

PCAP_AVAILABLE_0_7
PCAP_API int	pcap_setnonblock(pcap_t *, int, char *);

PCAP_AVAILABLE_0_9
PCAP_API int	pcap_inject(pcap_t *, const void *, size_t);

PCAP_AVAILABLE_0_8
PCAP_API int	pcap_sendpacket(pcap_t *, const u_char *, int);

PCAP_AVAILABLE_1_0
PCAP_API const char *pcap_statustostr(int);

PCAP_AVAILABLE_0_4
PCAP_API const char *pcap_strerror(int);

PCAP_AVAILABLE_0_4
PCAP_API char	*pcap_geterr(pcap_t *);

PCAP_AVAILABLE_0_4
PCAP_API void	pcap_perror(pcap_t *, const char *);

PCAP_AVAILABLE_0_4
PCAP_API int	pcap_compile(pcap_t *, struct bpf_program *, const char *, int,
	    bpf_u_int32);

PCAP_AVAILABLE_0_5
PCAP_DEPRECATED("use pcap_open_dead(), pcap_compile() and pcap_close()")
PCAP_API int	pcap_compile_nopcap(int, int, struct bpf_program *,
	    const char *, int, bpf_u_int32);

/* XXX - this took two arguments in 0.4 and 0.5 */
PCAP_AVAILABLE_0_6
PCAP_API void	pcap_freecode(struct bpf_program *);

PCAP_AVAILABLE_1_0
PCAP_API int	pcap_offline_filter(const struct bpf_program *,
	    const struct pcap_pkthdr *, const u_char *);

PCAP_AVAILABLE_0_4
PCAP_API int	pcap_datalink(pcap_t *);

PCAP_AVAILABLE_1_0
PCAP_API int	pcap_datalink_ext(pcap_t *);

PCAP_AVAILABLE_0_8
PCAP_API int	pcap_list_datalinks(pcap_t *, int **);

PCAP_AVAILABLE_0_8
PCAP_API int	pcap_set_datalink(pcap_t *, int);

PCAP_AVAILABLE_0_8
PCAP_API void	pcap_free_datalinks(int *);

PCAP_AVAILABLE_0_8
PCAP_API int	pcap_datalink_name_to_val(const char *);

PCAP_AVAILABLE_0_8
PCAP_API const char *pcap_datalink_val_to_name(int);

PCAP_AVAILABLE_0_8
PCAP_API const char *pcap_datalink_val_to_description(int);

PCAP_AVAILABLE_1_9
PCAP_API const char *pcap_datalink_val_to_description_or_dlt(int);

PCAP_AVAILABLE_0_4
PCAP_API int	pcap_snapshot(pcap_t *);

PCAP_AVAILABLE_0_4
PCAP_API int	pcap_is_swapped(pcap_t *);

PCAP_AVAILABLE_0_4
PCAP_API int	pcap_major_version(pcap_t *);

PCAP_AVAILABLE_0_4
PCAP_API int	pcap_minor_version(pcap_t *);

PCAP_AVAILABLE_1_9
PCAP_API int	pcap_bufsize(pcap_t *);

/* XXX */
PCAP_AVAILABLE_0_4
PCAP_API FILE	*pcap_file(pcap_t *);

#ifdef _WIN32
PCAP_AVAILABLE_0_4
PCAP_DEPRECATED("request a 'pcap_handle' that returns a HANDLE if you need it")
PCAP_API int	pcap_fileno(pcap_t *);
#else /* _WIN32 */
PCAP_AVAILABLE_0_4
PCAP_API int	pcap_fileno(pcap_t *);
#endif /* _WIN32 */

#ifdef _WIN32
  PCAP_API int	pcap_wsockinit(void);
#endif

PCAP_AVAILABLE_0_4
PCAP_API pcap_dumper_t *pcap_dump_open(pcap_t *, const char *);

#ifdef _WIN32
  PCAP_AVAILABLE_0_9
  PCAP_API pcap_dumper_t *pcap_dump_hopen(pcap_t *, intptr_t);

  #ifndef BUILDING_PCAP
    #define pcap_dump_fopen(p,f) \
	pcap_dump_hopen(p, _get_osfhandle(_fileno(f)))
  #endif
#else /*_WIN32*/
  PCAP_AVAILABLE_0_9
  PCAP_API pcap_dumper_t *pcap_dump_fopen(pcap_t *, FILE *fp);
#endif /*_WIN32*/

PCAP_AVAILABLE_1_7
PCAP_API pcap_dumper_t *pcap_dump_open_append(pcap_t *, const char *);

PCAP_AVAILABLE_0_8
PCAP_API FILE	*pcap_dump_file(pcap_dumper_t *);

PCAP_AVAILABLE_0_9
PCAP_API long	pcap_dump_ftell(pcap_dumper_t *);

PCAP_AVAILABLE_1_9
PCAP_API int64_t	pcap_dump_ftell64(pcap_dumper_t *);

PCAP_AVAILABLE_0_8
PCAP_API int	pcap_dump_flush(pcap_dumper_t *);

PCAP_AVAILABLE_0_4
PCAP_API void	pcap_dump_close(pcap_dumper_t *);

PCAP_AVAILABLE_0_4
PCAP_API void	pcap_dump(u_char *, const struct pcap_pkthdr *, const u_char *);

PCAP_AVAILABLE_0_7
PCAP_API int	pcap_findalldevs(pcap_if_t **, char *);

PCAP_AVAILABLE_0_7
PCAP_API void	pcap_freealldevs(pcap_if_t *);

PCAP_AVAILABLE_0_8
PCAP_API const char *pcap_lib_version(void);

#if defined(_WIN32)

  /*
   * Win32 definitions
   */

  /*!
    \brief A queue of raw packets that will be sent to the network with pcap_sendqueue_transmit().
  */
  struct pcap_send_queue
  {
	u_int maxlen;	/* Maximum size of the queue, in bytes. This
			   variable contains the size of the buffer field. */
	u_int len;	/* Current size of the queue, in bytes. */
	char *buffer;	/* Buffer containing the packets to be sent. */
  };

  typedef struct pcap_send_queue pcap_send_queue;

  /*!
    \brief This typedef is a support for the pcap_get_airpcap_handle() function
  */
  #if !defined(AIRPCAP_HANDLE__EAE405F5_0171_9592_B3C2_C19EC426AD34__DEFINED_)
    #define AIRPCAP_HANDLE__EAE405F5_0171_9592_B3C2_C19EC426AD34__DEFINED_
    typedef struct _AirpcapHandle *PAirpcapHandle;
  #endif

  PCAP_API int pcap_setbuff(pcap_t *p, int dim);
  PCAP_API int pcap_setmode(pcap_t *p, int mode);
  PCAP_API int pcap_setmintocopy(pcap_t *p, int size);

  PCAP_API HANDLE pcap_getevent(pcap_t *p);

  PCAP_AVAILABLE_1_8
  PCAP_API int pcap_oid_get_request(pcap_t *, bpf_u_int32, void *, size_t *);

  PCAP_AVAILABLE_1_8
  PCAP_API int pcap_oid_set_request(pcap_t *, bpf_u_int32, const void *, size_t *);

  PCAP_API pcap_send_queue* pcap_sendqueue_alloc(u_int memsize);

  PCAP_API void pcap_sendqueue_destroy(pcap_send_queue* queue);

  PCAP_API int pcap_sendqueue_queue(pcap_send_queue* queue, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);

  PCAP_API u_int pcap_sendqueue_transmit(pcap_t *p, pcap_send_queue* queue, int sync);

  PCAP_API struct pcap_stat *pcap_stats_ex(pcap_t *p, int *pcap_stat_size);

  PCAP_API int pcap_setuserbuffer(pcap_t *p, int size);

  PCAP_API int pcap_live_dump(pcap_t *p, char *filename, int maxsize, int maxpacks);

  PCAP_API int pcap_live_dump_ended(pcap_t *p, int sync);

  PCAP_API int pcap_start_oem(char* err_str, int flags);

  PCAP_API PAirpcapHandle pcap_get_airpcap_handle(pcap_t *p);

  #define MODE_CAPT 0
  #define MODE_STAT 1
  #define MODE_MON 2

#elif defined(MSDOS)



  PCAP_API int  pcap_stats_ex (pcap_t *, struct pcap_stat_ex *);
  PCAP_API void pcap_set_wait (pcap_t *p, void (*yield)(void), int wait);
  PCAP_API u_long pcap_mac_packets (void);

#else /* UN*X */


  PCAP_AVAILABLE_0_8
  PCAP_API int	pcap_get_selectable_fd(pcap_t *);

  PCAP_AVAILABLE_1_9
  PCAP_API const struct timeval *pcap_get_required_select_timeout(pcap_t *);

#endif /* _WIN32/MSDOS/UN*X */

#define PCAP_BUF_SIZE 1024


#define PCAP_SRC_FILE		2	/* local savefile */
#define PCAP_SRC_IFLOCAL	3	/* local network interface */
#define PCAP_SRC_IFREMOTE	4	/* interface on a remote host, using RPCAP */

#define PCAP_SRC_FILE_STRING "file://"

#define PCAP_SRC_IF_STRING "rpcap://"


#define PCAP_OPENFLAG_PROMISCUOUS		0x00000001


#define PCAP_OPENFLAG_DATATX_UDP		0x00000002


#define PCAP_OPENFLAG_NOCAPTURE_RPCAP		0x00000004


#define PCAP_OPENFLAG_NOCAPTURE_LOCAL		0x00000008

#define PCAP_OPENFLAG_MAX_RESPONSIVENESS	0x00000010

#define RPCAP_RMTAUTH_NULL 0

#define RPCAP_RMTAUTH_PWD 1

struct pcap_rmtauth
{
	
	int type;
	
	char *username;
	
	char *password;
};

PCAP_AVAILABLE_1_9_REMOTE
PCAP_API pcap_t	*pcap_open(const char *source, int snaplen, int flags,
	    int read_timeout, struct pcap_rmtauth *auth, char *errbuf);

PCAP_AVAILABLE_1_9_REMOTE
PCAP_API int	pcap_createsrcstr(char *source, int type, const char *host,
	    const char *port, const char *name, char *errbuf);

PCAP_AVAILABLE_1_9_REMOTE
PCAP_API int	pcap_parsesrcstr(const char *source, int *type, char *host,
	    char *port, char *name, char *errbuf);

PCAP_AVAILABLE_1_9_REMOTE
PCAP_API int	pcap_findalldevs_ex(const char *source,
	    struct pcap_rmtauth *auth, pcap_if_t **alldevs, char *errbuf);


#define PCAP_SAMP_NOSAMP	0

#define PCAP_SAMP_1_EVERY_N	1

#define PCAP_SAMP_FIRST_AFTER_N_MS 2

struct pcap_samp
{
	
	int method;

	
	int value;
};


PCAP_AVAILABLE_1_9_REMOTE
PCAP_API struct pcap_samp *pcap_setsampling(pcap_t *p);


#define RPCAP_HOSTLIST_SIZE 1024

PCAP_AVAILABLE_1_9_REMOTE
PCAP_API PCAP_SOCKET	pcap_remoteact_accept(const char *address, const char *port,
	    const char *hostlist, char *connectinghost,
	    struct pcap_rmtauth *auth, char *errbuf);

PCAP_AVAILABLE_1_10_REMOTE
PCAP_API PCAP_SOCKET	pcap_remoteact_accept_ex(const char *address, const char *port,
	    const char *hostlist, char *connectinghost,
	    struct pcap_rmtauth *auth, int uses_ssl, char *errbuf);

PCAP_AVAILABLE_1_9_REMOTE
PCAP_API int	pcap_remoteact_list(char *hostlist, char sep, int size,
	    char *errbuf);

PCAP_AVAILABLE_1_9_REMOTE
PCAP_API int	pcap_remoteact_close(const char *host, char *errbuf);

PCAP_AVAILABLE_1_9_REMOTE
PCAP_API void	pcap_remoteact_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* lib_pcap_pcap_h */
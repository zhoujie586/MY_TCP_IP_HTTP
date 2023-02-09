/**
 * 用1500行代码从0开始实现TCP/IP协议栈+WEB服务器
 *
 * 本源码旨在用最简单、最易懂的方式帮助你快速地了解TCP/IP以及HTTP工作原理的主要核心知识点。
 * 所有代码经过精心简化设计，避免使用任何复杂的数据结构和算法，避免实现其它无关紧要的细节。
 *
 * 本源码配套高清的视频教程，免费提供下载！具体的下载网址请见下面。
 * 视频中的PPT暂时提供下载，但配套了学习指南，请访问下面的网址。
 *
 * 作者：李述铜
 * 网址: http://01ketang.cc/tcpip
 * QQ群1：78034806   QQ群2：1063238091 （加群时请注明：tcpip），免费提供关于该源码的支持和问题解答。
 * 微信公众号：请搜索 01课堂
 *
 * 版权声明：源码仅供学习参考，请勿用于商业产品，不保证可靠性。二次开发或其它商用前请联系作者。
 * 注：
 * 1.源码不断升级中，该版本可能非最新版。如需获取最新版，请访问上述网址获取最新版本的代码
 * 2.1500行代码指未包含注释的代码。
 *
 * 如果你在学习本课程之后，对深入研究TCP/IP感兴趣，欢迎关注我的后续课程。我将开发出一套更加深入
 * 详解TCP/IP的课程。采用多线程的方式，实现更完善的功能，包含但不限于
 * 1. IP层的分片与重组
 * 2. Ping功能的实现
 * 3. TCP的流量控制等
 * 4. 基于UDP的TFTP服务器实现
 * 5. DNS域名接触
 * 6. DHCP动态地址获取
 * 7. HTTP服务器
 * ..... 更多功能开发中...........
 * 如果你有兴趣的话，欢迎关注。
 */
#ifndef XNET_TINY_H
#define XNET_TINY_H

#include <stdint.h>

#define XNET_CFG_PACKET_MAX_SIZE		1516		// 收发数据包的最大大小

#define XNET_MAC_ADDR_SIZE				6			// MAC地址长度

#define XNET_IPV4_ADDR_SIZE				4			// IPV4地址长度

#define XARP_CFG_ENTRY_OK_TMO			(30)		// ARP表项超时时间
#define XARP_CFG_ENTRY_PENDING_TMO		(1)			// ARP表项挂起超时时间
#define XARP_CFG_MAX_RETRIES			(4)			// ARP表挂起时重试查询次数

#define XNET_CFG_NETIF_IP				{192, 168, 254, 2}	// 该程序的网卡IP

#define XNET_CFG_MAX_UDP				10
#define XNET_CFG_MAX_TCP				10

#define XTCP_CFG_RTX_BUF_SIZE			128


 /**
  * 网络数据结构
  */
typedef struct _xnet_packet_t
{
	uint16_t size;								// 数据包中有效数据大小
	uint8_t* data;								// 数据包的起始地址
	uint8_t payload[XNET_CFG_PACKET_MAX_SIZE];	// 最大负载数据量
}xnet_packet_t;

typedef enum _xnet_err_t
{
	XNET_ERR_OK = 0,
	XNET_ERR_IO = -1,
	XNET_ERR_NONE = -2,
	XNET_ERR_BINDED = -3,
}xnet_err_t;


#pragma pack(1)
 /**
  * 以太网数据帧格式的帧头：RFC894
  */
typedef struct _xether_hdr_t 
{
	uint8_t dest[XNET_MAC_ADDR_SIZE];			// 目标mac地址
	uint8_t src[XNET_MAC_ADDR_SIZE];			// 源mac地址
	uint16_t protocal;							// 协议/长度
}xether_hdr_t;
#pragma pack()

xnet_packet_t* xnet_alloc_for_send(uint16_t data_size);
xnet_packet_t* xnet_alloc_for_read(uint16_t data_size);
void truncate_header(xnet_packet_t* packet, uint16_t size);

xnet_err_t xnet_driver_open(uint8_t* mac_addr);
xnet_err_t xnet_driver_send(xnet_packet_t* packet);
xnet_err_t xnet_driver_read(xnet_packet_t** packet);


typedef enum _xnet_protocal_t
{
	XNET_PROTOCAL_ARP = 0x0806,		// ARP协议，以太网协议类型
	XNET_PROTOCAL_IP = 0x0800,		// IP协议，以太网协议类型

	XNET_PROTOCAL_ICMP = 1,			// ICMP协议，IP协议号
	XNET_PROTOCAL_TCP = 6,			// TCP协议，IP协议号
	XNET_PROTOCAL_UDP = 17,			// UDP协议，IP协议号

}xnet_protocal_t;


/**
 * IP地址
 */
typedef union _xipaddr_t 
{
	uint8_t array[XNET_IPV4_ADDR_SIZE];			// 以数据形式存储的ip
	uint32_t addr;								// 32位的ip地址
}xipaddr_t;

#define XARP_ENTRY_FREE					0		// ARP表项空闲
#define XARP_ENTRY_OK					1		// 
#define XARP_ENTRY_PENDING				2		// 
#define XARP_TIMER_PERIOD				1

/**
 * ARP表项
 */
typedef struct _xarp_entry_t
{
	xipaddr_t ipaddr;							// ip地址
	uint8_t macaddr[XNET_MAC_ADDR_SIZE];		// mac地址
	uint8_t state;								// 状态位
	uint16_t tmo;								// 当前超时
	uint8_t retry_cnt;							// 当前重试次数
}xarp_entry_t;


#pragma pack(1)
typedef struct _xarp_packet_t
{
	uint16_t hw_type, pro_type;					// 硬件类型和协议类型
	uint8_t hw_len, pro_len;					// 硬件地址长度 + 协议地址长度
	uint16_t opcode;							// 请求/响应
	uint8_t sender_mac[XNET_MAC_ADDR_SIZE];		// 发送方硬件地址
	uint8_t sender_ip[XNET_IPV4_ADDR_SIZE];		// 发送方协议地址
	uint8_t target_mac[XNET_MAC_ADDR_SIZE];		// 接收方硬件地址
	uint8_t target_ip[XNET_IPV4_ADDR_SIZE];		// 接收方协议地址
}xarp_packet_t;
#pragma pack()

#define XARP_REQUEST		0x1					// ARP请求包
#define XARP_REPLY			0x2					// ARP响应包
#define XARP_HW_EHTER		0x1					// 以太网

typedef uint32_t xnet_time_t;
const xnet_time_t xsys_get_time(void);			// 时间类型，返回当前系统跑了多少个100ms

void xarp_init(void);
xnet_err_t xarp_make_request(const xipaddr_t* ipaddr);
xnet_err_t xarp_make_response(xarp_packet_t* arp_packet);
xnet_err_t xarp_resolve(const xipaddr_t* ipaddr, uint8_t** mac_addr);
void xarp_in(xnet_packet_t* packet);
void xarp_poll(void);


#pragma pack(1)
typedef struct _xip_hdr_t
{
	uint8_t hdr_len : 4;						// 首部长, 4字节为单位
	uint8_t version : 4;						// 版本号, 4字节为单位
	uint8_t tos;								// 服务类型
	uint16_t total_len;							// 总长度
	uint16_t id;								// 标识符
	uint16_t flags_fragment;					// 标志与分段
	uint8_t ttl;								// 存活时间
	uint8_t protocal;							// 上层协议
	uint16_t checksum;							// 首部校验和
	uint8_t src_ip[XNET_IPV4_ADDR_SIZE];		// 源IP	
	uint8_t dest_ip[XNET_IPV4_ADDR_SIZE];		// 目标IP
}xip_hdr_t;
#pragma pack()

#define XNET_VERSION_IPV4			4
#define XNET_IP_DEFAULT_TTL			64

void xip_init(void);
void xip_in(xnet_packet_t* packet);
xnet_err_t xip_out(xnet_protocal_t protocal, xipaddr_t* dest_ip, xnet_packet_t* packet);



#pragma pack(1)
typedef struct _xicmp_hdr_t
{
	uint8_t type;								// 类型
	uint8_t code;								// 代码
	uint16_t checksum;							// 首部校验和
	uint16_t id;								// 标识符
	uint16_t seq;								// 序号 

}xicmp_hdr_t;
#pragma pack()

#define XICMP_TYPE_ECHO_REQUEST			8
#define XICMP_TYPE_ECHO_RERLY			0
#define XICMP_TYPE_UNREACH				3

#define XICMP_CODE_PORT_UNRECH			3
#define XICMP_CODE_PROTOCAL_UNRECH		2


void xicmp_init(void);
void xicmp_in(xipaddr_t* src_ip, xnet_packet_t* packet);
xnet_err_t xicmp_dest_unreach(uint8_t code, xip_hdr_t* ip_hdr);

#pragma pack(1)
typedef struct _xudp_hdr_t
{
	uint16_t src_port;
	uint16_t dest_port;
	uint16_t total_len;
	uint16_t checksum;
}xudp_hdr_t;
#pragma pack()

typedef struct _xudp_t xudp_t;
typedef xnet_err_t(*xudp_handler_t)(xudp_t* udp, xipaddr_t* src_ip, uint16_t src_port,
	xnet_packet_t* packet);

struct _xudp_t
{
	enum
	{
		XUDP_STATE_FREE,				// UDP未使用
		XUDP_STATE_USED,				// UDP已使用
	}state;								// 状态

	uint16_t local_port;				// 本地端口
	xudp_handler_t handler;				// 事件处理回调
};

void xudp_init(void);
void xudp_in(xudp_t* udp, xipaddr_t* src_ip, xnet_packet_t* packet);
xnet_err_t xudp_out(xudp_t* udp, xipaddr_t* dest_ip, uint16_t dest_port, xnet_packet_t* packet);

xudp_t* xudp_open(xudp_handler_t handler);
void xudp_close(xudp_t* udp);
xudp_t* xudp_find(uint16_t port);
xnet_err_t xudp_bind(xudp_t* udp, uint16_t local_port);


#define XTCP_FLAG_FIN				(1 << 0)
#define XTCP_FLAG_SYN				(1 << 1)
#define XTCP_FLAG_RST				(1 << 2)
#define XTCP_FLAG_ACK				(1 << 4)

#pragma pack(1)
typedef struct _xtcp_hdr_t
{
	uint16_t src_port;
	uint16_t dest_port;
	uint32_t seq;
	uint32_t ack;

	union
	{
		struct
		{
			uint16_t flags : 6;
			uint16_t reserved : 6;
			uint16_t hdr_len : 4;
		};
		uint16_t all;
	}hdr_flags;

	uint16_t window;
	uint16_t checksum;
	uint16_t urgent_ptr;

}xtcp_hdr_t;
#pragma pack()

typedef struct _xtcp_buf_t
{
	uint16_t data_count, unacked_count;			// 总的数据量+未发送的数据量
	uint16_t tail, next, front;					// 起始、结束、下一待发送位置
	uint8_t data[XTCP_CFG_RTX_BUF_SIZE];		// 数据缓存空间

}xtcp_buf_t;

typedef enum _xtcp_state_t 
{
	XTCP_STATE_FREE,
	XTCP_STATE_CLOSED,
	XTCP_STATE_LISTEN,
	XTCP_STATE_SYN_RECVD,
	XTCP_STATE_ESTABLISHED,
	XTCP_STATE_FIN_WAIT_1,
	XTCP_STATE_FIN_WAIT_2,
	XTCP_STATE_CLOSING,
	XTCP_STATE_TIMED_WAIT,
	XTCP_STATE_CLOSE_WAIT,
	XTCP_STATE_LAST_ACK,
}xtcp_state_t;

typedef enum _xtcp_conn_state_t
{
	XTCP_CONN_CONNECTED,
	XTCP_CONN_DATA_RECV,
	XTCP_CONN_CLOSED,
}xtcp_conn_state_t;

#define XTCP_KIND_END			0
#define XTCP_KIND_MSS			2
#define XTCP_MSS_DEFAULT		1460

typedef struct _xtcp_t xtcp_t;
typedef xnet_err_t(*xtcp_handler_t)(xtcp_t* tcp, xtcp_conn_state_t event);

struct _xtcp_t
{
	xtcp_state_t state;					// 状态
	uint16_t local_port;				// 本地端口 + 源端口
	uint16_t remote_port;
	xipaddr_t remote_ip;				// 源IP

	uint32_t next_seq;					// 下一发送序号
	uint32_t unacked_seq;				// 未确认的起始序号
	uint32_t ack;						// 期望对方发来的包序号

	uint16_t remote_mss;				// 对方的mss,不含选项区
	uint16_t remote_win;				// 对方的窗口大小

	xtcp_handler_t handler;				// 事件处理回调

	xtcp_buf_t tx_buf;					// 收发缓冲区
	xtcp_buf_t rx_buf;
};

void xtcp_init(void);
void xtcp_in(xipaddr_t* remote_ip, xnet_packet_t* packet);
int xtcp_write(xtcp_t* tcp, uint8_t* data, uint16_t size);
int xtcp_read(xtcp_t* tcp, uint8_t* data, uint16_t size);

xtcp_t* xtcp_open(xtcp_handler_t handler);
xnet_err_t xtcp_bind(xtcp_t* tcp, uint16_t local_port);
xnet_err_t xtcp_listen(xtcp_t* tcp);
xnet_err_t xtcp_close(xtcp_t* tcp);

void xnet_init(void);
void xnet_poll(void);


#endif // XNET_TINY_H


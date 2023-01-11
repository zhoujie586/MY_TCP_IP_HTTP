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
#include <string.h>
#include "xnet_tiny.h"

#define min(a, b)		((a) > (b) ? (b) : (a))

#define swap_order16(v)   ((((v) & 0xFF) << 8) | (((v) >> 8) & 0xFF))
#define xipaddr_is_equal_buf(ipaddr, buf) (memcmp((ipaddr)->array, buf, XNET_IPV4_ADDR_SIZE) == 0)


static uint8_t netif_mac[XNET_MAC_ADDR_SIZE];					// 用于存储服务器网口mac地址
static const uint8_t ether_broadcast[XNET_MAC_ADDR_SIZE] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static const xipaddr_t netif_ipaddr = XNET_CFG_NETIF_IP;

static xnet_packet_t tx_packet, rx_packet;						// 接收与发送缓冲区
static xarp_entry_t arp_entry;									// 节省内存，只使用一个ARP表项
static xnet_time_t arp_timer;

/**
 * 检查是否超时
 * @param time 前一时间
 * @param sec 预期超时时间，值为0时，表示获取当前时间
 * @return 0 - 未超时，1-超时
 */
int xnet_check_tmo(xnet_time_t* time, xnet_time_t sec)
{
	xnet_time_t curr = xsys_get_time();
	if (sec == 0)
	{
		*time = curr;
		return 0;
	}
	else if ((curr - *time) >= sec)
	{
		*time = curr;
		return 1;
	}

	return 0;
}


/**
 * 分配一个网络数据包用于发送数据
 * @param data_size 数据空间大小
 * @return 分配得到的包结构
 */
xnet_packet_t* xnet_alloc_for_send(uint16_t data_size)
{
	// 从tx_packet的后端往前分配，因为前边要预留作为各种协议的头部数据存储空间
	tx_packet.data = tx_packet.payload + XNET_CFG_PACKET_MAX_SIZE - data_size;
	tx_packet.size = data_size;
	return &tx_packet;
}	

/**
 * 分配一个网络数据包用于读取
 * @param data_size 数据空间大小
 * @return 分配得到的数据包
 */
xnet_packet_t* xnet_alloc_for_read(uint16_t data_size)
{
	// 从最开始进行分配，用于最底层的网络数据帧读取
	rx_packet.data = rx_packet.payload;
	rx_packet.size = data_size;
	return &rx_packet;
}

/**
 * 为发包添加一个头部
 * @param packet 待处理的数据包
 * @param header_size 增加的头部大小
 */
static void add_header(xnet_packet_t* packet, uint16_t header_size)
{
	packet->data -= header_size;
	packet->size += header_size;
}

/**
 * 为接收向上处理移去头部
 * @param packet 待处理的数据包
 * @param header_size 移去的头部大小
 */
static void remove_header(xnet_packet_t* packet, uint16_t header_size)
{
	packet->data += header_size;
	packet->size -= header_size;
}

/**
 * 将包的长度截断为size大小
 * @param packet 待处理的数据包
 * @param size 最终大小
 */
static void truncate_header(xnet_packet_t* packet, uint16_t size)
{
	packet->size = min(packet->size, size);
}

/**
 * 以太网初始化
 * @return 初始化结果
 */
static xnet_err_t ethernet_init(void)
{
	xnet_err_t err = xnet_driver_open(netif_mac);

	if (err < 0) return err;

	return xarp_make_request(&netif_ipaddr);
}

/**
 * 发送一个以太网数据帧
 * @param protocol 上层数据协议，IP或ARP
 * @param mac_addr 目标网卡的mac地址
 * @param packet 待发送的数据包
 * @return 发送结果
 */
static xnet_err_t ethernet_out_to(xnet_protocal_t protocal, const uint8_t* mac_addr, xnet_packet_t* packet)
{
	xether_hdr_t* ether_hdr;

	// 添加头部
	add_header(packet, sizeof(xether_hdr_t));
	ether_hdr = (xether_hdr_t*)packet->data;
	memcpy(ether_hdr->dest, mac_addr, XNET_MAC_ADDR_SIZE);
	memcpy(ether_hdr->src, netif_mac, XNET_MAC_ADDR_SIZE);
	ether_hdr->protocal = swap_order16(protocal);

	// 数据发送
	return xnet_driver_send(packet);
}

/**
 * 以太网数据帧输入处理
 * @param packet 待处理的包
 */
static void ethernet_in(xnet_packet_t* packet)
{
	// 至少要比头部数据大
	if (packet->size <= sizeof(xether_hdr_t))
	{
		return;
	}
	
	// 往上分解到各个协议处理
	xether_hdr_t* ether_hdr;
	ether_hdr = (xether_hdr_t*)packet->data;
	switch (swap_order16(ether_hdr->protocal))
	{
	case XNET_PROTOCAL_ARP:
		remove_header(packet, sizeof(xether_hdr_t));
		xarp_in(packet);
		break;
	case XNET_PROTOCAL_IP:
		break;
	default:
		break;
	}
}

/**
 * 查询网络接口，看看是否有数据包，有则进行处理
 */
static void ethernet_poll(void)
{
	xnet_packet_t* packet;

	if (xnet_driver_read(&packet) == XNET_ERR_OK)
	{
		// 正常情况下，在此打个断点，全速运行
		// 然后在对方端ping 192.168.254.2，会停在这里
		ethernet_in(packet);
	}
}

/**
 * ARP初始化
 */
void xarp_init(void)
{
	arp_entry.state = XARP_ENRTY_FREE;
	xnet_check_tmo(&arp_timer, 0);
}

/**
 * 产生一个ARP请求，请求网络指定ip地址的机器发回一个ARP响应
 * @param ipaddr 请求的IP地址
 * @return 请求结果
 */
xnet_err_t xarp_make_request(const xipaddr_t* ipaddr)
{
	xnet_packet_t* packet = xnet_alloc_for_send(sizeof(xarp_packet_t));
	xarp_packet_t* arp_packet = (xarp_packet_t*)packet->data;

	arp_packet->hw_type = swap_order16(XARP_HW_EHTER);
	arp_packet->hw_len = XNET_MAC_ADDR_SIZE;
	arp_packet->pro_type = swap_order16(XNET_PROTOCAL_IP);
	arp_packet->pro_len = XNET_IPV4_ADDR_SIZE;
	arp_packet->opcode = swap_order16(XARP_REQUEST);
	memcpy(arp_packet->sender_mac, netif_mac, XNET_MAC_ADDR_SIZE);
	memcpy(arp_packet->sender_ip, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
	memset(arp_packet->target_mac, 0, XNET_MAC_ADDR_SIZE);
	memcpy(arp_packet->target_ip, ipaddr->array, XNET_IPV4_ADDR_SIZE);

	return ethernet_out_to(XNET_PROTOCAL_ARP, ether_broadcast, packet);
}

/**
 * 生成一个ARP响应
 * @param arp_packet 接收到的ARP请求包
 * @return 生成结果
 */
xnet_err_t xarp_make_response(xarp_packet_t* arp_packet)
{
	xnet_packet_t* packet = xnet_alloc_for_send(sizeof(xarp_packet_t));
	xarp_packet_t* response_packet = (xarp_packet_t*)packet->data;

	response_packet->hw_type = swap_order16(XARP_HW_EHTER);
	response_packet->hw_len = XNET_MAC_ADDR_SIZE;
	response_packet->pro_type = swap_order16(XNET_PROTOCAL_IP);
	response_packet->pro_len = XNET_IPV4_ADDR_SIZE;
	response_packet->opcode = swap_order16(XARP_REPLY);
	memcpy(response_packet->sender_mac, netif_mac, XNET_MAC_ADDR_SIZE);
	memcpy(response_packet->sender_ip, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
	memcpy(response_packet->target_mac, arp_packet->sender_mac, XNET_MAC_ADDR_SIZE);
	memcpy(response_packet->target_ip, arp_packet->sender_ip, XNET_IPV4_ADDR_SIZE);

	return ethernet_out_to(XNET_PROTOCAL_ARP, arp_packet->sender_mac, packet);
}

/**
 * 更新ARP表项
 * @param src_ip 源IP地址
 * @param mac_addr 对应的mac地址
 */
static void update_arp_entry(uint8_t* src_ip, uint8_t* mac_addr)
{
	memcpy(arp_entry.ipaddr.array, src_ip, XNET_IPV4_ADDR_SIZE);
	memcpy(arp_entry.macaddr, mac_addr, XNET_MAC_ADDR_SIZE);
	arp_entry.state = XARP_ENRTY_OK;
	arp_entry.tmo = XARP_CFG_ENTRY_OK_TMO;
	arp_entry.retry_cnt = XARP_CFG_MAX_RETRIES;
}

/**
 * ARP输入处理
 * @param packet 输入的ARP包
 */
void xarp_in(xnet_packet_t* packet)
{
	if (packet->size < sizeof(xarp_packet_t))									//数据段长度检查
		return;

	xarp_packet_t* arp_packet = (xarp_packet_t*)packet->data;
	uint16_t opcode = swap_order16(arp_packet->opcode);

	if ((swap_order16(arp_packet->hw_type) != XARP_HW_EHTER) ||					//硬件类型检查
		(swap_order16(arp_packet->pro_type) != XNET_PROTOCAL_IP) ||				//协议类型检查
		(arp_packet->hw_len != XNET_MAC_ADDR_SIZE) ||							//硬件地址长度检查
		(arp_packet->pro_len != XNET_IPV4_ADDR_SIZE)							//协议地址长度检查
		)		
		return;
	if ((opcode != XARP_REQUEST) && (opcode != XARP_REPLY))						//opcode类型检查
		return;	
	if (!xipaddr_is_equal_buf(&netif_ipaddr, arp_packet->target_ip))			//目标ip地址检查
		return;

	switch (opcode)
	{
	case XARP_REQUEST:
		xarp_make_response(arp_packet);
		update_arp_entry(arp_packet->sender_ip, arp_packet->sender_mac);
		break;
	case XARP_REPLY:
		update_arp_entry(arp_packet->sender_ip, arp_packet->sender_mac);
		break;
	default:
		break;
	}
}

/**
 * 查询ARP表项是否超时，超时则重新请求
 */
void xarp_poll(void)
{
	if (xnet_check_tmo(&arp_timer, XARP_TIMER_PERIOD) == 0)
		return;
	
	switch (arp_entry.state)
	{
	case XARP_ENRTY_OK:
		if (--arp_entry.tmo)
			break;
		// 超时，重新请求
		xarp_make_request(&arp_entry.ipaddr);
		arp_entry.state = XARP_ENRTY_PENDING;
		arp_entry.tmo = XARP_CFG_ENTRY_PENDING_TMO;
		break;
	case XARP_ENRTY_PENDING:
		if (--arp_entry.tmo)
			break;

		if (arp_entry.retry_cnt-- == 0)		// 重试完毕，回收
		{
			arp_entry.state = XARP_ENRTY_FREE;
		}
		else	// 继续重试
		{
			xarp_make_request(&arp_entry.ipaddr);
			arp_entry.state = XARP_ENRTY_PENDING;
			arp_entry.tmo = XARP_CFG_ENTRY_PENDING_TMO;
		}
		break;
	default:
		break;
	}
}

/**
 * 协议栈的初始化
 */
void xnet_init(void)
{
	ethernet_init();
	xarp_init();

}

/**
 * 轮询处理数据包，并在协议栈中处理
 */
void xnet_poll(void)
{
	ethernet_poll();
	xarp_poll();
}
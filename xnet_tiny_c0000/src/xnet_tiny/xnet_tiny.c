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
#include <stdlib.h>
#include <stdio.h>

//#define min(a, b)		((a) > (b) ? (b) : (a))

#define tcp_get_init_seq()		((rand() << 16) + rand())
#define XTCP_DATA_MAX_SIZE		(XNET_CFG_PACKET_MAX_SIZE - sizeof(xether_hdr_t) - sizeof(xip_hdr_t) - sizeof(xtcp_hdr_t))

#define swap_order16(v)   ((((v) & 0xFF) << 8) | (((v) >> 8) & 0xFF))
#define swap_order32(v)   ((((v) & 0xFF) << 24) | ((((v) >> 8) & 0xFF) << 16) | ((((v) >> 16) & 0xFF) << 8) | ((((v) >> 24) & 0xFF) << 0))

#define xipaddr_is_equal_buf(ipaddr, buf) (memcmp((ipaddr)->array, buf, XNET_IPV4_ADDR_SIZE) == 0)
#define xipaddr_is_equal(addr1, addr2) ((addr1)->addr == (addr2)->addr)
#define xipaddr_from_buf(dest, buf)		((dest)->addr = *(uint32_t *)(buf))

static uint8_t netif_mac[XNET_MAC_ADDR_SIZE];					// 用于存储服务器网口mac地址
static const uint8_t ether_broadcast[XNET_MAC_ADDR_SIZE] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static const xipaddr_t netif_ipaddr = XNET_CFG_NETIF_IP;

static xnet_packet_t tx_packet, rx_packet;						// 接收与发送缓冲区
static xarp_entry_t arp_entry;									// 节省内存，只使用一个ARP表项
static xnet_time_t arp_timer;
static xudp_t udp_socket[XNET_CFG_MAX_UDP];
static xtcp_t tcp_socket[XNET_CFG_MAX_TCP];

static void update_arp_entry(uint8_t* src_ip, uint8_t* mac_addr);

static void tcp_buf_init(xtcp_buf_t* tcp_buf);

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
void truncate_header(xnet_packet_t* packet, uint16_t size)
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

static xnet_err_t ethernet_out(xipaddr_t* dest_ip, xnet_packet_t* packet)
{
	xnet_err_t err;
	uint8_t* mac_addr;

	err = xarp_resolve(dest_ip, &mac_addr);
	if (err == XNET_ERR_OK)
		return ethernet_out_to(XNET_PROTOCAL_IP, mac_addr, packet);
	return err;
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
	{
		//xip_hdr_t* iphdr = (xip_hdr_t*)(packet->data + sizeof(xether_hdr_t));
		//update_arp_entry(iphdr->src_ip, ether_hdr->src);
		remove_header(packet, sizeof(xether_hdr_t));
		xip_in(packet);
		break;
	}
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
	arp_entry.state = XARP_ENTRY_FREE;
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

xnet_err_t xarp_resolve(const xipaddr_t* ipaddr, uint8_t** mac_addr)
{
	if ((arp_entry.state = XARP_ENTRY_OK) && xipaddr_is_equal(ipaddr, &arp_entry.ipaddr))
	{
		*mac_addr = arp_entry.macaddr;
		return XNET_ERR_OK;
	}

	xarp_make_request(ipaddr);
	return XNET_ERR_NONE;
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
	arp_entry.state = XARP_ENTRY_OK;
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
	case XARP_ENTRY_OK:
		if (--arp_entry.tmo)
			break;
		// 超时，重新请求
		xarp_make_request(&arp_entry.ipaddr);
		arp_entry.state = XARP_ENTRY_PENDING;
		arp_entry.tmo = XARP_CFG_ENTRY_PENDING_TMO;
		break;
	case XARP_ENTRY_PENDING:
		if (--arp_entry.tmo)
			break;

		if (arp_entry.retry_cnt-- == 0)		// 重试完毕，回收
		{
			arp_entry.state = XARP_ENTRY_FREE;
		}
		else	// 继续重试
		{
			xarp_make_request(&arp_entry.ipaddr);
			arp_entry.state = XARP_ENTRY_PENDING;
			arp_entry.tmo = XARP_CFG_ENTRY_PENDING_TMO;
		}
		break;
	default:
		break;
	}
}

/**
 * 校验和计算
 * @param buf 校验数据区的起始地址
 * @param len 数据区的长度，以字节为单位
 * @param pre_sum 累加的之前的值，用于多次调用checksum对不同的的数据区计算出一个校验和
 * @param complement 是否对累加和的结果进行取反
 * @return 校验和结果
 */
static uint16_t checksum16(uint16_t* buf, uint16_t len, uint16_t pre_sum, int complement)
{
	uint32_t checksum = pre_sum;
	uint16_t high;
	while (len > 1)
	{
		checksum += *buf++;
		len -= 2;
	}

	if (len > 0)
	{
		checksum += *(uint8_t*)buf;
	}

	while ((high = checksum >> 16) != 0)
	{
		checksum = high + (checksum & 0xFFFF);
	}

	return complement ? (uint16_t)~checksum : (uint16_t)checksum;
}

/**
 * IP层的初始化
 */
void xip_init(void)
{

}


/**
 * IP层的输入处理
 * @param packet 输入的IP数据包
 */
void xip_in(xnet_packet_t* packet)
{
	xip_hdr_t* ip_hdr = (xip_hdr_t*)packet->data;
	uint16_t header_size;
	uint16_t total_size;
	uint16_t pre_checksum;
	xipaddr_t src_ip;

	// 只处理目标IP为自己的数据包，其它广播之类的IP全部丢掉
	if (!xipaddr_is_equal_buf(&netif_ipaddr, ip_hdr->dest_ip))
		return;

	// 进行一些必要性的检查：版本号要求
	if (ip_hdr->version != XNET_VERSION_IPV4)
		return;

	// 长度要求检查
	header_size = ip_hdr->hdr_len * 4;
	total_size = swap_order16(ip_hdr->total_len);
	if ((header_size < sizeof(xip_hdr_t)) || (total_size < header_size))
		return;

	// 校验和要求检查
	pre_checksum = ip_hdr->checksum;
	ip_hdr->checksum = 0;
	if (pre_checksum != checksum16((uint16_t*)ip_hdr, header_size, 0, 1))
		return;
	ip_hdr->checksum = pre_checksum;

	xipaddr_from_buf(&src_ip, ip_hdr->src_ip);

	// 多跟复用，分别交由ICMP、UDP、TCP处理
	switch (ip_hdr->protocal)
	{
	case XNET_PROTOCAL_ICMP:
		remove_header(packet, sizeof(xip_hdr_t));
		xicmp_in(&src_ip, packet);
		break;
	case XNET_PROTOCAL_UDP:
	{
		xudp_hdr_t* udp_hdr = (xudp_hdr_t*)(packet->data + header_size);
		xudp_t* udp = xudp_find(swap_order16(udp_hdr->dest_port));
		if (udp)
		{
			remove_header(packet, sizeof(xip_hdr_t));
			xudp_in(udp, &src_ip, packet);
		}
		else
			xicmp_dest_unreach(XICMP_CODE_PROTOCAL_UNRECH, ip_hdr);
		break;
	}
	case XNET_PROTOCAL_TCP:
		truncate_header(packet, total_size);
		remove_header(packet, sizeof(xip_hdr_t));
		xtcp_in(&src_ip, packet);
		break;
	default:
		xicmp_dest_unreach(XICMP_CODE_PROTOCAL_UNRECH, ip_hdr);
		break;
	}
}

/**
 * IP包的输出
 * @param protocol 上层协议，ICMP、UDP或TCP
 * @param dest_ip
 * @param packet
 * @return
 */
xnet_err_t xip_out(xnet_protocal_t protocal, xipaddr_t* dest_ip, xnet_packet_t* packet) 
{
	static uint32_t ip_packet_id = 0;
	xip_hdr_t* ip_hdr;

	add_header(packet, sizeof(xip_hdr_t));
	ip_hdr = (xip_hdr_t*)packet->data;

	ip_hdr->version = XNET_VERSION_IPV4;
	ip_hdr->hdr_len = sizeof(xip_hdr_t) / 4;
	ip_hdr->tos = 0;
	ip_hdr->total_len = swap_order16(packet->size);

	ip_hdr->id = swap_order16(ip_packet_id);
	ip_hdr->flags_fragment = 0;

	ip_hdr->ttl = XNET_IP_DEFAULT_TTL;
	ip_hdr->protocal = protocal;
	memcpy(ip_hdr->src_ip, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
	memcpy(ip_hdr->dest_ip, dest_ip->array, XNET_IPV4_ADDR_SIZE);
	ip_hdr->checksum = 0;
	ip_hdr->checksum = checksum16((uint16_t*)ip_hdr, sizeof(xip_hdr_t), 0, 1);

	ip_packet_id++;
	// 数据发送
	return ethernet_out(dest_ip, packet);
}

/**
 * icmp初始化
 */
void xicmp_init(void)
{

}

/**
 * 发送ICMP ECHO响应，即回应ping
 * @param icmp_hdr 收到的icmp包头
 * @param src_ip 包的来源ip
 * @param packet 收到的数据包
 * @return 处理结果
 */
static xnet_err_t reply_icmp_request(xicmp_hdr_t* icmp_hdr, xipaddr_t* src_ip, xnet_packet_t* rx_packet)
{
	xnet_packet_t* tx_packet = xnet_alloc_for_send(rx_packet->size);
	xicmp_hdr_t* reply_hdr = (xicmp_hdr_t*)tx_packet->data;

	reply_hdr->type = XICMP_TYPE_ECHO_RERLY;
	reply_hdr->code = 0; 
	reply_hdr->id = icmp_hdr->id;
	reply_hdr->seq = icmp_hdr->seq;

	memcpy((uint8_t*)reply_hdr + sizeof(xicmp_hdr_t), (uint8_t*)icmp_hdr + sizeof(xicmp_hdr_t),
		rx_packet->size - sizeof(xicmp_hdr_t));

	reply_hdr->checksum = 0;
	reply_hdr->checksum = checksum16((uint16_t*)reply_hdr, tx_packet->size, 0, 1);

	return xip_out(XNET_PROTOCAL_ICMP, src_ip, tx_packet);
}

/**
 * ICMP包输入处理
 * @param src_ip 数据包来源
 * @param packet 待处理的数据包
 */
void xicmp_in(xipaddr_t* src_ip, xnet_packet_t* packet)
{
	xicmp_hdr_t* icmp_hdr = (xicmp_hdr_t*)packet->data;

	if (packet->size < sizeof(xicmp_hdr_t))
		return;

	switch (icmp_hdr->type)
	{
	case XICMP_TYPE_ECHO_REQUEST:
		reply_icmp_request(icmp_hdr, src_ip, packet);
	default:
		break;
	}
}

/**
 * 发送ICMP端口不可达或协议不可达的响应
 * @param code 不可达的类型码
 * @param ip_hdr 收到的ip包
 * @return 处理结果
 */
xnet_err_t xicmp_dest_unreach(uint8_t code, xip_hdr_t* ip_hdr) 
{
	xicmp_hdr_t* imcp_hdr;
	xnet_packet_t* packet;
	xipaddr_t dest_ip;

	// 计算要拷贝的ip数据量
	uint16_t ip_hdr_size = ip_hdr->hdr_len * 4;
	uint16_t ip_data_size = swap_order16(ip_hdr->total_len) - ip_hdr_size;

	// RFC文档里写的是8字节。但实际测试windows上发现复制了不止8个字节
	ip_data_size = ip_hdr_size + min(ip_data_size, 8);

	// 生成数据包，然后发送
	packet = xnet_alloc_for_send(sizeof(xicmp_hdr_t) + ip_data_size);

	imcp_hdr = (xicmp_hdr_t*)packet->data;
	imcp_hdr->type = XICMP_TYPE_UNREACH;
	imcp_hdr->code = code;
	imcp_hdr->id = 0;
	imcp_hdr->seq = 0;
	memcpy((uint8_t*)imcp_hdr + sizeof(xicmp_hdr_t), (uint8_t*)ip_hdr, ip_data_size);
	imcp_hdr->checksum = 0;
	imcp_hdr->checksum = checksum16((uint16_t*)imcp_hdr, packet->size, 0, 1);

	xipaddr_from_buf(&dest_ip, ip_hdr->src_ip);

	return xip_out(XNET_PROTOCAL_ICMP, &dest_ip, packet);
}

/**
 * 计算UDP伪校验和
 * @param src_ip 源IP
 * @param dest_ip 目标IP
 * @param protocol 协议
 * @param buf 数据区
 * @param len 数据长度
 * @return 校验和结果
 */
uint16_t checksum_peso(const xipaddr_t* src_ip, const xipaddr_t* dest_ip, uint8_t protocal,
	uint16_t* buf, uint16_t len)
{
	uint32_t sum;
	uint8_t zero_proytocal[] = { 0, protocal };
	uint16_t c_len = swap_order16(len);

	sum = checksum16((uint16_t*)src_ip->array, XNET_IPV4_ADDR_SIZE, 0, 0);
	sum = checksum16((uint16_t*)dest_ip->array, XNET_IPV4_ADDR_SIZE, sum, 0);
	sum = checksum16((uint16_t*)zero_proytocal, 2, sum, 0);
	sum = checksum16((uint16_t*)&c_len, 2, sum, 0);

	return checksum16(buf, len, sum, 1);
}

/**
 * UDP初始化
 */
void xudp_init(void)
{
	memset(udp_socket, 0, sizeof(udp_socket));
}

/**
 * UDP输入处理
 * @param udp 待处理的UDP
 * @param src_ip 数据包来源
 * @param packet 数据包结构
 */
void xudp_in(xudp_t* udp, xipaddr_t* src_ip, xnet_packet_t* packet)
{
	xudp_hdr_t* udp_hdr = (xudp_hdr_t*)packet->data;
	uint16_t pre_checksum;
	uint16_t src_port;

	if (packet->size < sizeof(xudp_hdr_t))
		return;

	if (packet->size < swap_order16(udp_hdr->total_len))
		return;

	pre_checksum = udp_hdr->checksum;
	udp_hdr->checksum = 0;
	if (pre_checksum != 0)
	{
		uint16_t checksum = checksum_peso(src_ip, &netif_ipaddr, XNET_PROTOCAL_UDP,
			(uint16_t*)udp_hdr, swap_order16(udp_hdr->total_len));
		checksum = (checksum == 0) ? 0xffff : checksum;

		if (checksum != pre_checksum)
			return;
	}

	src_port = swap_order16(udp_hdr->src_port);
	remove_header(packet, sizeof(xudp_hdr_t));
	if (udp->handler)
	{
		udp->handler(udp, src_ip, src_port, packet);
	}

}

/**
 * 发送一个UDP数据包
 * @param udp udp结构
 * @param dest_ip 目标ip
 * @param dest_port 目标端口
 * @param packet 待发送的包
 * @return 发送结果
 */
xnet_err_t xudp_out(xudp_t* udp, xipaddr_t* dest_ip, uint16_t dest_port, xnet_packet_t* packet)
{
	xudp_hdr_t* udp_hdr;
	uint16_t checksum;

	add_header(packet, sizeof(xudp_hdr_t));
	udp_hdr = (xudp_hdr_t*)packet->data;
	udp_hdr->src_port = swap_order16(udp->local_port);
	udp_hdr->dest_port = swap_order16(dest_port);
	udp_hdr->total_len = swap_order16(packet->size);
	udp_hdr->checksum = 0;

	checksum = checksum_peso(&netif_ipaddr, dest_ip, XNET_PROTOCAL_UDP, 
		(uint16_t*)packet->data, packet->size);
	udp_hdr->checksum = checksum;

	return xip_out(XNET_PROTOCAL_UDP, dest_ip, packet);
}

/**
 * 打开UDP结构
 * @param handler 事件处理回调函数
 * @return 打开的xudp_t结构
 */
xudp_t* xudp_open(xudp_handler_t handler) 
{
	xudp_t* udp;
	xudp_t* end;

	for (udp = &udp_socket[0], end = &udp_socket[XNET_CFG_MAX_UDP]; udp < end; udp++)
	{
		if (udp->state == XUDP_STATE_FREE)
		{
			udp->state = XUDP_STATE_USED;
			udp->local_port = 0;
			udp->handler = handler;
			return udp;
		}
	}

	return (xudp_t*)0;
}

/**
 * 关闭UDP连接
 * @param udp 待关闭的xudp_t结构
 */
void xudp_close(xudp_t* udp)
{
	udp->state = XUDP_STATE_FREE;
}

/**
 * 查找指定端口对应的udp结构
 * @param port 待查找的端口
 * @return 找到的xudp_t结构
 */
xudp_t* xudp_find(uint16_t port)
{
	xudp_t* curr;
	xudp_t* end;
	for (curr = &udp_socket[0], end = &udp_socket[XNET_CFG_MAX_UDP]; curr < end; curr++)
	{
		if ((curr->state == XUDP_STATE_USED) && (curr->local_port == port))
			return curr;
	}

	return (xudp_t*)0;
}

/**
 * 绑定xudp_t结构到指定端口
 * @param udp 待绑定的结构
 * @param local_port 目标端口
 * @return 绑定结果
 */
xnet_err_t xudp_bind(xudp_t* udp, uint16_t local_port)
{
	xudp_t* curr;
	xudp_t* end;
	for (curr = &udp_socket[0], end = &udp_socket[XNET_CFG_MAX_UDP]; curr < end; curr++)
	{
		if ((curr != udp) && (curr->local_port == local_port))
			return XNET_ERR_BINDED;

	}

	udp->local_port = local_port;
	return XNET_ERR_OK;
}

/**
 * 分配一个tcp连接块
 * @return 分配结果，0-分配失败
 */
static xtcp_t* tcp_alloc(void)
{
	xtcp_t* tcp;
	xtcp_t* end;

	for (tcp = &tcp_socket[0], end = &tcp_socket[XNET_CFG_MAX_TCP]; tcp < end; tcp++)
	{
		if (tcp->state == XTCP_STATE_FREE)
		{
			tcp->local_port = 0;
			tcp->remote_port = 0;
			tcp->remote_ip.addr = 0;
			tcp->handler = (xtcp_handler_t)0;
			tcp->remote_win = XTCP_MSS_DEFAULT;
			tcp->remote_mss = XTCP_MSS_DEFAULT;
			tcp->next_seq = tcp_get_init_seq();
			tcp->unacked_seq = tcp->next_seq;
			tcp->ack = 0;
			tcp_buf_init(&tcp->tx_buf);
			tcp_buf_init(&tcp->rx_buf);
			return tcp;
		}
	}

	return (xtcp_t*)0;
}

/**
 * 释放一个连接块
 * @param tcp 待释放的
 */
static void tcp_free(xtcp_t* tcp)
{
	tcp->state = XTCP_STATE_FREE;
}

/**
 * 根据远端的端口、ip找一个对应的tcp连接进行处理。
 * 优先找端口、IP全匹配的，其次找处于监听状态的
 * @param remote_ip
 * @param remote_port
 * @param local_port
 * @return
 */
static xtcp_t* tcp_find(xipaddr_t* remote_ip, uint16_t remote_port, uint16_t local_port)
{
	xtcp_t* tcp;
	xtcp_t* end;
	xtcp_t* founded_tcp = (xtcp_t*)0;

	for (tcp = &tcp_socket[0], end = &tcp_socket[XNET_CFG_MAX_TCP]; tcp < end; tcp++)
	{
		if (tcp->state == XTCP_STATE_FREE)
			continue;

		if (tcp->local_port != local_port)
			continue;

		if (xipaddr_is_equal(remote_ip, &tcp->remote_ip) && (remote_port == tcp->remote_port))
			return tcp;

		if (tcp->state == XTCP_STATE_LISTEN)
			founded_tcp = tcp;
	}

	return founded_tcp;
}

/**
 * 分配一个tcp连接块
 * @return 分配结果，0-分配失败
 */
static void tcp_buf_init(xtcp_buf_t* tcp_buf)
{
	tcp_buf->front = 0;
	tcp_buf->tail = 0;
	tcp_buf->data_count = 0;
	tcp_buf->unacked_count = 0;

}

/**
 * 获取buf中空闲的字节量
 * @param tcp_buf 待查询的结构
 * @return 空闲的字节量
 */
static uint16_t tcp_buf_free_count(xtcp_buf_t* tcp_buf)
{
	return XTCP_CFG_RTX_BUF_SIZE - tcp_buf->data_count;
}

static uint16_t tcp_buf_wait_send_count(xtcp_buf_t* tcp_buf)
{
	return tcp_buf->data_count - tcp_buf->unacked_count;
}

/**
 * 从buf中读取数据用于发送
 * @param tcp_buf 读取的buf
 * @param to 读取的目的地
 * @param size 读取的字节量
 * @return 实际读取的字节量
 */
static uint16_t tcp_buf_read_for_send(xtcp_buf_t* tcp_buf, uint8_t* to, uint16_t size)
{
	int i;

	uint16_t wait_send_count = tcp_buf->data_count - tcp_buf->unacked_count;
	size = min(size, wait_send_count);

	for (i = 0; i < size; i++)
	{
		*to++ = tcp_buf->data[tcp_buf->next++];
		if (tcp_buf->next >= XTCP_CFG_RTX_BUF_SIZE)
			tcp_buf->next = 0;
	}

	return size;

}

/**
 * 从buf中读取数据，仅接接收使用
 * @param tcp_buf 读取的buf
 * @param to 读取的目的地
 * @param size 读取的字节量
 * @return 实际读取的大小
 */
static uint16_t tcp_buf_read(xtcp_buf_t* tcp_buf, uint8_t* to, uint16_t size)
{
	int i;

	size = min(size, tcp_buf->data_count);
	for (i = 0; i < size; i++)
	{
		*to++ = tcp_buf->data[tcp_buf->tail++];
		if (tcp_buf->tail >= XTCP_CFG_RTX_BUF_SIZE)
			tcp_buf->tail = 0;
	}

	tcp_buf->data_count -= size;

	return size;
}

/**
 * 向buf中写入新的需要发送的数据。仅供发送使用
 * @param tcp_buf 写入buf
 * @param from 数据源
 * @param size 数据字节量
 * @return 实际写入的量，由于缓存空间有限，实际写入的可能比期望的要小一些
 */
static uint16_t tcp_buf_write(xtcp_buf_t* tcp_buf, uint8_t* from, uint16_t size)
{
	int i;
	size = min(size, tcp_buf_free_count(tcp_buf));

	for (i = 0; i < size; i++)
	{
		tcp_buf->data[tcp_buf->front++] = *from++;
		if (tcp_buf->front >= XTCP_CFG_RTX_BUF_SIZE)
			tcp_buf->front = 0;
	}

	tcp_buf->data_count += size;
	return size;
}

/**
 * 增加buf中确认的数据量
 * @param tcp_buf buf缓存
 * @param size 新增确认的数据量
 */
static void tcp_buf_add_acked_count(xtcp_buf_t* tcp_buf, uint16_t size)
{
	tcp_buf->tail += size;
	if (tcp_buf->tail >= XTCP_CFG_RTX_BUF_SIZE)
		tcp_buf->tail = 0;

	tcp_buf->data_count -= size;
	tcp_buf->unacked_count -= size;
}

/**
 * 增加buf中未确认的数据量
 * @param tcp_buf buf缓存
 * @param size 新增未确认的数据量
 */
static void tcp_buf_add_unacked_count(xtcp_buf_t* tcp_buf, uint16_t size)
{
	tcp_buf->unacked_count += size;
}

/**
 * 从收到的tcp数据包中，读取数据到tcp接收缓存
 * @param tcp 待读取的tcp连接
 * @param flags 包头标志
 * @param from 从包头的哪里读取
 * @param size 读取的字节量
 * @return 实际读取的字节量
 */
static uint16_t tcp_recv(xtcp_t* tcp, uint8_t flags, uint8_t* from, uint16_t size)
{
	uint16_t read_size = tcp_buf_write(&tcp->rx_buf, from, size);
	tcp->ack += read_size;
	/*if (flags & (XTCP_FLAG_FIN | XTCP_FLAG_SYN))
		tcp->ack++;*/

	return read_size;
}

/**
 * TCP初始化
 */
void xtcp_init(void)
{
	memset(tcp_socket, 0, sizeof(tcp_socket));
}

/**
 * 发送TCP复位包
 */
static xnet_err_t tcp_send_reset(uint32_t remote_ack, uint16_t local_port, xipaddr_t* remote_ip, 
	uint16_t remote_port)
{
	xnet_packet_t* packet = xnet_alloc_for_send(sizeof(xtcp_hdr_t));
	xtcp_hdr_t* tcp_hdr = (xtcp_hdr_t*)packet->data;

	tcp_hdr->src_port = swap_order16(local_port);
	tcp_hdr->dest_port = swap_order16(remote_port);
	tcp_hdr->seq = 0;
	tcp_hdr->ack = swap_order32(remote_ack);

	tcp_hdr->hdr_flags.all = 0;
	tcp_hdr->hdr_flags.hdr_len = sizeof(xtcp_hdr_t) / 4;
	tcp_hdr->hdr_flags.flags = XTCP_FLAG_RST | XTCP_FLAG_ACK;
	tcp_hdr->hdr_flags.all = swap_order16(tcp_hdr->hdr_flags.all);

	tcp_hdr->window = 0;
	tcp_hdr->checksum = 0;
	tcp_hdr->urgent_ptr = 0;
	tcp_hdr->checksum = checksum_peso(&netif_ipaddr, remote_ip, XNET_PROTOCAL_TCP,
		(uint16_t*)tcp_hdr, packet->size);
	tcp_hdr->checksum = (tcp_hdr->checksum == 0) ? 0xffff : tcp_hdr->checksum;

	return xip_out(XNET_PROTOCAL_TCP, remote_ip, packet);
}

/**
 * 将发送缓冲区中的数据发送出去。尽最大努力发送最多
 * @param tcp 处理的tcp连接
 * @param flags 发送的标志位
 * @return 发送结果
 */
static xnet_err_t tcp_send(xtcp_t* tcp, uint8_t flags)
{
	xnet_packet_t* packet;
	xtcp_hdr_t* tcp_hdr;
	xnet_err_t err;
	uint16_t opt_size = (flags & XTCP_FLAG_SYN) ? 4 : 0;
	uint16_t data_size = tcp_buf_wait_send_count(&tcp->tx_buf);

	if (tcp->remote_win)
	{
		data_size = min(data_size, tcp->remote_win);
		data_size = min(data_size, tcp->remote_mss);
		if ((data_size + opt_size) > XTCP_DATA_MAX_SIZE)
			data_size = XTCP_DATA_MAX_SIZE - opt_size;
	}
	else
		data_size = 0;

	packet = xnet_alloc_for_send(sizeof(xtcp_hdr_t) + opt_size + data_size);
	tcp_hdr = (xtcp_hdr_t*)packet->data;

	tcp_hdr->src_port = swap_order16(tcp->local_port);
	tcp_hdr->dest_port = swap_order16(tcp->remote_port);
	tcp_hdr->seq = swap_order32(tcp->next_seq);
	tcp_hdr->ack = swap_order32(tcp->ack);

	tcp_hdr->hdr_flags.all = 0;
	tcp_hdr->hdr_flags.hdr_len = (sizeof(xtcp_hdr_t) + opt_size) / 4;
	tcp_hdr->hdr_flags.flags = flags;
	tcp_hdr->hdr_flags.all = swap_order16(tcp_hdr->hdr_flags.all);

	tcp_hdr->window = swap_order16(tcp_buf_free_count(&tcp->rx_buf));
	tcp_hdr->checksum = 0;
	tcp_hdr->urgent_ptr = 0;

	if (flags & XTCP_FLAG_SYN) 
	{
		uint8_t* opt_data = packet->data + sizeof(xtcp_hdr_t);
		opt_data[0] = XTCP_KIND_MSS;
		opt_data[1] = 4;
		*(uint16_t*)(opt_data + 2) = swap_order16(XTCP_MSS_DEFAULT);

	}

	tcp_buf_read_for_send(&tcp->tx_buf, packet->data + sizeof(xtcp_hdr_t) + opt_size, data_size);

	tcp_hdr->checksum = checksum_peso(&netif_ipaddr, &(tcp->remote_ip), XNET_PROTOCAL_TCP,
		(uint16_t*)tcp_hdr, packet->size);
	tcp_hdr->checksum = (tcp_hdr->checksum == 0) ? 0xffff : tcp_hdr->checksum;

	err = xip_out(XNET_PROTOCAL_TCP, &(tcp->remote_ip), packet);
	if (err < 0)
		return err;

	tcp->remote_win -= data_size;
	tcp->next_seq += data_size;
	tcp_buf_add_unacked_count(&tcp->tx_buf, data_size);


	if (flags & (XTCP_FLAG_SYN | XTCP_FLAG_FIN))
		tcp->next_seq++;

	return XNET_ERR_OK;
}

/**
 * 从tcp包头中读取选项字节。简单起见，仅读取mss字段
 * @param tcp 待读取的tcp连接
 * @param tcp_hdr tcp包头
 */
static void tcp_read_mss(xtcp_t* tcp, xtcp_hdr_t* tcp_hdr)
{
	uint16_t opt_len = tcp_hdr->hdr_flags.hdr_len - sizeof(xtcp_hdr_t);

	if (opt_len == 0)
		tcp->remote_mss = XTCP_MSS_DEFAULT;
	else
	{
		uint8_t* opt_data = (uint8_t*)tcp_hdr + sizeof(xtcp_hdr_t);
		uint8_t* opt_end = opt_data + opt_len;

		while ((*opt_data != XTCP_KIND_END) && (opt_data < opt_end))
		{
			if ((*opt_data++ == XTCP_KIND_MSS) && (*opt_data++ == 4))
			{
				tcp->remote_mss = swap_order16(*(uint16_t*)opt_data);
				return;
			}
		}
	}
}

/**
 * 处理tcp连接请求
 */
static void tcp_process_accept(xtcp_t* listen_tcp, xipaddr_t* remote_ip, xtcp_hdr_t* tcp_hdr)
{
	uint16_t hdr_flags = tcp_hdr->hdr_flags.all;

	if (hdr_flags & XTCP_FLAG_SYN)
	{
		xnet_err_t err;
		uint32_t ack = tcp_hdr->seq + 1;

		xtcp_t* new_tcp = tcp_alloc();
		if (!new_tcp)
			return;

		new_tcp->state = XTCP_STATE_SYN_RECVD;
		new_tcp->local_port = listen_tcp->local_port;
		new_tcp->handler = listen_tcp->handler;
		new_tcp->remote_port = tcp_hdr->src_port;
		new_tcp->remote_ip.addr = remote_ip->addr;
		new_tcp->ack = ack;
		new_tcp->next_seq = tcp_get_init_seq();
		new_tcp->unacked_seq = new_tcp->next_seq;
		new_tcp->remote_win = listen_tcp->remote_win;

		tcp_read_mss(new_tcp, tcp_hdr);

		err = tcp_send(new_tcp, XTCP_FLAG_SYN | XTCP_FLAG_ACK);
		if (err < 0)
		{
			tcp_free(new_tcp);
			return;
		}

	}
	else
		tcp_send_reset(tcp_hdr->seq, listen_tcp->local_port, remote_ip, tcp_hdr->src_port);
}

/**
 * TCP包的输入处理
 */
void xtcp_in(xipaddr_t* remote_ip, xnet_packet_t* packet)
{
	xtcp_hdr_t* tcp_hdr = (xtcp_hdr_t*)packet->data;
	uint16_t pre_checksum;
	xtcp_t* tcp;
	uint16_t read_size;

	if (packet->size < sizeof(xtcp_hdr_t))
		return;

	pre_checksum = tcp_hdr->checksum;
	tcp_hdr->checksum = 0;
	if (pre_checksum != 0)
	{
		uint16_t checksum = checksum_peso(remote_ip, &netif_ipaddr, XNET_PROTOCAL_TCP,
			(uint16_t*)tcp_hdr, packet->size);
		checksum = (checksum == 0) ? 0xffff : checksum;

		if (checksum != pre_checksum)
			return;
	}

	tcp_hdr->src_port = swap_order16(tcp_hdr->src_port);
	tcp_hdr->dest_port = swap_order16(tcp_hdr->dest_port);
	tcp_hdr->hdr_flags.all = swap_order16(tcp_hdr->hdr_flags.all);
	tcp_hdr->seq = swap_order32(tcp_hdr->seq);
	tcp_hdr->ack = swap_order32(tcp_hdr->ack);
	tcp_hdr->window = swap_order16(tcp_hdr->window);

	tcp = tcp_find(remote_ip, tcp_hdr->src_port, tcp_hdr->dest_port);
	if (tcp == (xtcp_t*)0)
	{
		tcp_send_reset(tcp_hdr->seq + 1, tcp_hdr->dest_port, remote_ip, tcp_hdr->src_port);
		return;
	}

	tcp->remote_win = tcp_hdr->window;

	if (tcp->state == XTCP_STATE_LISTEN)
	{
		tcp_process_accept(tcp, remote_ip, tcp_hdr);
		return;
	}

	if (tcp_hdr->seq != tcp->ack)
	{
		tcp_send_reset(tcp_hdr->seq + 1, tcp_hdr->dest_port, remote_ip, tcp_hdr->src_port);
		return;
	}
	
	

	remove_header(packet, tcp_hdr->hdr_flags.hdr_len * 4);
	switch (tcp->state)
	{
	case XTCP_STATE_SYN_RECVD:
		if (tcp_hdr->hdr_flags.flags & XTCP_FLAG_ACK)
		{
			tcp->unacked_seq++;
			tcp->state = XTCP_STATE_ESTABLISHED;
			tcp->handler(tcp, XTCP_CONN_CONNECTED);
		}
		break;
	case XTCP_STATE_ESTABLISHED:
		{
			if (tcp_hdr->hdr_flags.flags & (XTCP_FLAG_ACK | XTCP_FLAG_FIN)) {
				if (tcp_hdr->hdr_flags.flags & XTCP_FLAG_ACK)
				{
					if ((tcp->unacked_seq < tcp_hdr->ack) && (tcp_hdr->ack <= tcp->next_seq))
					{
						uint16_t curr_ack_size = tcp_hdr->ack - tcp->unacked_seq;
						tcp_buf_add_acked_count(&tcp->tx_buf, curr_ack_size);
						tcp->unacked_seq += curr_ack_size;
					}
				}

				read_size = tcp_recv(tcp, (uint8_t)tcp_hdr->hdr_flags.flags, packet->data, packet->size);

				if (tcp_hdr->hdr_flags.flags & XTCP_FLAG_FIN)
				{
					tcp->state = XTCP_STATE_LAST_ACK;
					tcp->ack++;
					tcp_send(tcp, XTCP_FLAG_FIN | XTCP_FLAG_ACK);
				}
				else if (read_size)
				{
					tcp_send(tcp, XTCP_FLAG_ACK);
					tcp->handler(tcp, XTCP_CONN_DATA_RECV);
				}
				else if (tcp_buf_wait_send_count(&tcp->tx_buf))
					tcp_send(tcp, XTCP_FLAG_ACK);
			}
		
		}
		break;
	case XTCP_STATE_FIN_WAIT_1:
		if ((tcp_hdr->hdr_flags.flags & (XTCP_FLAG_FIN | XTCP_FLAG_ACK)) == (XTCP_FLAG_FIN | XTCP_FLAG_ACK))
		{
			tcp_free(tcp);
		}
		else if (tcp_hdr->hdr_flags.flags & XTCP_FLAG_ACK)
		{
			tcp->state = XTCP_STATE_FIN_WAIT_2;
		}
		break;
	case XTCP_STATE_FIN_WAIT_2:
		if (tcp_hdr->hdr_flags.flags & XTCP_FLAG_FIN)
		{
			tcp->ack++;
			tcp_send(tcp, XTCP_FLAG_ACK);
			tcp_free(tcp);
		}
		break;
	case XTCP_STATE_LAST_ACK:
		if (tcp_hdr->hdr_flags.flags & XTCP_FLAG_ACK)
		{
			tcp->handler(tcp, XTCP_CONN_CLOSED);
			tcp_free(tcp);
		}
		break;
	default:
		break;
	}


}

/**
 * 向tcp发送数据
 */
int xtcp_write(xtcp_t* tcp, uint8_t* data, uint16_t size)
{
	int sent_count;

	if (tcp->state != XTCP_STATE_ESTABLISHED)
		return -1;

	sent_count = tcp_buf_write(&tcp->tx_buf, data, size);
	if (sent_count)
		tcp_send(tcp, XTCP_FLAG_ACK);
	return sent_count;
}

/**
 * 从tcp中读取数据
 */
int xtcp_read(xtcp_t* tcp, uint8_t* data, uint16_t size)
{
	return tcp_buf_read(&tcp->rx_buf, data, size);
}

/**
 * 打开TCP
 */
xtcp_t* xtcp_open(xtcp_handler_t handler)
{
	xtcp_t* tcp = tcp_alloc();
	if (!tcp)
		return tcp;

	tcp->state = XTCP_STATE_CLOSED;
	tcp->handler = handler;
	return tcp;
}

/**
 * 建立tcp与指定本地端口的关联，使得其能够处理来自该端口的包
 * 以及通过该端口发送数据包
 */
xnet_err_t xtcp_bind(xtcp_t* tcp, uint16_t local_port)
{
	xtcp_t* curr;
	xtcp_t* end;
	for (curr = &tcp_socket[0], end = &tcp_socket[XNET_CFG_MAX_TCP]; curr < end; curr++)
	{
		if ((curr != tcp) && (curr->local_port == local_port))
			return XNET_ERR_BINDED;

	}

	tcp->local_port = local_port;
	return XNET_ERR_OK;
}

/**
 * 控制tcp进入监听状态
 */
xnet_err_t xtcp_listen(xtcp_t* tcp)
{
	tcp->state = XTCP_STATE_LISTEN;
	return XNET_ERR_OK;
}

/**
 * 关掉tcp连接
 */
xnet_err_t xtcp_close(xtcp_t* tcp)
{
	xnet_err_t err;
	if (tcp->state == XTCP_STATE_ESTABLISHED) 
	{
		err = tcp_send(tcp, XTCP_FLAG_FIN | XTCP_FLAG_ACK);
		if (err < 0)
			return err;

		tcp->state = XTCP_STATE_FIN_WAIT_1;
	}
	else
		tcp_free(tcp);

	return XNET_ERR_OK;
}

/**
 * 协议栈的初始化
 */
void xnet_init(void)
{
	ethernet_init();
	xarp_init();
	xip_init();
	xicmp_init();
	xudp_init();
	xtcp_init();
	srand(xsys_get_time());
}

/**
 * 轮询处理数据包，并在协议栈中处理
 */
void xnet_poll(void)
{
	ethernet_poll();
	xarp_poll();
}
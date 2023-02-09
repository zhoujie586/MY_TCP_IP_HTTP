#include "xserver_datetime.h"
#include <time.h>
#include <string.h>

#define TIME_STR_SIZE		128

xnet_err_t datatime_handler(xudp_t* udp, xipaddr_t* src_ip, uint16_t src_port, xnet_packet_t* packet)
{
	time_t rawtime;
	const struct tm* timeinfo;
	xnet_packet_t* tx_packet;
	size_t str_size;

	tx_packet = xnet_alloc_for_send(TIME_STR_SIZE);

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	str_size = strftime((char*)tx_packet->data, TIME_STR_SIZE, "%A, %B %d, %Y %T-%z", timeinfo);
	truncate_header(tx_packet, (uint16_t)str_size);
	//发送
	
	return xudp_out(udp, src_ip, src_port, tx_packet);
}

xnet_err_t xserver_datatime_create(uint16_t port)
{
	xudp_t* udp = xudp_open(datatime_handler);

	xudp_bind(udp, port);

	return XNET_ERR_OK;
}
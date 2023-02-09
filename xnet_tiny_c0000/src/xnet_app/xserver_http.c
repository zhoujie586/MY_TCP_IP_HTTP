#include "xserver_http.h"
#include <stdio.h>

static uint8_t tx_buffer[1024];

xnet_err_t http_handler(xtcp_t* tcp, xtcp_conn_state_t event)
{
	static char* num = "0123456789ABCDEF";
	if (event == XTCP_CONN_CONNECTED)
	{
		printf("http connected\n");
		//int i;
		//for (i = 0; i < 1024; i++)
		//{
		//	tx_buffer[i] = num[i % 16];
		//}

		//xtcp_write(tcp, tx_buffer, sizeof(tx_buffer));
	}
	else if (event == XTCP_CONN_DATA_RECV)
	{
		uint8_t* data = tx_buffer;

		uint16_t read_size = xtcp_read(tcp, tx_buffer, sizeof(tx_buffer));

		while (read_size)
		{
			uint16_t curr_size = xtcp_write(tcp, data, read_size);
			data += curr_size;
			read_size -= curr_size;
		}
	}
	else if (event == XTCP_CONN_CLOSED)
		printf("http closed\n");

	return XNET_ERR_OK;
}

xnet_err_t xserver_http_create(uint16_t port)
{
	xtcp_t* tcp = xtcp_open(http_handler);

	xtcp_bind(tcp, port);
	xtcp_listen(tcp);

	return XNET_ERR_OK;
}
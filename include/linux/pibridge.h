#ifndef _PIBRIDGE_H
#define _PIBRIDGE_H

int piIoComm_send(u8 *buf, u16 len);
int piIoComm_recv(u8 *buf, u16 len);	/* using default timeout REV_PI_IO_TIMEOUT */
int piIoComm_recv_timeout(u8 *buf, u16 len, u16 timeout);
int pibridge_req_gate_tmt(u8 dst, u16 cmd, u8 *snd_buf, u16 snd_len,
		u8 *rcv_buf, u16 rcv_len, u16 tmt);
int pibridge_req_send_gate(u8 dst, u16 cmd, u8 *snd_buf, u16 snd_len);
int pibridge_req_gate(u8 dst, u16 cmd, u8 *snd_buf, u16 snd_len,
		u8 *rcv_buf, u16 rcv_len);
int pibridge_req_send_io(u8 addr, u16 cmd, u8 *snd_buf, u16 snd_len);
int pibridge_req_io(u8 addr, u8 cmd, u8 *snd_buf, u16 snd_len,
		u8 *rcv_buf, u16 rcv_len);
#endif  /*_PIBRIDGE_H*/

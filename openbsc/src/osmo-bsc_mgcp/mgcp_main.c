/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* The main method to drive it as a standalone process      */

/*
 * (C) 2009-2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2011 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>

#include <sys/socket.h>

#include "g711common.h"
#include <gsm.h>
#include <bcg729/decoder.h>
#include <bcg729/encoder.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>
#include <openbsc/vty.h>

#include <osmocom/core/application.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>

#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>

#include <osmocom/vty/command.h>

#include "../../bscconfig.h"

/* this is here for the vty... it will never be called */
void subscr_put() { abort(); }

#define _GNU_SOURCE
#include <getopt.h>

#warning "Make use of the rtp proxy code"

static struct mgcp_config *cfg;
static struct mgcp_trunk_config *reset_trunk;
static int reset_endpoints = 0;
static int daemonize = 0;

const char *openbsc_copyright =
	"Copyright (C) 2009-2010 Holger Freyther and On-Waves\r\n"
	"Contributions by Daniel Willmann, Jan Lübbe, Stefan Schmidt\r\n"
	"Dieter Spaar, Andreas Eversberg, Harald Welte\r\n\r\n"
	"License AGPLv3+: GNU AGPL version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

static char *config_file = "mgcp.cfg";

/* used by msgb and mgcp */
void *tall_bsc_ctx = NULL;

static void print_help()
{
	printf("Some useful help...\n");
	printf(" -h --help is printing this text.\n");
	printf(" -c --config-file filename The config file to use.\n");
	printf(" -s --disable-color\n");
	printf(" -D --daemonize Fork the process into a background daemon\n");
	printf(" -V --version Print the version number\n");
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"config-file", 1, 0, 'c'},
			{"daemonize", 0, 0, 'D'},
			{"version", 0, 0, 'V'},
			{"disable-color", 0, 0, 's'},
			{0, 0, 0, 0},
		};

		c = getopt_long(argc, argv, "hc:VD", long_options, &option_index);

		if (c == -1)
			break;

		switch(c) {
		case 'h':
			print_help();
			exit(0);
			break;
		case 'c':
			config_file = talloc_strdup(tall_bsc_ctx, optarg);
			break;
		case 's':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		case 'D':
			daemonize = 1;
			break;
		default:
			/* ignore */
			break;
		};
	}
}

/* simply remember this */
static int mgcp_rsip_cb(struct mgcp_trunk_config *tcfg)
{
	reset_endpoints = 1;
	reset_trunk = tcfg;

	return 0;
}

static int read_call_agent(struct osmo_fd *fd, unsigned int what)
{
	struct sockaddr_in addr;
	socklen_t slen = sizeof(addr);
	struct msgb *msg;
	struct msgb *resp;
	int i;

	msg = (struct msgb *) fd->data;

	/* read one less so we can use it as a \0 */
	int rc = recvfrom(cfg->gw_fd.bfd.fd, msg->data, msg->data_len - 1, 0,
		(struct sockaddr *) &addr, &slen);
	if (rc < 0) {
		perror("Gateway failed to read");
		return -1;
	} else if (slen > sizeof(addr)) {
		fprintf(stderr, "Gateway received message from outerspace: %zu %zu\n",
			slen, sizeof(addr));
		return -1;
	}

	/* handle message now */
	msg->l2h = msgb_put(msg, rc);
	resp = mgcp_handle_message(cfg, msg);
	msgb_reset(msg);

	if (resp) {
		sendto(cfg->gw_fd.bfd.fd, resp->l2h, msgb_l2len(resp), 0, (struct sockaddr *) &addr, sizeof(addr));
		msgb_free(resp);
	}

	if (reset_endpoints) {
		LOGP(DMGCP, LOGL_NOTICE,
		     "Asked to reset endpoints: %d/%d\n",
		     reset_trunk->trunk_nr, reset_trunk->trunk_type);
		reset_endpoints = 0;

		/* is checking in_addr.s_addr == INADDR_LOOPBACK making it more secure? */
		for (i = 1; i < reset_trunk->number_endpoints; ++i)
			mgcp_free_endp(&reset_trunk->endpoints[i]);
	}

	return 0;
}

extern enum node_type bsc_vty_go_parent(struct vty *vty);

static struct vty_app_info vty_info = {
	.name 		= "OpenBSC MGCP",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= bsc_vty_go_parent,
	.is_config_node	= bsc_vty_is_config_node,
};

int main(int argc, char **argv)
{
	struct gsm_network dummy_network;
	struct sockaddr_in addr;
	int on = 1, rc;

	tall_bsc_ctx = talloc_named_const(NULL, 1, "mgcp-callagent");

	osmo_init_ignore_signals();
	osmo_init_logging(&log_info);

	cfg = mgcp_config_alloc();
	if (!cfg)
		return -1;

	vty_info.copyright = openbsc_copyright;
	vty_init(&vty_info);
	logging_vty_add_cmds(&log_info);
	mgcp_vty_init();

	handle_options(argc, argv);

	rc = mgcp_parse_config(config_file, cfg, MGCP_BSC);
	if (rc < 0)
		return rc;

	rc = telnet_init(tall_bsc_ctx, &dummy_network, 4243);
	if (rc < 0)
		return rc;

	/* set some callbacks */
	cfg->reset_cb = mgcp_rsip_cb;

        /* we need to bind a socket */
        if (rc == 0) {
		cfg->gw_fd.bfd.when = BSC_FD_READ;
		cfg->gw_fd.bfd.cb = read_call_agent;
		cfg->gw_fd.bfd.fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (cfg->gw_fd.bfd.fd < 0) {
			perror("Gateway failed to listen");
			return -1;
		}

		setsockopt(cfg->gw_fd.bfd.fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(cfg->source_port);
		inet_aton(cfg->source_addr, &addr.sin_addr);

		if (bind(cfg->gw_fd.bfd.fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
			perror("Gateway failed to bind");
			return -1;
		}

		cfg->gw_fd.bfd.data = msgb_alloc(4096, "mgcp-msg");
		if (!cfg->gw_fd.bfd.data) {
			fprintf(stderr, "Gateway memory error.\n");
			return -1;
		}

		if (cfg->call_agent_addr) {
			addr.sin_port = htons(2727);
			inet_aton(cfg->call_agent_addr, &addr.sin_addr);
			if (connect(cfg->gw_fd.bfd.fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
				LOGP(DMGCP, LOGL_ERROR, "Failed to connect to: '%s'. errno: %d\n",
				     cfg->call_agent_addr, errno);
				close(cfg->gw_fd.bfd.fd);
				cfg->gw_fd.bfd.fd = -1;
				return -1;
			}
		}

		if (osmo_fd_register(&cfg->gw_fd.bfd) != 0) {
			LOGP(DMGCP, LOGL_FATAL, "Failed to register the fd\n");
			return -1;
		}

		LOGP(DMGCP, LOGL_NOTICE, "Configured for MGCP.\n");
	}

	/* initialisation */
	srand(time(NULL));

	if (daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			exit(1);
		}
	}

	/* main loop */
	while (1) {
		osmo_select_main(0);
	}


	return 0;
}

enum audio_format {
	AF_INVALID, /* must be 0 */
	AF_S16,
	AF_L16,
	AF_GSM,
	AF_G729,
	AF_PCMA
};

struct mgcp_process_rtp_state {
	/* decoding */
	enum audio_format src_fmt;
	union {
		gsm gsm_handle;
		bcg729DecoderChannelContextStruct *g729_dec;
	} src;
	size_t src_frame_size;
	size_t src_samples_per_frame;

	/* processing */

	/* encoding */
	enum audio_format dst_fmt;
	union {
		gsm gsm_handle;
		bcg729EncoderChannelContextStruct *g729_enc;
	} dst;
	size_t dst_frame_size;
	size_t dst_samples_per_frame;
};

static enum audio_format get_audio_format(const struct mgcp_rtp_end *rtp_end)
{
	if (rtp_end->subtype_name) {
		if (!strcmp("GSM", rtp_end->subtype_name))
			return AF_GSM;
		if (!strcmp("PCMA", rtp_end->subtype_name))
			return AF_PCMA;
		if (!strcmp("G729", rtp_end->subtype_name))
			return AF_G729;
		if (!strcmp("L16", rtp_end->subtype_name))
			return AF_L16;
	}

	switch (rtp_end->payload_type) {
	case 3 /* GSM */:
		return AF_GSM;
	case 8 /* PCMA */:
		return AF_PCMA;
	case 18 /* G.729 */:
		return AF_G729;
	case 11 /* L16 */:
		return AF_L16;
	default:
		return AF_INVALID;
	}
}

static void l16_encode(short *sample, unsigned char *buf, size_t n)
{
	for (; n > 0; --n, ++sample, buf += 2) {
		buf[0] = sample[0] >> 8;
		buf[1] = sample[0] & 0xff;
	}
}

static void l16_decode(unsigned char *buf, short *sample, size_t n)
{
	for (; n > 0; --n, ++sample, buf += 2)
		sample[0] = ((short)buf[0] << 8) | buf[1];
}

static void alaw_encode(short *sample, unsigned char *buf, size_t n)
{
	for (; n > 0; --n)
		*(buf++) = s16_to_alaw(*(sample++));
}

static void alaw_decode(unsigned char *buf, short *sample, size_t n)
{
	for (; n > 0; --n)
		*(sample++) = alaw_to_s16(*(buf++));
}

static int processing_state_destructor(struct mgcp_process_rtp_state *state)
{
	switch (state->src_fmt) {
	case AF_GSM:
		if (state->dst.gsm_handle)
			gsm_destroy(state->src.gsm_handle);
		break;
	case AF_G729:
		if (state->src.g729_dec)
			closeBcg729DecoderChannel(state->src.g729_dec);
		break;
	default:
		break;
	}
	switch (state->dst_fmt) {
	case AF_GSM:
		if (state->dst.gsm_handle)
			gsm_destroy(state->dst.gsm_handle);
		break;
	case AF_G729:
		if (state->dst.g729_enc)
			closeBcg729EncoderChannel(state->dst.g729_enc);
		break;
	default:
		break;
	}
	return 0;
}

int mgcp_setup_processing(struct mgcp_endpoint *endp,
			  struct mgcp_rtp_end *dst_end,
			  struct mgcp_rtp_end *src_end)
{
	struct mgcp_process_rtp_state *state = dst_end->rtp_process_data;
	enum audio_format src_fmt, dst_fmt;

	/* cleanup first */
	if (state) {
		talloc_free(state);
		dst_end->rtp_process_data = NULL;
	}

	if (!src_end)
		return 0;

	src_fmt = get_audio_format(src_end);
	dst_fmt = get_audio_format(dst_end);

	if (!src_fmt || !dst_fmt) {
		if (src_end->payload_type == dst_end->payload_type)
			/* Nothing to do */
			return 0;

		LOGP(DMGCP, LOGL_ERROR, "Cannot transcode: %s codec not supported.\n",
		     src_fmt ? "destination" : "source");
		return -EINVAL;
	}

	if (src_end->rate && dst_end->rate && src_end->rate != dst_end->rate) {
		LOGP(DMGCP, LOGL_ERROR,
		     "Cannot transcode: rate conversion (%d -> %d) not supported.\n",
		     src_end->rate, dst_end->rate);
		return -EINVAL;
	}

	state = talloc_zero(NULL, struct mgcp_process_rtp_state);
	talloc_set_destructor(state, processing_state_destructor);
	dst_end->rtp_process_data = state;

	state->src_fmt = src_fmt;

	switch (state->src_fmt) {
	case AF_L16:
	case AF_S16:
		state->src_frame_size = 80 * sizeof(short);
		state->src_samples_per_frame = 80;
		break;
	case AF_GSM:
		state->src_frame_size = sizeof(gsm_frame);
		state->src_samples_per_frame = 160;
		state->src.gsm_handle = gsm_create();
		if (!state->src.gsm_handle) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Failed to initialize GSM decoder.\n");
			return -EINVAL;
		}
		break;
	case AF_G729:
		state->src_frame_size = 10;
		state->src_samples_per_frame = 80;
		state->src.g729_dec = initBcg729DecoderChannel();
		if (!state->src.g729_dec) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Failed to initialize G.729 decoder.\n");
			return -EINVAL;
		}
		break;
	case AF_PCMA:
		state->src_frame_size = 80;
		state->src_samples_per_frame = 80;
		break;
	default:
		break;
	}

	state->dst_fmt = dst_fmt;

	switch (state->dst_fmt) {
	case AF_L16:
	case AF_S16:
		state->dst_frame_size = 80*sizeof(short);
		state->dst_samples_per_frame = 80;
		break;
	case AF_GSM:
		state->dst_frame_size = sizeof(gsm_frame);
		state->dst_samples_per_frame = 160;
		state->dst.gsm_handle = gsm_create();
		if (!state->dst.gsm_handle) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Failed to initialize GSM encoder.\n");
			return -EINVAL;
		}
		break;
	case AF_G729:
		state->dst_frame_size = 10;
		state->dst_samples_per_frame = 80;
		state->dst.g729_enc = initBcg729EncoderChannel();
		if (!state->dst.g729_enc) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Failed to initialize G.729 decoder.\n");
			return -EINVAL;
		}
		break;
	case AF_PCMA:
		state->dst_frame_size = 80;
		state->dst_samples_per_frame = 80;
		break;
	default:
		break;
	}

	LOGP(DMGCP, LOGL_INFO,
	     "Initialized RTP processing on: 0x%x "
	     "conv: %d (%d, %d, %s) -> %d (%d, %d, %s)\n",
	     ENDPOINT_NUMBER(endp),
	     src_fmt, src_end->payload_type, src_end->rate, src_end->fmtp_extra,
	     dst_fmt, dst_end->payload_type, dst_end->rate, dst_end->fmtp_extra);

	return 0;
}

void mgcp_net_downlink_format(struct mgcp_endpoint *endp,
			      int *payload_type,
			      const char**audio_name,
			      const char**fmtp_extra)
{
	struct mgcp_process_rtp_state *state = endp->net_end.rtp_process_data;
	if (!state || endp->net_end.payload_type < 0) {
		*payload_type = endp->bts_end.payload_type;
		*audio_name = endp->bts_end.audio_name;
		*fmtp_extra = endp->bts_end.fmtp_extra;
		return;
	}

	*payload_type = endp->net_end.payload_type;
	*fmtp_extra = endp->net_end.fmtp_extra;
	*audio_name = endp->net_end.audio_name;
}


int mgcp_process_rtp_payload(struct mgcp_rtp_end *dst_end,
			     char *data, int *len, int buf_size)
{
	struct mgcp_process_rtp_state *state = dst_end->rtp_process_data;
	size_t rtp_hdr_size = 12;
	char *payload_data = data + rtp_hdr_size;
	int payload_len = *len - rtp_hdr_size;
	size_t sample_cnt = 0;
	size_t sample_idx;
	int16_t samples[10*160];
	uint8_t *src = (uint8_t *)payload_data;
	uint8_t *dst = (uint8_t *)payload_data;
	size_t nbytes = payload_len;
	size_t frame_remainder;

	if (!state)
		return 0;

	if (state->src_fmt == state->dst_fmt)
		return 0;

	/* TODO: check payload type (-> G.711 comfort noise) */

	/* Decode src into samples */
	while (nbytes >= state->src_frame_size) {
		if (sample_cnt + state->src_samples_per_frame > ARRAY_SIZE(samples)) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Sample buffer too small: %d > %d.\n",
			     sample_cnt + state->src_samples_per_frame,
			     ARRAY_SIZE(samples));
			return -ENOSPC;
		}
		switch (state->src_fmt) {
		case AF_GSM:
			if (gsm_decode(state->src.gsm_handle,
				       (gsm_byte *)src, samples + sample_cnt) < 0) {
				LOGP(DMGCP, LOGL_ERROR,
				     "Failed to decode GSM.\n");
				return -EINVAL;
			}
			break;
		case AF_G729:
			bcg729Decoder(state->src.g729_dec, src, 0, samples + sample_cnt);
			break;
		case AF_PCMA:
			alaw_decode(src, samples + sample_cnt,
				    state->src_samples_per_frame);
			break;
		case AF_S16:
			memmove(samples + sample_cnt, src,
				state->src_frame_size);
			break;
		case AF_L16:
			l16_decode(src, samples + sample_cnt,
				   state->src_samples_per_frame);
			break;
		default:
			break;
		}
		src        += state->src_frame_size;
		nbytes     -= state->src_frame_size;
		sample_cnt += state->src_samples_per_frame;
	}

	/* Add silence if necessary */
	frame_remainder = sample_cnt % state->dst_samples_per_frame;
	if (frame_remainder) {
		size_t silence = state->dst_samples_per_frame - frame_remainder;
		if (sample_cnt + silence > ARRAY_SIZE(samples)) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Sample buffer too small for silence: %d > %d.\n",
			     sample_cnt + silence,
			     ARRAY_SIZE(samples));
			return -ENOSPC;
		}

		while (silence > 0) {
			samples[sample_cnt] = 0;
			sample_cnt += 1;
			silence -= 1;
		}
	}

	/* Encode samples into dst */
	sample_idx = 0;
	nbytes = 0;
	while (sample_idx + state->dst_samples_per_frame <= sample_cnt) {
		if (nbytes + state->dst_frame_size > buf_size) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Encoding (RTP) buffer too small: %d > %d.\n",
			     nbytes + state->dst_frame_size, buf_size);
			return -ENOSPC;
		}
		switch (state->dst_fmt) {
		case AF_GSM:
			gsm_encode(state->dst.gsm_handle,
				   samples + sample_idx, dst);
			break;
		case AF_G729:
			bcg729Encoder(state->dst.g729_enc,
				      samples + sample_idx, dst);
			break;
		case AF_PCMA:
			alaw_encode(samples + sample_idx, dst,
				    state->src_samples_per_frame);
			break;
		case AF_S16:
			memmove(dst, samples + sample_idx, state->dst_frame_size);
			break;
		case AF_L16:
			l16_encode(samples + sample_idx, dst,
				   state->src_samples_per_frame);
			break;
		default:
			break;
		}
		dst        += state->dst_frame_size;
		nbytes     += state->dst_frame_size;
		sample_idx += state->dst_samples_per_frame;
	}

	*len = rtp_hdr_size + nbytes;
	/* Patch payload type */
	data[1] = (data[1] & 0x80) | (dst_end->payload_type & 0x7f);

	/* TODO: remove me
	fprintf(stderr, "sample_cnt = %d, sample_idx = %d, plen = %d -> %d, "
		"hdr_size = %d, len = %d, pt = %d\n",
	       sample_cnt, sample_idx, payload_len, nbytes, rtp_hdr_size, *len,
	       data[1]);
	       */

	return 0;
}


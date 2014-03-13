#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <err.h>

#include "g711common.h"
#include "gsm.h"
#include "bcg729/decoder.h"
#include "bcg729/encoder.h"

#include <osmocom/core/talloc.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>

enum audio_format {
	AF_INVALID, /* must be 0 */
	AF_S16,
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

enum audio_format parse_audio_format(const char *fmt)
{
	if (!strcasecmp(fmt, "gsm"))
		return AF_GSM;
	else if (!strcasecmp(fmt, "g729"))
		return AF_G729;
	else if (!strcasecmp(fmt, "pcma"))
		return AF_PCMA;
	else if (!strcasecmp(fmt, "s16"))
		return AF_S16;
	return AF_INVALID;
}

int audio_name_to_type(const char *name)
{
	if (!strcasecmp(name, "gsm"))
		return 3;
	else if (!strcasecmp(name, "g729"))
		return 18;
	else if (!strcasecmp(name, "pcma"))
		return 8;
	else if (!strcasecmp(name, "s16"))
		return 257;
	return -1;
}

enum audio_format get_audio_format(const struct mgcp_rtp_end *rtp_end)
{
	switch (rtp_end->payload_type) {
	case 3 /* GSM */:
		return AF_GSM;
	case 8 /* PCMA */:
		return AF_PCMA;
	case 18 /* G.729 */:
		return AF_G729;
	case 257 /* Fake S16 */:
		return AF_S16;
	default:
		return AF_INVALID;
	}
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
	if (state)
		talloc_free(state);

	src_fmt = get_audio_format(src_end);
	dst_fmt = get_audio_format(dst_end);

	if (!src_fmt || !dst_fmt) {
		LOGP(DMGCP, LOGL_ERROR, "Cannot transcode: %s codec not supported.\n",
		     src_fmt ? "destination" : "source");
		return -EINVAL;
	}

	state = talloc_zero(dst_end, struct mgcp_process_rtp_state);
	talloc_set_destructor(state, processing_state_destructor);
	dst_end->rtp_process_data = state;

	state->src_fmt = src_fmt;

	switch (state->src_fmt) {
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

	return 0;
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

	// TODO: payload type checken (comfort noise)

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

	fprintf(stderr, "sample_cnt = %d, sample_idx = %d, plen = %d -> %d, "
		"hdr_size = %d, len = %d, pt = %d\n",
	       sample_cnt, sample_idx, payload_len, nbytes, rtp_hdr_size, *len,
	       data[1]);

	return 0;
}

int main(int argc, char **argv)
{
	char buf[4096] = {0};
	int cc, rc;
	struct mgcp_rtp_end *dst_end, *src_end;
	struct mgcp_process_rtp_state *state;
	int in_size;

	dst_end = talloc_zero(NULL, struct mgcp_rtp_end);
	src_end = talloc_zero(NULL, struct mgcp_rtp_end);

	if (argc <= 2)
		errx(1, "Usage: {gsm|g729|pcma} {gsm|g729|pcma}");

	if ((src_end->payload_type = audio_name_to_type(argv[1])) == -1)
		errx(1, "invalid input format '%s'", argv[1]);
	if ((dst_end->payload_type = audio_name_to_type(argv[2])) == -1)
		errx(1, "invalid output format '%s'", argv[2]);

	rc = mgcp_setup_processing(NULL, dst_end, src_end);
	if (rc < 0)
		errx(1, "setup failed: %s", strerror(-rc));

	state = dst_end->rtp_process_data;
	OSMO_ASSERT(state != NULL);

	in_size = 160 / state->src_samples_per_frame * state->src_frame_size;
	OSMO_ASSERT(sizeof(buf) >= in_size + 12);

	while ((cc = read(0, buf + 12, in_size))) {
		if (cc != in_size)
			err(1, "read");

		cc += 12; /* include RTP header */

		rc = mgcp_process_rtp_payload(dst_end, buf, &cc, sizeof(buf));
		if (rc < 0)
			errx(1, "processing failed: %s", strerror(-rc));

		cc -= 12; /* ignore RTP header */
		if (write(1, buf + 12, cc) != cc)
			err(1, "write");
	}
	return 0;
}

#if 0
int main(int argc, char **argv)
{
	gsm gsm_in = NULL, gsm_out = NULL;
	bcg729DecoderChannelContextStruct *g729_in = NULL;
	bcg729EncoderChannelContextStruct *g729_out = NULL;
	unsigned char buf[4096] = {0};
	gsm_signal sample[160] = {0};
	int cc;
	enum audio_format src_fmt, dst_fmt;
	size_t in_buf_size = 0;
	size_t out_buf_size = 0;

	if (argc <= 2)
		errx(1, "Usage: {gsm|g729|pcma} {gsm|g729|pcma}");

	if (!(src_fmt = parse_audio_format(argv[1])))
		errx(1, "invalid input format '%s'", argv[1]);
	if (!(dst_fmt = parse_audio_format(argv[2])))
		errx(1, "invalid output format '%s'", argv[2]);

	switch (src_fmt) {
	case AF_S16:
		in_buf_size = 160*sizeof(short);
		break;
	case AF_GSM:
		in_buf_size = sizeof(gsm_frame);
		if (!(gsm_in = gsm_create()))
			errx(1, "gsm_create");
		break;
	case AF_G729:
		in_buf_size = 10 * 2;
		if (!(g729_in = initBcg729DecoderChannel()))
			errx(1, "initBcg729DecoderChannel");
		break;
	case AF_PCMA:
		in_buf_size = 160;
		break;
	default:
		errx(1, "input format not supported");
	}

	switch (dst_fmt) {
	case AF_S16:
		out_buf_size = 160*sizeof(short);
		break;
	case AF_GSM:
		out_buf_size = sizeof(gsm_frame);
		if (!(gsm_out = gsm_create()))
			errx(1, "gsm_create");
		break;
	case AF_G729:
		out_buf_size = 10 * 2;
		if (!(g729_out = initBcg729EncoderChannel()))
			errx(1, "initBcg729EncoderChannel");
		break;
	case AF_PCMA:
		out_buf_size = 160;
		break;
	default:
		errx(1, "output format not supported");
	}

	while ((cc = read(0, (char *)buf, in_buf_size))) {
		if (cc != in_buf_size)
			err(1, "read");
		switch (src_fmt) {
		case AF_GSM:
			if (gsm_decode(gsm_in, buf, sample) < 0)
				errx(1, "gsm_decode");
			break;
		case AF_G729:
			bcg729Decoder(g729_in, buf, 0, sample);
			bcg729Decoder(g729_in, buf+in_buf_size/2, 0, &sample[80]);
			break;
		case AF_PCMA:
			alaw_decode(buf, sample, 160);
			break;
		case AF_S16:
			memmove((void *)sample, buf, in_buf_size);
			break;
		default:
			break;
		}
		switch (dst_fmt) {
		case AF_GSM:
			gsm_encode(gsm_out, sample, buf);
			break;
		case AF_G729:
			bcg729Encoder(g729_out, sample, buf);
			bcg729Encoder(g729_out, &sample[80], buf+out_buf_size/2);
			break;
		case AF_PCMA:
			alaw_encode(sample, buf, 160);
			break;
		case AF_S16:
			memmove(buf, sample, out_buf_size);
			break;
		default:
			break;
		}
		if (write(1, buf, out_buf_size) != out_buf_size)
			err(1, "write");
	}
	if (gsm_in)
		gsm_destroy(gsm_in);
	if (gsm_out)
		gsm_destroy(gsm_out);
	if (g729_in)
		closeBcg729DecoderChannel(g729_in);
	if (g729_out)
		closeBcg729EncoderChannel(g729_out);
	return 0;
}
#endif

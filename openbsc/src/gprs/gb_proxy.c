/* NS-over-IP proxy */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010-2013 by On-Waves
 * (C) 2013 by Holger Hans Peter Freyther
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <time.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/rate_ctr.h>

#include <osmocom/gprs/gprs_ns.h>
#include <osmocom/gprs/gprs_bssgp.h>

#include <osmocom/gsm/gsm_utils.h>

#include <openbsc/signal.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_gb_parse.h>
#include <openbsc/gb_proxy.h>

#include <openbsc/gprs_llc.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/gsm_04_08_gprs.h>
#include <openbsc/gprs_utils.h>

static const struct rate_ctr_desc global_ctr_description[] = {
	{ "inv-bvci",	    "Invalid BVC Identifier          " },
	{ "inv-lai",	    "Invalid Location Area Identifier" },
	{ "inv-rai",	    "Invalid Routing Area Identifier " },
	{ "inv-nsei",	    "No BVC established for NSEI     " },
	{ "proto-err.bss",  "BSSGP protocol error      (BSS )" },
	{ "proto-err.sgsn", "BSSGP protocol error      (SGSN)" },
	{ "not-supp.bss",   "Feature not supported     (BSS )" },
	{ "not-supp.sgsn",  "Feature not supported     (SGSN)" },
	{ "restart.sgsn",   "Restarted RESET procedure (SGSN)" },
	{ "tx-err.sgsn",    "NS Transmission error     (SGSN)" },
	{ "error",          "Other error                     " },
	{ "mod-peer-err",   "Patch error: no peer            " },
};

static const struct rate_ctr_group_desc global_ctrg_desc = {
	.group_name_prefix = "gbproxy.global",
	.group_description = "GBProxy Global Statistics",
	.num_ctr = ARRAY_SIZE(global_ctr_description),
	.ctr_desc = global_ctr_description,
};

static int check_peer_nsei(struct gbproxy_peer *peer, uint16_t nsei)
{
	if (peer->nsei != nsei) {
		LOGP(DGPRS, LOGL_NOTICE, "Peer entry doesn't match current NSEI "
		     "BVCI=%u via NSEI=%u (expected NSEI=%u)\n",
		     peer->bvci, nsei, peer->nsei);
		rate_ctr_inc(&peer->ctrg->ctr[GBPROX_PEER_CTR_INV_NSEI]);
		return 0;
	}

	return 1;
}

/* strip off the NS header */
static void strip_ns_hdr(struct msgb *msg)
{
	int strip_len = msgb_bssgph(msg) - msg->data;
	msgb_pull(msg, strip_len);
}

/* update peer according to the BSS message */
static void gbprox_update_current_raid(uint8_t *raid_enc,
				       struct gbproxy_peer *peer,
				       const char *log_text)
{
	struct gbproxy_patch_state *state = &peer->patch_state;
	const int old_local_mcc = state->local_mcc;
	const int old_local_mnc = state->local_mnc;
	struct gprs_ra_id raid;

	if (!raid_enc)
		return;

	gsm48_parse_ra(&raid, raid_enc);

	/* save source side MCC/MNC */
	if (!peer->cfg->core_mcc || raid.mcc == peer->cfg->core_mcc) {
		state->local_mcc = 0;
	} else {
		state->local_mcc = raid.mcc;
	}

	if (!peer->cfg->core_mnc || raid.mnc == peer->cfg->core_mnc) {
		state->local_mnc = 0;
	} else {
		state->local_mnc = raid.mnc;
	}

	if (old_local_mcc != state->local_mcc ||
	    old_local_mnc != state->local_mnc)
		LOGP(DGPRS, LOGL_NOTICE,
		     "Patching RAID %sactivated, msg: %s, "
		     "local: %d-%d, core: %d-%d\n",
		     state->local_mcc || state->local_mnc ?
		     "" : "de",
		     log_text,
		     state->local_mcc, state->local_mnc,
		     peer->cfg->core_mcc, peer->cfg->core_mnc);
}

uint32_t gbproxy_make_bss_ptmsi(struct gbproxy_peer *peer,
				uint32_t sgsn_ptmsi)
{
	uint32_t bss_ptmsi;
	if (!peer->cfg->patch_ptmsi) {
		bss_ptmsi = sgsn_ptmsi;
	} else {
		do {
			bss_ptmsi = rand_r(&peer->cfg->bss_ptmsi_state);
			bss_ptmsi = bss_ptmsi | 0xC0000000;

			if (gbproxy_find_tlli_by_ptmsi(peer, bss_ptmsi))
				bss_ptmsi = GSM_RESERVED_TMSI;
		} while (bss_ptmsi == GSM_RESERVED_TMSI);
	}

	return bss_ptmsi;
}

uint32_t gbproxy_make_sgsn_tlli(struct gbproxy_peer *peer,
				struct gbproxy_tlli_info *tlli_info,
				uint32_t bss_tlli)
{
	uint32_t sgsn_tlli;
	if (!peer->cfg->patch_ptmsi) {
		sgsn_tlli = bss_tlli;
	} else if (tlli_info->sgsn_tlli.ptmsi != GSM_RESERVED_TMSI) {
		sgsn_tlli = gprs_tmsi2tlli(tlli_info->sgsn_tlli.ptmsi,
					   TLLI_FOREIGN);
	} else {
		do {
			/* create random TLLI, 0b01111xxx... */
			sgsn_tlli = rand_r(&peer->cfg->sgsn_tlli_state);
			sgsn_tlli = (sgsn_tlli & 0x7fffffff) | 0x78000000;

			if (gbproxy_find_tlli_by_sgsn_tlli(peer, sgsn_tlli))
				sgsn_tlli = 0;
		} while (!sgsn_tlli);
	}
	return sgsn_tlli;
}

/* patch BSSGP message */
static void gbprox_process_bssgp_ul(struct gbproxy_config *cfg,
				    struct msgb *msg,
				    struct gbproxy_peer *peer)
{
	struct gprs_gb_parse_context parse_ctx = {0};
	int rc;
	int len_change = 0;
	time_t now;
	struct gbproxy_tlli_info *tlli_info = NULL;

	if (!cfg->core_mcc && !cfg->core_mnc && !cfg->core_apn)
		return;

	parse_ctx.to_bss = 0;

	/* Parse BSSGP/LLC */
	rc = gprs_gb_parse_bssgp(msgb_bssgph(msg), msgb_bssgp_len(msg),
				 &parse_ctx);

	if (!rc) {
		if (!parse_ctx.need_decryption) {
			LOGP(DGPRS, LOGL_ERROR,
			     "NSEI=%u(BSS) patching: "
			     "failed to parse BSSGP/GMM message\n",
			     msgb_nsei(msg));
			return;
		}
	}

	/* Get peer */
	if (!peer && msgb_bvci(msg) >= 2)
		peer = gbproxy_peer_by_bvci(cfg, msgb_bvci(msg));

	if (!peer)
		peer = gbproxy_peer_by_nsei(cfg, msgb_nsei(msg));

	if (!peer)
		peer = gbproxy_peer_by_bssgp_tlv(cfg, &parse_ctx.bssgp_tp);

	if (!peer) {
		LOGP(DLLC, LOGL_INFO,
		     "NSEI=%d(BSS) patching: didn't find peer for message, "
		     "PDU %d\n",
		     msgb_nsei(msg), parse_ctx.pdu_type);
		/* Increment counter */
		rate_ctr_inc(&cfg->ctrg->ctr[GBPROX_GLOB_CTR_PATCH_PEER_ERR]);
		return;
	}

	now = time(NULL);

	if (parse_ctx.bssgp_raid_enc && parse_ctx.old_raid_enc &&
	    memcmp(parse_ctx.bssgp_raid_enc, parse_ctx.old_raid_enc, 6) == 0)
		parse_ctx.old_raid_matches = 1;

	gbprox_update_current_raid(parse_ctx.bssgp_raid_enc, peer,
				   parse_ctx.llc_msg_name);

	if (parse_ctx.g48_hdr) {
		switch (parse_ctx.g48_hdr->msg_type) {
		case GSM48_MT_GMM_ATTACH_REQ:
			rate_ctr_inc(&peer->ctrg->ctr[GBPROX_PEER_CTR_ATTACH_REQS]);
			break;

		default:
			break;
		}
	}

	gprs_gb_log_parse_context(&parse_ctx, "BSSGP");

	tlli_info = gbproxy_update_tlli_state_ul(peer, now, &parse_ctx);

	gbproxy_patch_bssgp(msg, msgb_bssgph(msg), msgb_bssgp_len(msg),
			    peer, tlli_info, &len_change, &parse_ctx);

	gbproxy_update_tlli_state_after(peer, tlli_info, now, &parse_ctx);

	return;
}

/* patch BSSGP message to use core_mcc/mnc on the SGSN side */
static void gbprox_process_bssgp_dl(struct gbproxy_config *cfg,
				    struct msgb *msg,
				    struct gbproxy_peer *peer)
{
	struct gprs_gb_parse_context parse_ctx = {0};
	int rc;
	int len_change = 0;
	time_t now;
	struct gbproxy_tlli_info *tlli_info = NULL;

	parse_ctx.to_bss = 1;

	rc = gprs_gb_parse_bssgp(msgb_bssgph(msg), msgb_bssgp_len(msg),
				 &parse_ctx);

	if (!rc) {
		if (!parse_ctx.need_decryption) {
			LOGP(DGPRS, LOGL_ERROR,
			     "NSEI=%u(SGSN) patching: "
			     "failed to parse BSSGP/GMM message\n",
			     msgb_nsei(msg));
			return;
		}
	}

	if (!peer && msgb_bvci(msg) >= 2)
		peer = gbproxy_peer_by_bvci(cfg, msgb_bvci(msg));

	if (!peer)
		peer = gbproxy_peer_by_bssgp_tlv(cfg, &parse_ctx.bssgp_tp);

	if (!peer) {
		LOGP(DLLC, LOGL_INFO,
		     "NSEI=%d(SGSN) patching: didn't find peer for message, "
		     "PDU %d\n",
		     msgb_nsei(msg), parse_ctx.pdu_type);
		/* Increment counter */
		rate_ctr_inc(&cfg->ctrg->ctr[GBPROX_GLOB_CTR_PATCH_PEER_ERR]);
		return;
	}

	now = time(NULL);

	if (parse_ctx.g48_hdr) {
		switch (parse_ctx.g48_hdr->msg_type) {
		case GSM48_MT_GMM_ATTACH_REJ:
			rate_ctr_inc(&peer->ctrg->ctr[GBPROX_PEER_CTR_ATTACH_REJS]);
			break;

		default:
			break;
		}
	}

	gprs_gb_log_parse_context(&parse_ctx, "BSSGP");

	tlli_info = gbproxy_update_tlli_state_dl(peer, now, &parse_ctx);

	gbproxy_patch_bssgp(msg, msgb_bssgph(msg), msgb_bssgp_len(msg),
			    peer, tlli_info, &len_change, &parse_ctx);

	gbproxy_update_tlli_state_after(peer, tlli_info, now, &parse_ctx);

	return;
}

/* feed a message down the NS-VC associated with the specified peer */
static int gbprox_relay2sgsn(struct gbproxy_config *cfg, struct msgb *old_msg,
			     uint16_t ns_bvci)
{
	/* create a copy of the message so the old one can
	 * be free()d safely when we return from gbprox_rcvmsg() */
	struct msgb *msg = gprs_msgb_copy(old_msg, "msgb_relay2sgsn");
	int rc;

	DEBUGP(DGPRS, "NSEI=%u proxying BTS->SGSN (NS_BVCI=%u, NSEI=%u)\n",
		msgb_nsei(msg), ns_bvci, cfg->nsip_sgsn_nsei);

	msgb_bvci(msg) = ns_bvci;
	msgb_nsei(msg) = cfg->nsip_sgsn_nsei;

	strip_ns_hdr(msg);

	rc = gprs_ns_sendmsg(bssgp_nsi, msg);
	if (rc < 0)
		rate_ctr_inc(&cfg->ctrg->ctr[GBPROX_GLOB_CTR_TX_ERR_SGSN]);

	return rc;
}

/* feed a message down the NS-VC associated with the specified peer */
static int gbprox_relay2peer(struct msgb *old_msg, struct gbproxy_peer *peer,
			  uint16_t ns_bvci)
{
	/* create a copy of the message so the old one can
	 * be free()d safely when we return from gbprox_rcvmsg() */
	struct msgb *msg = gprs_msgb_copy(old_msg, "msgb_relay2peer");
	int rc;

	DEBUGP(DGPRS, "NSEI=%u proxying SGSN->BSS (NS_BVCI=%u, NSEI=%u)\n",
		msgb_nsei(msg), ns_bvci, peer->nsei);

	msgb_bvci(msg) = ns_bvci;
	msgb_nsei(msg) = peer->nsei;

	/* Strip the old NS header, it will be replaced with a new one */
	strip_ns_hdr(msg);

	rc = gprs_ns_sendmsg(bssgp_nsi, msg);
	if (rc < 0)
		rate_ctr_inc(&peer->ctrg->ctr[GBPROX_PEER_CTR_TX_ERR]);

	return rc;
}

static int block_unblock_peer(struct gbproxy_config *cfg, uint16_t ptp_bvci, uint8_t pdu_type)
{
	struct gbproxy_peer *peer;

	peer = gbproxy_peer_by_bvci(cfg, ptp_bvci);
	if (!peer) {
		LOGP(DGPRS, LOGL_ERROR, "BVCI=%u: Cannot find BSS\n",
			ptp_bvci);
		rate_ctr_inc(&cfg->ctrg->ctr[GBPROX_GLOB_CTR_INV_BVCI]);
		return -ENOENT;
	}

	switch (pdu_type) {
	case BSSGP_PDUT_BVC_BLOCK_ACK:
		peer->blocked = 1;
		rate_ctr_inc(&peer->ctrg->ctr[GBPROX_PEER_CTR_BLOCKED]);
		break;
	case BSSGP_PDUT_BVC_UNBLOCK_ACK:
		peer->blocked = 0;
		rate_ctr_inc(&peer->ctrg->ctr[GBPROX_PEER_CTR_UNBLOCKED]);
		break;
	default:
		break;
	}
	return 0;
}

/* Send a message to a peer identified by ptp_bvci but using ns_bvci
 * in the NS hdr */
static int gbprox_relay2bvci(struct gbproxy_config *cfg, struct msgb *msg, uint16_t ptp_bvci,
			  uint16_t ns_bvci)
{
	struct gbproxy_peer *peer;

	peer = gbproxy_peer_by_bvci(cfg, ptp_bvci);
	if (!peer) {
		LOGP(DGPRS, LOGL_ERROR, "BVCI=%u: Cannot find BSS\n",
			ptp_bvci);
		rate_ctr_inc(&cfg->ctrg->ctr[GBPROX_GLOB_CTR_INV_BVCI]);
		return -ENOENT;
	}

	return gbprox_relay2peer(msg, peer, ns_bvci);
}

int bssgp_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	return 0;
}

/* Receive an incoming PTP message from a BSS-side NS-VC */
static int gbprox_rx_ptp_from_bss(struct gbproxy_config *cfg,
				  struct msgb *msg, uint16_t nsei,
				  uint16_t nsvci, uint16_t ns_bvci)
{
	struct gbproxy_peer *peer;

	peer = gbproxy_peer_by_bvci(cfg, ns_bvci);

	if (peer)
		check_peer_nsei(peer, nsei);

	gbprox_process_bssgp_ul(cfg, msg, peer);

	return gbprox_relay2sgsn(cfg, msg, ns_bvci);
}

/* Receive an incoming PTP message from a SGSN-side NS-VC */
static int gbprox_rx_ptp_from_sgsn(struct gbproxy_config *cfg,
				   struct msgb *msg, uint16_t nsei,
				   uint16_t nsvci, uint16_t ns_bvci)
{
	struct gbproxy_peer *peer;

	peer = gbproxy_peer_by_bvci(cfg, ns_bvci);

	/* Send status messages before patching */

	if (!peer) {
		LOGP(DGPRS, LOGL_INFO, "Didn't find peer for "
		     "BVCI=%u for message from NSVC=%u/NSEI=%u (SGSN)\n",
		     ns_bvci, nsvci, nsei);
		rate_ctr_inc(&cfg->ctrg->
			     ctr[GBPROX_GLOB_CTR_INV_BVCI]);
		return bssgp_tx_status(BSSGP_CAUSE_UNKNOWN_BVCI,
				       &ns_bvci, msg);
	}

	if (peer->blocked) {
		LOGP(DGPRS, LOGL_NOTICE, "Dropping PDU for "
		     "blocked BVCI=%u via NSVC=%u/NSEI=%u\n",
		     ns_bvci, nsvci, nsei);
		rate_ctr_inc(&peer->ctrg->ctr[GBPROX_PEER_CTR_DROPPED]);
		return bssgp_tx_status(BSSGP_CAUSE_BVCI_BLOCKED, NULL, msg);
	}

	/* Optionally patch the message */
	gbprox_process_bssgp_dl(cfg, msg, peer);

	return gbprox_relay2peer(msg, peer, ns_bvci);
}

/* Receive an incoming signalling message from a BSS-side NS-VC */
static int gbprox_rx_sig_from_bss(struct gbproxy_config *cfg,
				  struct msgb *msg, uint16_t nsei,
				  uint16_t ns_bvci)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	struct tlv_parsed tp;
	uint8_t pdu_type = bgph->pdu_type;
	int data_len = msgb_bssgp_len(msg) - sizeof(*bgph);
	struct gbproxy_peer *from_peer = NULL;
	struct gprs_ra_id raid;

	if (ns_bvci != 0 && ns_bvci != 1) {
		LOGP(DGPRS, LOGL_NOTICE, "NSEI=%u BVCI=%u is not signalling\n",
			nsei, ns_bvci);
		return -EINVAL;
	}

	/* we actually should never see those two for BVCI == 0, but double-check
	 * just to make sure  */
	if (pdu_type == BSSGP_PDUT_UL_UNITDATA ||
	    pdu_type == BSSGP_PDUT_DL_UNITDATA) {
		LOGP(DGPRS, LOGL_NOTICE, "NSEI=%u UNITDATA not allowed in "
			"signalling\n", nsei);
		return -EINVAL;
	}

	bssgp_tlv_parse(&tp, bgph->data, data_len);

	switch (pdu_type) {
	case BSSGP_PDUT_SUSPEND:
	case BSSGP_PDUT_RESUME:
		/* We implement RAI snooping during SUSPEND/RESUME, since it
		 * establishes a relationsip between BVCI/peer and the routeing
		 * area identification.  The snooped information is then used
		 * for routing the {SUSPEND,RESUME}_[N]ACK back to the correct
		 * BSSGP */
		if (!TLVP_PRESENT(&tp, BSSGP_IE_ROUTEING_AREA))
			goto err_mand_ie;
		from_peer = gbproxy_peer_by_nsei(cfg, nsei);
		if (!from_peer)
			goto err_no_peer;
		memcpy(from_peer->ra, TLVP_VAL(&tp, BSSGP_IE_ROUTEING_AREA),
			sizeof(from_peer->ra));
		gsm48_parse_ra(&raid, from_peer->ra);
		LOGP(DGPRS, LOGL_INFO, "NSEI=%u BSSGP SUSPEND/RESUME "
			"RAI snooping: RAI %u-%u-%u-%u behind BVCI=%u\n",
			nsei, raid.mcc, raid.mnc, raid.lac,
			raid.rac , from_peer->bvci);
		/* FIXME: This only supports one BSS per RA */
		break;
	case BSSGP_PDUT_BVC_RESET:
		/* If we receive a BVC reset on the signalling endpoint, we
		 * don't want the SGSN to reset, as the signalling endpoint
		 * is common for all point-to-point BVCs (and thus all BTS) */
		if (TLVP_PRESENT(&tp, BSSGP_IE_BVCI)) {
			uint16_t bvci = ntohs(tlvp_val16_unal(&tp, BSSGP_IE_BVCI));
			LOGP(DGPRS, LOGL_INFO, "NSEI=%u Rx BVC RESET (BVCI=%u)\n",
				nsei, bvci);
			if (bvci == 0) {
				/* FIXME: only do this if SGSN is alive! */
				LOGP(DGPRS, LOGL_INFO, "NSEI=%u Tx fake "
					"BVC RESET ACK of BVCI=0\n", nsei);
				return bssgp_tx_simple_bvci(BSSGP_PDUT_BVC_RESET_ACK,
							    nsei, 0, ns_bvci);
			}
			from_peer = gbproxy_peer_by_bvci(cfg, bvci);
			if (!from_peer) {
				/* if a PTP-BVC is reset, and we don't know that
				 * PTP-BVCI yet, we should allocate a new peer */
				LOGP(DGPRS, LOGL_INFO, "Allocationg new peer for "
				     "BVCI=%u via NSEI=%u\n", bvci, nsei);
				from_peer = gbproxy_peer_alloc(cfg, bvci);
				from_peer->nsei = nsei;
			}

			if (!check_peer_nsei(from_peer, nsei))
				from_peer->nsei = nsei;

			if (TLVP_PRESENT(&tp, BSSGP_IE_CELL_ID)) {
				struct gprs_ra_id raid;
				/* We have a Cell Identifier present in this
				 * PDU, this means we can extend our local
				 * state information about this particular cell
				 * */
				memcpy(from_peer->ra,
					TLVP_VAL(&tp, BSSGP_IE_CELL_ID),
					sizeof(from_peer->ra));
				gsm48_parse_ra(&raid, from_peer->ra);
				LOGP(DGPRS, LOGL_INFO, "NSEI=%u/BVCI=%u "
				     "Cell ID %u-%u-%u-%u\n", nsei,
				     bvci, raid.mcc, raid.mnc, raid.lac,
				     raid.rac);
			}
		}
		break;
	}

	/* Normally, we can simply pass on all signalling messages from BSS to
	 * SGSN */
	gbprox_process_bssgp_ul(cfg, msg, from_peer);
	return gbprox_relay2sgsn(cfg, msg, ns_bvci);
err_no_peer:
	LOGP(DGPRS, LOGL_ERROR, "NSEI=%u(BSS) cannot find peer based on NSEI\n",
		nsei);
	rate_ctr_inc(&cfg->ctrg->ctr[GBPROX_GLOB_CTR_INV_NSEI]);
	return bssgp_tx_status(BSSGP_CAUSE_UNKNOWN_BVCI, NULL, msg);
err_mand_ie:
	LOGP(DGPRS, LOGL_ERROR, "NSEI=%u(BSS) missing mandatory RA IE\n",
		nsei);
	rate_ctr_inc(&cfg->ctrg->ctr[GBPROX_GLOB_CTR_PROTO_ERR_BSS]);
	return bssgp_tx_status(BSSGP_CAUSE_MISSING_MAND_IE, NULL, msg);
}

/* Receive paging request from SGSN, we need to relay to proper BSS */
static int gbprox_rx_paging(struct gbproxy_config *cfg, struct msgb *msg, struct tlv_parsed *tp,
			    uint32_t nsei, uint16_t ns_bvci)
{
	struct gbproxy_peer *peer = NULL;
	int errctr = GBPROX_GLOB_CTR_PROTO_ERR_SGSN;

	LOGP(DGPRS, LOGL_INFO, "NSEI=%u(SGSN) BSSGP PAGING ",
		nsei);
	if (TLVP_PRESENT(tp, BSSGP_IE_BVCI)) {
		uint16_t bvci = ntohs(tlvp_val16_unal(tp, BSSGP_IE_BVCI));
		LOGPC(DGPRS, LOGL_INFO, "routing by BVCI to peer BVCI=%u\n",
			bvci);
		errctr = GBPROX_GLOB_CTR_OTHER_ERR;
	} else if (TLVP_PRESENT(tp, BSSGP_IE_ROUTEING_AREA)) {
		peer = gbproxy_peer_by_rai(cfg, TLVP_VAL(tp, BSSGP_IE_ROUTEING_AREA));
		LOGPC(DGPRS, LOGL_INFO, "routing by RAI to peer BVCI=%u\n",
			peer ? peer->bvci : -1);
		errctr = GBPROX_GLOB_CTR_INV_RAI;
	} else if (TLVP_PRESENT(tp, BSSGP_IE_LOCATION_AREA)) {
		peer = gbproxy_peer_by_lai(cfg, TLVP_VAL(tp, BSSGP_IE_LOCATION_AREA));
		LOGPC(DGPRS, LOGL_INFO, "routing by LAI to peer BVCI=%u\n",
			peer ? peer->bvci : -1);
		errctr = GBPROX_GLOB_CTR_INV_LAI;
	} else
		LOGPC(DGPRS, LOGL_INFO, "\n");

	if (!peer) {
		LOGP(DGPRS, LOGL_ERROR, "NSEI=%u(SGSN) BSSGP PAGING: "
			"unable to route, missing IE\n", nsei);
		rate_ctr_inc(&cfg->ctrg->ctr[errctr]);
		return -EINVAL;
	}
	return gbprox_relay2peer(msg, peer, ns_bvci);
}

/* Receive an incoming BVC-RESET message from the SGSN */
static int rx_reset_from_sgsn(struct gbproxy_config *cfg,
			struct msgb *orig_msg,
			struct msgb *msg, struct tlv_parsed *tp,
			uint32_t nsei, uint16_t ns_bvci)
{
	struct gbproxy_peer *peer;
	uint16_t ptp_bvci;

	if (!TLVP_PRESENT(tp, BSSGP_IE_BVCI)) {
		rate_ctr_inc(&cfg->ctrg->
			     ctr[GBPROX_GLOB_CTR_PROTO_ERR_SGSN]);
		return bssgp_tx_status(BSSGP_CAUSE_MISSING_MAND_IE,
				       NULL, orig_msg);
	}
	ptp_bvci = ntohs(tlvp_val16_unal(tp, BSSGP_IE_BVCI));

	if (ptp_bvci >= 2) {
		/* A reset for a PTP BVC was received, forward it to its
		 * respective peer */
		peer = gbproxy_peer_by_bvci(cfg, ptp_bvci);
		if (!peer) {
			LOGP(DGPRS, LOGL_ERROR, "NSEI=%u BVCI=%u: Cannot find BSS\n",
				nsei, ptp_bvci);
			rate_ctr_inc(&cfg->ctrg->
				     ctr[GBPROX_GLOB_CTR_INV_BVCI]);
			return bssgp_tx_status(BSSGP_CAUSE_UNKNOWN_BVCI,
					       NULL, orig_msg);
		}
		return gbprox_relay2peer(msg, peer, ns_bvci);
	}

	/* A reset for the Signalling entity has been received
	 * from the SGSN.  As the signalling BVCI is shared
	 * among all the BSS's that we multiplex, it needs to
	 * be relayed  */
	llist_for_each_entry(peer, &cfg->bts_peers, list)
		gbprox_relay2peer(msg, peer, ns_bvci);

	return 0;
}

/* Receive an incoming signalling message from the SGSN-side NS-VC */
static int gbprox_rx_sig_from_sgsn(struct gbproxy_config *cfg,
				struct msgb *orig_msg, uint32_t nsei,
				uint16_t ns_bvci)
{
	struct bssgp_normal_hdr *bgph =
		(struct bssgp_normal_hdr *) msgb_bssgph(orig_msg);
	struct tlv_parsed tp;
	uint8_t pdu_type = bgph->pdu_type;
	int data_len;
	struct gbproxy_peer *peer;
	uint16_t bvci;
	struct msgb *msg;
	int rc = 0;

	if (ns_bvci != 0 && ns_bvci != 1) {
		LOGP(DGPRS, LOGL_NOTICE, "NSEI=%u(SGSN) BVCI=%u is not "
			"signalling\n", nsei, ns_bvci);
		/* FIXME: Send proper error message */
		return -EINVAL;
	}

	/* we actually should never see those two for BVCI == 0, but double-check
	 * just to make sure  */
	if (pdu_type == BSSGP_PDUT_UL_UNITDATA ||
	    pdu_type == BSSGP_PDUT_DL_UNITDATA) {
		LOGP(DGPRS, LOGL_NOTICE, "NSEI=%u(SGSN) UNITDATA not allowed in "
			"signalling\n", nsei);
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, orig_msg);
	}

	msg = gprs_msgb_copy(orig_msg, "rx_sig_from_sgsn");
	gbprox_process_bssgp_dl(cfg, msg, NULL);
	/* Update message info */
	bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	data_len = msgb_bssgp_len(orig_msg) - sizeof(*bgph);
	rc = bssgp_tlv_parse(&tp, bgph->data, data_len);

	switch (pdu_type) {
	case BSSGP_PDUT_BVC_RESET:
		rc = rx_reset_from_sgsn(cfg, msg, orig_msg, &tp, nsei, ns_bvci);
		break;
	case BSSGP_PDUT_FLUSH_LL:
	case BSSGP_PDUT_BVC_RESET_ACK:
		/* simple case: BVCI IE is mandatory */
		if (!TLVP_PRESENT(&tp, BSSGP_IE_BVCI))
			goto err_mand_ie;
		bvci = ntohs(tlvp_val16_unal(&tp, BSSGP_IE_BVCI));
		rc = gbprox_relay2bvci(cfg, msg, bvci, ns_bvci);
		break;
	case BSSGP_PDUT_PAGING_PS:
	case BSSGP_PDUT_PAGING_CS:
		/* process the paging request (LAI/RAI lookup) */
		rc = gbprox_rx_paging(cfg, msg, &tp, nsei, ns_bvci);
		break;
	case BSSGP_PDUT_STATUS:
		/* Some exception has occurred */
		LOGP(DGPRS, LOGL_NOTICE,
			"NSEI=%u(SGSN) BSSGP STATUS ", nsei);
		if (!TLVP_PRESENT(&tp, BSSGP_IE_CAUSE)) {
			LOGPC(DGPRS, LOGL_NOTICE, "\n");
			goto err_mand_ie;
		}
		LOGPC(DGPRS, LOGL_NOTICE,
			"cause=0x%02x(%s) ", *TLVP_VAL(&tp, BSSGP_IE_CAUSE),
			bssgp_cause_str(*TLVP_VAL(&tp, BSSGP_IE_CAUSE)));
		if (TLVP_PRESENT(&tp, BSSGP_IE_BVCI)) {
			uint16_t bvci = tlvp_val16_unal(&tp, BSSGP_IE_BVCI);
			LOGPC(DGPRS, LOGL_NOTICE,
				"BVCI=%u\n", ntohs(bvci));
		} else
			LOGPC(DGPRS, LOGL_NOTICE, "\n");
		break;
	/* those only exist in the SGSN -> BSS direction */
	case BSSGP_PDUT_SUSPEND_ACK:
	case BSSGP_PDUT_SUSPEND_NACK:
	case BSSGP_PDUT_RESUME_ACK:
	case BSSGP_PDUT_RESUME_NACK:
		/* RAI IE is mandatory */
		if (!TLVP_PRESENT(&tp, BSSGP_IE_ROUTEING_AREA))
			goto err_mand_ie;
		peer = gbproxy_peer_by_rai(cfg, TLVP_VAL(&tp, BSSGP_IE_ROUTEING_AREA));
		if (!peer)
			goto err_no_peer;
		rc = gbprox_relay2peer(msg, peer, ns_bvci);
		break;
	case BSSGP_PDUT_BVC_BLOCK_ACK:
	case BSSGP_PDUT_BVC_UNBLOCK_ACK:
		if (!TLVP_PRESENT(&tp, BSSGP_IE_BVCI))
			goto err_mand_ie;
		bvci = ntohs(tlvp_val16_unal(&tp, BSSGP_IE_BVCI));
		if (bvci == 0) {
			LOGP(DGPRS, LOGL_NOTICE, "NSEI=%u(SGSN) BSSGP "
			     "%sBLOCK_ACK for signalling BVCI ?!?\n", nsei,
			     pdu_type == BSSGP_PDUT_BVC_UNBLOCK_ACK ? "UN":"");
			/* should we send STATUS ? */
			rate_ctr_inc(&cfg->ctrg->
				     ctr[GBPROX_GLOB_CTR_INV_BVCI]);
		} else {
			/* Mark BVC as (un)blocked */
			block_unblock_peer(cfg, bvci, pdu_type);
		}
		rc = gbprox_relay2bvci(cfg, msg, bvci, ns_bvci);
		break;
	case BSSGP_PDUT_SGSN_INVOKE_TRACE:
		LOGP(DGPRS, LOGL_ERROR,
		     "NSEI=%u(SGSN) BSSGP INVOKE TRACE not supported\n",nsei);
		rate_ctr_inc(&cfg->ctrg->
			     ctr[GBPROX_GLOB_CTR_NOT_SUPPORTED_SGSN]);
		rc = bssgp_tx_status(BSSGP_CAUSE_PDU_INCOMP_FEAT, NULL, orig_msg);
		break;
	default:
		LOGP(DGPRS, LOGL_NOTICE, "BSSGP PDU type 0x%02x unknown\n",
			pdu_type);
		rate_ctr_inc(&cfg->ctrg->
			     ctr[GBPROX_GLOB_CTR_PROTO_ERR_SGSN]);
		rc = bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, orig_msg);
		break;
	}

	msgb_free(msg);

	return rc;
err_mand_ie:
	LOGP(DGPRS, LOGL_ERROR, "NSEI=%u(SGSN) missing mandatory IE\n",
		nsei);
	rate_ctr_inc(&cfg->ctrg->
		     ctr[GBPROX_GLOB_CTR_PROTO_ERR_SGSN]);
	msgb_free(msg);
	return bssgp_tx_status(BSSGP_CAUSE_MISSING_MAND_IE, NULL, orig_msg);
err_no_peer:
	LOGP(DGPRS, LOGL_ERROR, "NSEI=%u(SGSN) cannot find peer based on RAI\n",
		nsei);
	rate_ctr_inc(&cfg->ctrg-> ctr[GBPROX_GLOB_CTR_INV_RAI]);
	msgb_free(msg);
	return bssgp_tx_status(BSSGP_CAUSE_UNKNOWN_BVCI, NULL, orig_msg);
}

/* Main input function for Gb proxy */
int gbprox_rcvmsg(struct gbproxy_config *cfg, struct msgb *msg, uint16_t nsei,
		uint16_t ns_bvci, uint16_t nsvci)
{
	int rc;
	int remote_end_is_sgsn = nsei == cfg->nsip_sgsn_nsei;

	/* Only BVCI=0 messages need special treatment */
	if (ns_bvci == 0 || ns_bvci == 1) {
		if (remote_end_is_sgsn)
			rc = gbprox_rx_sig_from_sgsn(cfg, msg, nsei, ns_bvci);
		else
			rc = gbprox_rx_sig_from_bss(cfg, msg, nsei, ns_bvci);
	} else {
		/* All other BVCI are PTP */
		if (remote_end_is_sgsn)
			rc = gbprox_rx_ptp_from_sgsn(cfg, msg, nsei, nsvci,
						     ns_bvci);
		else
			rc = gbprox_rx_ptp_from_bss(cfg, msg, nsei, nsvci,
						    ns_bvci);
	}

	return rc;
}

int gbprox_reset_persistent_nsvcs(struct gprs_ns_inst *nsi)
{
	struct gprs_nsvc *nsvc;

	llist_for_each_entry(nsvc, &nsi->gprs_nsvcs, list) {
		if (!nsvc->persistent)
			continue;
		gprs_nsvc_reset(nsvc, NS_CAUSE_OM_INTERVENTION);
	}
	return 0;
}

/* Signal handler for signals from NS layer */
int gbprox_signal(unsigned int subsys, unsigned int signal,
		  void *handler_data, void *signal_data)
{
	struct gbproxy_config *cfg = handler_data;
	struct ns_signal_data *nssd = signal_data;
	struct gprs_nsvc *nsvc = nssd->nsvc;
	struct gbproxy_peer *peer;

	if (subsys != SS_L_NS)
		return 0;

	if (signal == S_NS_RESET && nsvc->nsei == cfg->nsip_sgsn_nsei) {
		/* We have received a NS-RESET from the NSEI and NSVC
		 * of the SGSN.  This might happen with SGSN that start
		 * their own NS-RESET procedure without waiting for our
		 * NS-RESET */
		nsvc->remote_end_is_sgsn = 1;
	}

	if (signal == S_NS_ALIVE_EXP && nsvc->remote_end_is_sgsn) {
		LOGP(DGPRS, LOGL_NOTICE, "Tns alive expired too often, "
			"re-starting RESET procedure\n");
		rate_ctr_inc(&cfg->ctrg->
			     ctr[GBPROX_GLOB_CTR_RESTART_RESET_SGSN]);
		gprs_ns_nsip_connect(nsvc->nsi, &nsvc->ip.bts_addr,
				  nsvc->nsei, nsvc->nsvci);
	}

	if (!nsvc->remote_end_is_sgsn) {
		/* from BSS to SGSN */
		peer = gbproxy_peer_by_nsei(cfg, nsvc->nsei);
		if (!peer) {
			LOGP(DGPRS, LOGL_NOTICE, "signal %u for unknown peer "
			     "NSEI=%u/NSVCI=%u\n", signal, nsvc->nsei,
			     nsvc->nsvci);
			return 0;
		}
		switch (signal) {
		case S_NS_RESET:
		case S_NS_BLOCK:
			if (!peer->blocked)
				break;
			LOGP(DGPRS, LOGL_NOTICE, "Converting NS_RESET from "
			     "NSEI=%u/NSVCI=%u into BSSGP_BVC_BLOCK to SGSN\n",
			     nsvc->nsei, nsvc->nsvci);
			bssgp_tx_simple_bvci(BSSGP_PDUT_BVC_BLOCK, nsvc->nsei,
					     peer->bvci, 0);
			break;
		}
	} else {
		/* Forward this message to all NS-VC to BSS */
		struct gprs_ns_inst *nsi = cfg->nsi;
		struct gprs_nsvc *next_nsvc;

		llist_for_each_entry(next_nsvc, &nsi->gprs_nsvcs, list) {
			if (next_nsvc->remote_end_is_sgsn)
				continue;

			/* Note that the following does not start the full
			 * procedures including timer based retransmissions. */
			switch (signal) {
			case S_NS_RESET:
				gprs_ns_tx_reset(next_nsvc, nssd->cause);
				break;
			case S_NS_BLOCK:
				gprs_ns_tx_block(next_nsvc, nssd->cause);
				break;
			case S_NS_UNBLOCK:
				gprs_ns_tx_unblock(next_nsvc);
				break;
			}
		}
	}
	return 0;
}

void gbprox_reset(struct gbproxy_config *cfg)
{
	struct gbproxy_peer *peer, *tmp;

	llist_for_each_entry_safe(peer, tmp, &cfg->bts_peers, list)
		gbproxy_peer_free(peer);

	rate_ctr_group_free(cfg->ctrg);
	gbproxy_init_config(cfg);
}

int gbproxy_init_config(struct gbproxy_config *cfg)
{
	struct timespec tp;
	INIT_LLIST_HEAD(&cfg->bts_peers);
	cfg->ctrg = rate_ctr_group_alloc(tall_bsc_ctx, &global_ctrg_desc, 0);
	clock_gettime(CLOCK_REALTIME, &tp);
	cfg->bss_ptmsi_state = tp.tv_sec + tp.tv_nsec;
	cfg->sgsn_tlli_state = tp.tv_sec - tp.tv_nsec;
	return 0;
}

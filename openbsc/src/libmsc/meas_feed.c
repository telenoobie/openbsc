/* UDP-Feed of measurement reports */

#include <unistd.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/talloc.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/vty.h>

#include <openbsc/meas_rep.h>
#include <openbsc/signal.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/meas_feed.h>
#include <openbsc/vty.h>

struct meas_feed_state {
	struct osmo_wqueue wqueue;
	char scenario[31+1];
	char *dst_host;
	uint16_t dst_port;
};


static struct meas_feed_state g_mfs;

static int process_meas_rep(struct gsm_meas_rep *mr)
{
	struct msgb *msg;
	struct meas_feed_meas *mfm;
	struct gsm_subscriber *subscr;

	/* ignore measurements as long as we don't know who it is */
	if (!mr->lchan || !mr->lchan->conn || !mr->lchan->conn->subscr)
		return 0;

	subscr = mr->lchan->conn->subscr;

	msg = msgb_alloc(sizeof(struct meas_feed_meas), "Meas. Feed");
	if (!msg)
		return 0;

	/* fill in the header */
	mfm = (struct meas_feed_meas *) msgb_put(msg, sizeof(*mfm));
	mfm->hdr.msg_type = MEAS_FEED_MEAS;
	mfm->hdr.version = MEAS_FEED_VERSION;

	/* fill in MEAS_FEED_MEAS specific header */
	strncpy(mfm->imsi, subscr->imsi, sizeof(mfm->imsi)-1);
	mfm->imsi[sizeof(mfm->imsi)-1] = '\0';
	strncpy(mfm->name, subscr->name, sizeof(mfm->name)-1);
	mfm->name[sizeof(mfm->name)-1] = '\0';
	strncpy(mfm->scenario, g_mfs.scenario, sizeof(mfm->scenario));
	mfm->scenario[sizeof(mfm->scenario)-1] = '\0';

	printf("NR: %u %s\n", mr->nr, osmo_hexdump(mr, sizeof(*mr)));
	/* copy the entire measurement report */
	memcpy(&mfm->mr, mr, sizeof(mfm->mr));
	printf("%s\n\n", osmo_hexdump(&mfm->mr, sizeof(mfm->mr)));

	/* and send it to the socket */
	osmo_wqueue_enqueue(&g_mfs.wqueue, msg);

	return 0;
}

static int meas_feed_sig_cb(unsigned int subsys, unsigned int signal,
			    void *handler_data, void *signal_data)
{
	struct lchan_signal_data *sdata = signal_data;

	if (subsys != SS_LCHAN)
		return 0;

	if (signal == S_LCHAN_MEAS_REP)
		process_meas_rep(sdata->mr);

	return 0;
}

static int feed_write_cb(struct osmo_fd *ofd, struct msgb *msg)
{
	return write(ofd->fd, msgb_data(msg), msgb_length(msg));
}

static int feed_read_cb(struct osmo_fd *ofd, struct msgb *msg)
{
	int rc;
	char buf[256];

	rc = read(ofd->fd, buf, sizeof(buf));
	ofd->fd &= ~BSC_FD_READ;

	return rc;
}

static int meas_feed_cfg(const char *dst_host, uint16_t dst_port)
{
	int rc;
	int already_initialized = 0;

	if (g_mfs.wqueue.bfd.fd)
		already_initialized = 1;

	printf("already_initialized=%d\n", already_initialized);

	if (already_initialized &&
	    !strcmp(dst_host, g_mfs.dst_host) &&
	    dst_port == g_mfs.dst_port)
		return 0;

	if (!already_initialized) {
		osmo_wqueue_init(&g_mfs.wqueue, 10);
		g_mfs.wqueue.write_cb = feed_write_cb;
		g_mfs.wqueue.read_cb = feed_read_cb;
		osmo_signal_register_handler(SS_LCHAN, meas_feed_sig_cb, NULL);
	}

	if (already_initialized) {
		osmo_wqueue_clear(&g_mfs.wqueue);
		osmo_fd_unregister(&g_mfs.wqueue.bfd);
		close(g_mfs.wqueue.bfd.fd);
		/* don't set to zero, as that would mean 'not yet initialized' */
		g_mfs.wqueue.bfd.fd = -1;
	}
	rc = osmo_sock_init_ofd(&g_mfs.wqueue.bfd, AF_UNSPEC, SOCK_DGRAM,
				IPPROTO_UDP, dst_host, dst_port,
				OSMO_SOCK_F_CONNECT);
	if (rc < 0)
		return rc;

	g_mfs.wqueue.bfd.when &= ~BSC_FD_READ;

	if (g_mfs.dst_host)
		talloc_free(g_mfs.dst_host);
	g_mfs.dst_host = talloc_strdup(NULL, dst_host);
	g_mfs.dst_port = dst_port;

	printf("MEAS FEED FD: %d\n", g_mfs.wqueue.bfd.fd);

	return 0;
}

DEFUN(cfg_net_meas_feed, cfg_net_meas_feed_cmd,
	"meas-feed destination ADDR <0-65535>",
	"FIXME")
{
	int rc;

	rc = meas_feed_cfg(argv[0], atoi(argv[1]));
	if (rc < 0)
		return CMD_WARNING;

	return CMD_SUCCESS;
}

DEFUN(meas_feed_scenario, meas_feed_scenario_cmd,
	"meas-feed scenario NAME",
	"FIXME")
{
	strncpy(g_mfs.scenario, argv[0], sizeof(g_mfs.scenario)-1);
	g_mfs.scenario[sizeof(g_mfs.scenario)-1] = '\0';

	return CMD_SUCCESS;
}

int meas_feed_init(void)
{
	install_element(ENABLE_NODE, &meas_feed_scenario_cmd);
	install_element(GSMNET_NODE, &cfg_net_meas_feed_cmd);

	return 0;
}

#if 0
{
	struct gsm_rx_lev_qual *rq;
	/* uplink measurements do always exist */
	if (mr->flags & MEAS_REP_F_UL_DTX)
		rq = &mr->ul.sub;
	else
		rq = &mr->ul.full;
	/* FIXME */

	if (mr->flags & MEAS_REP_F_DL_VALID) {
		if (mr->flags & MEAS_REP_F_DL_DTX)
			rq = &mr->dl.sub;
		else
			rq = &mr->dl.full;
		/* FIXME */
	}

	if (mr->flags & MEAS_REP_F_MS_L1) {
		/* FIXME */
	}

	return 0;
}
#endif

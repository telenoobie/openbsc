#ifndef _GSM_SUBSCR_H
#define _GSM_SUBSCR_H

#include <sys/types.h>
#include "gsm_data.h"
#include "linuxlist.h"

#define GSM_IMEI_LENGTH 17
#define GSM_IMSI_LENGTH 17
#define GSM_TMSI_LENGTH 17
#define GSM_NAME_LENGTH 128
#define GSM_EXTENSION_LENGTH 128

struct gsm_subscriber {
	u_int64_t id;
	char imsi[GSM_IMSI_LENGTH];
	char tmsi[GSM_TMSI_LENGTH];
	u_int16_t lac;
	char name[GSM_NAME_LENGTH];
	char extension[GSM_EXTENSION_LENGTH];
	int authorized;

	/* for internal management */ 
	int use_count;
	struct llist_head entry;
};

enum gsm_subscriber_field {
	GSM_SUBSCRIBER_IMSI,
	GSM_SUBSCRIBER_TMSI,
};

struct gsm_subscriber *subscr_alloc();
struct gsm_subscriber *subscr_get(struct gsm_subscriber *subscr);
struct gsm_subscriber *subscr_put(struct gsm_subscriber *subscr);

#endif /* _GSM_SUBSCR_H */

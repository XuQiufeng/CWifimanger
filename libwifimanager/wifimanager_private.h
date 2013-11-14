#ifndef WIFIMANAGER_PRIVATE_H_
#define WIFIMANAGER_PRIVATE_H_

/*thread secure extension of wifi_command, will lock when enter and exit*/
int thread_secure_wifi_command(const char *iface, const char *command, char *reply, size_t *reply_len);

/** All events coming from the supplicant start with this prefix */
#define EVENT_PREFIX_STR		"CTRL-EVENT-"

/** All WPA events coming from the supplicant start with this prefix */
#define WPA_EVENT_PREFIX_STR	"WPA:"

/* WPS events */
#define WPS_SUCCESS_STR 		"WPS-SUCCESS"

/* Format: WPS-FAIL msg=%d [config_error=%d] [reason=%d (%s)] */
#define WPS_FAIL_STR   			"WPS-FAIL"

#define WPS_OVERLAP_STR 		"WPS-OVERLAP-DETECTED"
#define WPS_TIMEOUT_STR			"WPS-TIMEOUT"

/* Format: CTRL-EVENT-CONNECTED - Connection to xx:xx:xx:xx:xx:xx completed */
#define CONNECTED_STR			"CONNECTED"

/* Format: CTRL-EVENT-DISCONNECTED - Disconnect event - remove keys*/
#define DISCONNECTED_STR		"DISCONNECTED"

/* Format: CTRL-EVENT-STATE-CHANGE x*/
#define STATE_CHANGE_STR		"STATE-CHANGE"

/* Format: CTRL-EVENT-SCAN-RESULTS ready*/
#define SCAN_RESULTS_STR 		"SCAN-RESULTS"

/* Format: CTRL-EVENT-LINK-SPEED x Mb/s*/
#define LINK_SPEED_STR			"LINK-SPEED"

/* Format: CTRL-EVENT-TERMINATING - signal x*/
#define TERMINATING_STR 		"TERMINATING"

/* Format: CTRL-EVENT-DRIVER-STATE state*/
#define DRIVER_STATE_STR 		"DRIVER-STATE"

/* Format: CTRL-EVENT-EAP-FAILURE EAP authentication failed*/
#define EAP_FAILURE_STR			"EAP-FAILURE"

#define SUP_CONNECTION_EVENT                1
#define SUP_DISCONNECTION_EVENT             2
#define NETWORK_CONNECTION_EVENT            3
#define NETWORK_DISCONNECTION_EVENT         4
#define SCAN_RESULTS_EVENT                  5
#define SUPPLICANT_STATE_CHANGE_EVENT       6
#define AUTHENTICATION_FAILURE_EVENT        7
#define WPS_SUCCESS_EVENT                   8
#define WPS_FAIL_EVENT                      9
#define WPS_OVERLAP_EVENT                   10
#define WPS_TIMEOUT_EVENT                   11
#define DRIVER_HUNG_EVENT                   12

#define NETWORK_ASSOCIATING_EVENT           13
#define NETWORK_AUTHENTICATING_EVENT        14

typedef void (*Func)(void*);

struct EventHandler{
    struct EventHandler *prev, *next;
    int EventType;
    Func EventHandler;
};

#define MAX_REQUEST_BUFF_SIZE    50

struct NetworkRequest{
    struct NetworkRequest *prev, *next;
    char cmdbuf[MAX_REQUEST_BUFF_SIZE];
    Func RequestCallback;
};

int NewNetworkRequest(const char* cmdbuf, Func RequestCallback);
struct NetworkRequest * GetPendingRequest();
int NRQRequestDone(const char* cmdbuf);
int RegisterEventHandler(int Event, Func EventHandler);
Func GetEventHandler(int Event);

#endif  // WIFIMANAGER_H_

#ifndef WIFIMANAGER_H_
#define WIFIMANAGER_H_

//wifi network status definition
#define DISABLING          -1
#define DISABLED            0
#define ENABLING            1
#define ENABLED             2
#define CONNECTING          3
#define SCANNING            4
#define SCAN_COMPLETE       5
#define CONNECTED           6
#define DISCONNECTED        7
#define AUTHENTICATION_FAIL 8

//wifi scan result code
#define SCAN_START         -1
#define SCAN_OK            0
#define ALREADY_IN_PROCESS 1
#define WPA_NOT_STARTED    2
#define SCAN_TIMEOUT       3
#define SCAN_NOT_START     4
#define SCAN_ERROR         5
#define MAX_SCAN_ENTY      8

//wifi encrypt method
#define WPA_EAP_CCMP           0
#define WPA2_EAP_CCMP          1
#define WPA_PSK_CCMP           2
#define WPA2_PSK_CCMP          3
#define WPA_PSK_CCMP_TKIP      4
#define WPA2_PSK_CCMP_TKIP     5
#define ESS_ONLY               6
#define ENCYPT_METHOD_MAX      7

struct scan_result{
    int  id;
    char bssid[20];
    int  frequency;
    int  level;
    char tsf[20];
    char flags[128];
    char ssid[128];
};

struct accesspoint_info{
    struct scan_result ap_selected;
    char username[30];
    char password[30];
};

int enable_wifi();
void disable_wifi();
struct scan_result* wifi_scan_available();
int wifi_get_network_status();
int get_scan_result_code();
void *start_manual_scan(void (*callback)(struct scan_result*));
int get_manual_scan_state();
void *wait_for_init_scan(void (*callback)(struct scan_result*));
char *getCurrConnectedSSID();
void *start_manual_connect(struct accesspoint_info* pAPInfo);

void set_connecting_msg_callback(void (*gui_msg_callback)(int, char*));

#endif  // WIFIMANAGER_H_

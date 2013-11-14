#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>

#define LOG_TAG "R_WifiManager"
#include "cutils/log.h"
#include "cutils/properties.h"
#include "wifimanager.h"
#include "wifimanager_private.h"
#include "hardware_legacy/wifi.h"

#define wifi_command  thread_secure_wifi_command

extern int ifc_enable(const char *ifname);
extern int ifc_disable(const char *ifname);
extern int ifc_clear_addresses(const char *name);
extern int ifc_reset_connections(const char *ifname, int reset_mask);
extern int ifc_configure(const char *ifname, in_addr_t address,
                         uint32_t prefixLength, in_addr_t gateway,
                         in_addr_t dns1, in_addr_t dns2);

extern int dhcp_do_request(const char * const ifname,
                    const char *ipaddr,
                    const char *gateway,
                    uint32_t *prefixLength,
                    const char *dns[],
                    const char *server,
                    uint32_t *lease,
                    const char *vendorInfo,
                    const char *domains);

extern int dhcp_do_request_renew(const char * const ifname,
                    const char *ipaddr,
                    const char *gateway,
                    uint32_t *prefixLength,
                    const char *dns[],
                    const char *server,
                    uint32_t *lease,
                    const char *vendorInfo,
                    const char *domains);

extern int dhcp_stop(const char *ifname);
extern int dhcp_release_lease(const char *ifname);
extern char *dhcp_get_errmsg();

#define PROPERTY_VALUE_MAX 92
#define MAX_COMMAND_LENGTH 128

static void (*wifi_msg_callback)(int, char*);

#define WIFI_MSG_INFO_CALLBACK(...)   \
{                                                 \
ALOGD(__VA_ARGS__);					 		  \
char msg_for_callback[128];             	 	  \
sprintf(msg_for_callback, __VA_ARGS__);  	      \
wifi_msg_callback(0, msg_for_callback);           \
}

#define WIFI_MSG_ERR_CALLBACK(...)   \
{                                                 \
ALOGD(__VA_ARGS__);					 		  \
char msg_for_callback[128];             	 	  \
sprintf(msg_for_callback, __VA_ARGS__);  	      \
wifi_msg_callback(1, msg_for_callback);           \
}

static int runDHCP(const char* ifname)
{
    char ipaddr[PROPERTY_VALUE_MAX];
    uint32_t prefixLength;
    char gateway[PROPERTY_VALUE_MAX];
    char    dns1[PROPERTY_VALUE_MAX];
    char    dns2[PROPERTY_VALUE_MAX];
    char    dns3[PROPERTY_VALUE_MAX];
    char    dns4[PROPERTY_VALUE_MAX];
    const char *dns[5] = {dns1, dns2, dns3, dns4, NULL};
    char  server[PROPERTY_VALUE_MAX];
    uint32_t lease;
    char vendorInfo[PROPERTY_VALUE_MAX];
    char domains[PROPERTY_VALUE_MAX];

    ALOGD("stop dhcp for wlan0...");
    dhcp_stop("wlan0");
    ifc_clear_addresses("wlan0");

    //dhcp_do_request: start dhcpcd service to get ip address
    if(dhcp_do_request(ifname, ipaddr, gateway, &prefixLength, dns, server, &lease, vendorInfo, domains))
    {
        ALOGE("dhcp_do_request for wlan0 failed!");
        return -1;
    }

    //ifc_configure: use the dhcp info to configure interface
    if(ifc_configure(ifname, inet_addr(ipaddr), prefixLength, inet_addr(gateway), inet_addr(dns1), inet_addr(dns2)))
    {
        ALOGE("ifc_configure for wlan0 failed!");
        return -1;
    }

    return 0;
}

static int CommandOkay = 200;
static uint8_t sequence = 1;
static int setupDNS()
{
    int sock;
    const int one = 1;
    struct sockaddr_un proxy_addr;
    FILE* proxy = NULL;
    char command2netd[MAX_COMMAND_LENGTH];
    char code_buf[4], result_buf[128];
    struct in_addr in_addr;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        ALOGE("Create socket failed!");
        return -1;
    }
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sun_family = AF_UNIX;
    strlcpy(proxy_addr.sun_path, "/dev/socket/netd", sizeof(proxy_addr.sun_path));

    if (TEMP_FAILURE_RETRY(connect(sock,(const struct sockaddr*) &proxy_addr, sizeof(proxy_addr))) != 0)
    {
        ALOGE("Connecting to socket netd failed:%s", strerror(errno));
        goto err_exit;
    }
    ALOGD("Connected to socket netd!");

    //////////////////////////////////////////////////////////////////
    memset(command2netd, 0, MAX_COMMAND_LENGTH);
    char domains[PROPERTY_VALUE_MAX];
    char wifiserver[PROPERTY_VALUE_MAX];
    property_get("dhcp.wlan0.domain", domains, "");
    property_get("dhcp.wlan0.server", wifiserver, "");
    sprintf(command2netd,"%d resolver setifdns wlan0 %s %s", (sequence++)%100, domains, wifiserver);
    if (write(sock, command2netd, strlen(command2netd) + 1) < 0)
    {
        ALOGE("netd socket write cmd[setifdns] error: %s!", strerror(errno));
        goto err_exit;
    }
    if (read(sock, code_buf, sizeof(code_buf)) != sizeof(code_buf))
    {
        ALOGE("netd socket get cmd1 result code error: %s!", strerror(errno));
        goto err_exit;
    }
    code_buf[3]='\0';
    if ((int)strtol(code_buf, NULL, 10) != CommandOkay)
    {
        ALOGE("Command1 not OKay![%s", code_buf);
        read(sock, result_buf, sizeof(result_buf));
        ALOGE("%s]", result_buf);
        goto err_exit;
    }else
    {
        read(sock, result_buf, sizeof(result_buf));
        ALOGD("%s %s", code_buf, result_buf);
    }

    //////////////////////////////////////////////////////////////////
    memset(command2netd, 0, MAX_COMMAND_LENGTH);
    sprintf(command2netd,"%d resolver setdefaultif wlan0", (sequence++)%100);
    if (write(sock, command2netd, strlen(command2netd) + 1) < 0)
    {
        ALOGE("netd socket write cmd[setdefaultif] error: %s!", strerror(errno));
        goto err_exit;
    }
    if (read(sock, code_buf, sizeof(code_buf)) != sizeof(code_buf))
    {
        ALOGE("netd socket get cmd2 result code error: %s!", strerror(errno));
        goto err_exit;
    }
    code_buf[3]='\0';
    if ((int)strtol(code_buf, NULL, 10) != CommandOkay)
    {
        ALOGE("Command2 not OKay![%s", code_buf);
        read(sock, result_buf, sizeof(result_buf));
        ALOGE("%s]", result_buf);
        goto err_exit;
    }else
    {
        read(sock, result_buf, sizeof(result_buf));
        ALOGD("%s %s", code_buf, result_buf);
    }

    return 0;

err_exit:
    return -1;
}

static int setup_wifi_networks()
{
    //Run DHCP to get a valid ip address
    ALOGD("dhcp_do_request for wlan0...");
    if(runDHCP("wlan0"))
    {
        ALOGE("dhcp_do_request for wlan0 failed!");
        ALOGE("dhcp last error messaage:\n\t%s", dhcp_get_errmsg());
        return -2;
    }

    //Setup DNS service for the network
    ALOGD("setup dns for wlan0...");
    if(setupDNS())
    {
        ALOGE("setup dns for wlan0 failed!");
        return -3;
    }
    
    return 0;
}

static struct accesspoint_info *pSelectedAP = NULL;
static void setSelectedAP(struct accesspoint_info *p)
{
    pSelectedAP = p;
}
static struct accesspoint_info *getSelectedAP()
{
    return pSelectedAP;
}

static char curr_connected_ssid[128];
static void setCurrConnectedSSID(char* ssid)
{
    memset(curr_connected_ssid, 0, 128);
    strcpy(curr_connected_ssid, ssid);
    ALOGD("Set current connected SSID:%s", curr_connected_ssid);
}
char *getCurrConnectedSSID()
{
    return curr_connected_ssid;
}

//see encypt method define in wifimanager.h
static char wifi_encypt_method_name[ENCYPT_METHOD_MAX][20] =
{
    "WPA_EAP_CCMP",
    "WPA2_EAP_CCMP",
    "WPA_PSK_CCMP",
    "WPA2_PSK_CCMP",
    "WPA_PSK_CCMP_TKIP",
    "WPA2_PSK_CCMP_TKIP",
    "NONE"
};
static char wifi_key_mgmt_type[ENCYPT_METHOD_MAX][20] =
{
    "WPA-EAP IEEE8021X",
    "WPA-EAP IEEE8021X",
    "WPA-PSK",
    "WPA-PSK",
    "WPA-PSK",
    "WPA-PSK",
    "NONE"
};
////////////////////////////////////////////////////////////////////
// AutoManagerThread						                      //
////////////////////////////////////////////////////////////////////

extern pthread_cond_t scan_result_cond;
extern pthread_mutex_t scan_result_mutex;

pthread_cond_t connectAP_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t connectAP_mutex = PTHREAD_MUTEX_INITIALIZER;

static int wifi_state		 = DISABLED;
pthread_mutex_t NRQ_Mutex = PTHREAD_MUTEX_INITIALIZER;
sem_t sem, sem_conn_cmd_complete;

static void cmd_dummy_callback(void *params)
{
    ALOGD("%s:%s", __func__, (char*)params);
    return ;
}
static void cmd_add_network_callback(void *params)
{
    int networkId;
    char cmdbuf[MAX_REQUEST_BUFF_SIZE];

    char *replybuf = (char*)params;
    networkId = strtol(replybuf, NULL, 10);
    ALOGD("ADD_NETWORK cmd return: %d[networkId]", networkId);

    int ret;
    //2.0 set ssid
    memset(cmdbuf, 0, MAX_REQUEST_BUFF_SIZE);
    sprintf(cmdbuf, "SET_NETWORK %d ssid \"%s\"", networkId, (getSelectedAP()->ap_selected).ssid);
    pthread_mutex_lock(&NRQ_Mutex);
    ret = NewNetworkRequest(cmdbuf, cmd_dummy_callback);
    pthread_mutex_unlock(&NRQ_Mutex);
    if(ret == 0) sem_post(&sem);

    //2.1 set key_mgmt
    char * key_type = (getSelectedAP()->ap_selected).flags;
    memset(cmdbuf, 0, MAX_REQUEST_BUFF_SIZE);
    ALOGD("key_type:%s", key_type);
    if((strstr(key_type, "WPA-EAP-CCMP") != NULL) ||(strstr(key_type, "WPA2-EAP-CCMP") != NULL))
    {
        sprintf(cmdbuf, "SET_NETWORK %d key_mgmt %s", networkId, wifi_key_mgmt_type[WPA_EAP_CCMP]);
    }else if((strstr(key_type, "WPA-PSK-CCMP") != NULL) ||(strstr(key_type, "WPA2-PSK-CCMP") != NULL))
    {
        sprintf(cmdbuf, "SET_NETWORK %d key_mgmt %s", networkId, wifi_key_mgmt_type[WPA_PSK_CCMP]);
    }else
    {
        sprintf(cmdbuf, "SET_NETWORK %d key_mgmt NONE", networkId);
    }
    pthread_mutex_lock(&NRQ_Mutex);
    ret = NewNetworkRequest(cmdbuf, cmd_dummy_callback);
    if(ret == 0) sem_post(&sem);
    pthread_mutex_unlock(&NRQ_Mutex);

    //2.2 set id if need
    if((strstr(key_type, "WPA-EAP-CCMP") != NULL) ||(strstr(key_type, "WPA2-EAP-CCMP") != NULL))
    {
        memset(cmdbuf, 0, MAX_REQUEST_BUFF_SIZE);
        sprintf(cmdbuf, "SET_NETWORK %d identity \"%s\"", networkId, getSelectedAP()->username);
        pthread_mutex_lock(&NRQ_Mutex);
        ret = NewNetworkRequest(cmdbuf, cmd_dummy_callback);
        pthread_mutex_unlock(&NRQ_Mutex);
        if(ret == 0) sem_post(&sem);
    }

    //2.3 set password
    memset(cmdbuf, 0, MAX_REQUEST_BUFF_SIZE);
    if((strstr(key_type, "WPA-EAP-CCMP") != NULL) ||(strstr(key_type, "WPA2-EAP-CCMP") != NULL))
    {
        sprintf(cmdbuf, "SET_NETWORK %d password \"%s\"", networkId, getSelectedAP()->password);
        pthread_mutex_lock(&NRQ_Mutex);
        ret = NewNetworkRequest(cmdbuf, cmd_dummy_callback);
        pthread_mutex_unlock(&NRQ_Mutex);
        if(ret == 0) sem_post(&sem);
    }else if((strstr(key_type, "WPA-PSK-CCMP") != NULL) ||(strstr(key_type, "WPA2-PSK-CCMP") != NULL))
    {
        sprintf(cmdbuf, "SET_NETWORK %d psk \"%s\"", networkId, getSelectedAP()->password);
        pthread_mutex_lock(&NRQ_Mutex);
        ret = NewNetworkRequest(cmdbuf, cmd_dummy_callback);
        pthread_mutex_unlock(&NRQ_Mutex);
        if(ret == 0) sem_post(&sem);
    }

    //2.4 enable the selected network
    memset(cmdbuf, 0, MAX_REQUEST_BUFF_SIZE);
    pthread_mutex_lock(&NRQ_Mutex);
    sprintf(cmdbuf, "SELECT_NETWORK %d", networkId);
    ret = NewNetworkRequest(cmdbuf, cmd_dummy_callback);
    if(ret == 0) sem_post(&sem);
    pthread_mutex_unlock(&NRQ_Mutex);

    //2.5 save config
    memset(cmdbuf, 0, MAX_REQUEST_BUFF_SIZE);
    pthread_mutex_lock(&NRQ_Mutex);
    sprintf(cmdbuf, "SAVE_CONFIG");
    ret = NewNetworkRequest(cmdbuf, cmd_dummy_callback);
    if(ret == 0) sem_post(&sem);
    pthread_mutex_unlock(&NRQ_Mutex);

    //all need command send out
/*
    pthread_mutex_lock(&connectAP_mutex);
    pthread_cond_signal(&connectAP_cond);
    pthread_mutex_unlock(&connectAP_mutex);
*/
    sem_post(&sem_conn_cmd_complete);
    ALOGD("Connecting command all sendout, connecting is ongoing in background!");

    return ;
}
static void cmd_signal_poll_callback(void* params)
{
    char *replybuf = (char*)params;
    /*
     * Format :
     * RSSI=-58
     * LINKSPEED=39
     * NOISE=9999
     * FREQUENCY=0
     */
    ALOGD("%s:Link Status:\n%s", __func__, replybuf);
    return ;
}
static void cmd_status_callback(void* params)
{
    char *replybuf = (char*)params;

    /*
     * bssid=cc:53:b5:f3:60:71
     * ssid=MIOffice
     * id=1
     * mode=station
     * pairwise_cipher=CCMP
     * group_cipher=CCMP
     * key_mgmt=WPA2/IEEE 802.1X/EAP
     * wpa_state=COMPLETED
     * ip_address=10.237.216.204
     * p2p_device_address=00:0a:f5:15:46:5d
     * address=00:0a:f5:15:46:5c
     * Supplicant PAE state=AUTHENTICATED
     * suppPortStatus=Authorized
     * EAP state=SUCCESS
     * selectedMethod=25 (EAP-PEAP)
     * EAP TLS cipher=AES128-SHA
     * EAP-PEAPv0 Phase2 method=MSCHAPV2
     */
    ALOGD("%s:Status:\n%s", __func__, replybuf);
    if(strstr(replybuf, "wpa_state=COMPLETED") != NULL)
    {
        char *p = NULL, *q = NULL;
        if((p=strstr(replybuf, "ssid=")) != NULL && (p=strstr(p+5, "ssid=")) != NULL) //notice the "bssid" exist and ahead of "ssid"
        {
            if((q=strchr(p, '\n')) != NULL || (q=strchr(p, '\r')) !=NULL)
            {
                char tmp_ssid[128];
                memset(tmp_ssid, 0, 128);
                memcpy(tmp_ssid, p+5, q-p-5);
                setCurrConnectedSSID(tmp_ssid);
                WIFI_MSG_INFO_CALLBACK("Wifi connected to %s.", getCurrConnectedSSID());
            }
        }
    }
    return ;
}

/*
 * flow: (if something miss please correct)
 * ->1,  add_network (will return networkId)
 * ->2.0,set_network networkId ssid "<ssid>"
 * ->2.1,set_network networkId key_mgmt <type>
 * ->2.2,set_network networkId identity "<id>"
 * ->2.3,set_network networkId password "<password>"
 * ->2.4,select_network networkId
 * ->2.5,save_config
 */
static int connect_to_accesspoint(struct accesspoint_info *pAPInfo)
{
    int ret;

    //set the selected AP we want to connect
    setSelectedAP(pAPInfo);

    sem_init(&sem_conn_cmd_complete, 0, 0);

    //step1: add network
    pthread_mutex_lock(&NRQ_Mutex);
    ret = NewNetworkRequest("ADD_NETWORK", cmd_add_network_callback);
    pthread_mutex_unlock(&NRQ_Mutex);
    //setp2: do 2.0-2.5 together
    //this steps will be done in the ADD_NETWORK callback, because we need the networkId

    if(ret == 0) sem_post(&sem);

/* abandon use condition signal to sync with threads, because we cannot sure wait before signal 
    pthread_mutex_lock(&connectAP_mutex);
    pthread_cond_wait(&connectAP_cond, &connectAP_mutex);
    pthread_mutex_unlock(&connectAP_mutex);
*/
    sem_wait(&sem_conn_cmd_complete);

    return 0;
}

static int connect_thread_started = 0;
static void ManualConnectThread(struct accesspoint_info *pAPInfo)
{

    if (!connect_thread_started) {
        connect_thread_started = 1;
    }else{
        WIFI_MSG_ERR_CALLBACK("Trying connecting...");
        goto out1;
    }

    if(pAPInfo == NULL || strcmp((pAPInfo->ap_selected).ssid, "") == 0)
    {
        ALOGE("No selected AP information.");
        goto out0;
    }else if(strcmp((pAPInfo->ap_selected).ssid, getCurrConnectedSSID()) == 0)
    {
        WIFI_MSG_ERR_CALLBACK("Already connected on this AP.");
        goto out0;
    }
    else if((strcmp(pAPInfo->password,"") == 0) &&/*&&password required*/
            (strcmp((pAPInfo->ap_selected).flags, "[ESS]") != 0))
    {
        WIFI_MSG_ERR_CALLBACK("Password required, but is Empty.");
        goto out0;
    }else if((strcmp(pAPInfo->username,"") == 0) && /*&&username required*/
             ((strstr((pAPInfo->ap_selected).flags, "WPA-EAP-CCMP") != NULL) ||
              (strstr((pAPInfo->ap_selected).flags, "WPA2-EAP-CCMP") != NULL)))
    {
        WIFI_MSG_ERR_CALLBACK("Username required, but is empty.");
        goto out0;
    }

    //try to connecting
    connect_to_accesspoint(pAPInfo);

out0:
    connect_thread_started = 0;
out1:
    return ;
}

void *start_manual_connect(struct accesspoint_info* pAPInfo)
{
    pthread_t manual_connect_thread;
    pthread_create(&manual_connect_thread, NULL, &ManualConnectThread, pAPInfo);
    ALOGD("Manual Connect thread started!");
    return NULL;
}
///////////////////////////////////////////////////////////////////////////////

static void PollingThread()
{
    int ret;

    while(1)
    {
        if(wifi_state == SCAN_COMPLETE || wifi_state == CONNECTING)
        {
            pthread_mutex_lock(&NRQ_Mutex);
            ret = NewNetworkRequest("STATUS", cmd_status_callback);
            pthread_mutex_unlock(&NRQ_Mutex);
            //manager thread can run to deal with the request
            if(ret == 0) sem_post(&sem);
            //poll every second
            sleep(1);
        }else if(wifi_state == CONNECTED)
        {
            pthread_mutex_lock(&NRQ_Mutex);
            if(strcmp(getCurrConnectedSSID(), "") == 0)
            {
                ret = NewNetworkRequest("STATUS", cmd_status_callback);     //a chance to set current ssid
                pthread_mutex_unlock(&NRQ_Mutex);
                //manager thread can run to deal with the request
                if(ret == 0) sem_post(&sem);
            }else
            {
                ret = NewNetworkRequest("SIGNAL_POLL", cmd_signal_poll_callback);
                pthread_mutex_unlock(&NRQ_Mutex);
                //manager thread can run to deal with the request
                if(ret == 0) sem_post(&sem);
            }
            //poll every 5 seconds
            sleep(5);
        }
        sleep(0);
    }
}

#define MAX_EVENT_QUEUE_SIZE   100 
static int head, tail;
static int EventQueue[MAX_EVENT_QUEUE_SIZE];
static pthread_mutex_t EQ_Mutex = PTHREAD_MUTEX_INITIALIZER;

static void EventLoopThread()
{
    char commandbuf[50]={0};
    char replybuf[256] = {0};
    int replybuflen = sizeof(replybuf)-1;

    head = tail = 0;

    while(1)
    {
		memset(replybuf, 0, sizeof(replybuf));
		wifi_wait_for_event("wlan0", replybuf, &replybuflen);

		if(strstr(replybuf, "CTRL-EVENT-BSS-ADDED")!=NULL)
		{
            //Event ignore
		    ALOGD("%s",replybuf);
		}else if(strstr(replybuf, "CTRL-EVENT-BSS-REMOVED")!=NULL)
		{
            //Event ignore
		    ALOGD("%s",replybuf);
		}else if(strstr(replybuf, "CTRL-EVENT-SCAN-RESULTS")!=NULL)
		{
		    ALOGD("%s", replybuf);
            //add scan complete event
            pthread_mutex_lock(&EQ_Mutex);
            EventQueue[tail] = SCAN_RESULTS_EVENT;
            tail = (tail+1)%MAX_EVENT_QUEUE_SIZE;
            if(tail == head)
            {
                head = (head+1)%MAX_EVENT_QUEUE_SIZE;
                ALOGE("Event overlapped, the head event will missed");
            }
            pthread_mutex_unlock(&EQ_Mutex);
		}else if(strstr(replybuf, "CTRL-EVENT-CONNECTED") != NULL)
		{
		    ALOGD("%s",replybuf);
            //add connected event
            pthread_mutex_lock(&EQ_Mutex);
            EventQueue[tail] = NETWORK_CONNECTION_EVENT;
            tail = (tail+1)%MAX_EVENT_QUEUE_SIZE;
            if(tail == head)
                ALOGE("Event overlapped, the head event may overlapped");
            pthread_mutex_unlock(&EQ_Mutex);
		}else if(strstr(replybuf, "CTRL-EVENT-DISCONNECTED")!=NULL)
		{
		    ALOGD("%s",replybuf);
            //add disconnected event
            pthread_mutex_lock(&EQ_Mutex);
            EventQueue[tail] = NETWORK_DISCONNECTION_EVENT;
            tail = (tail+1)%MAX_EVENT_QUEUE_SIZE;
            if(tail == head)
                ALOGE("Event overlapped, the head event may overlapped");
            pthread_mutex_unlock(&EQ_Mutex);
		}else if(strstr(replybuf, "CTRL-EVENT-TERMINATING")!=NULL)
		{
		    ALOGD("%s",replybuf);
            //add wpa_supplicant terminating event
            pthread_mutex_lock(&EQ_Mutex);
            EventQueue[tail] = SUP_DISCONNECTION_EVENT;
            tail = (tail+1)%MAX_EVENT_QUEUE_SIZE;
            if(tail == head)
                ALOGE("Event overlapped, the head event may overlapped");
            pthread_mutex_unlock(&EQ_Mutex);
		}else if(strstr(replybuf, "Trying to associate with")!=NULL)     /*CTRL-EVENT-STATE-CHANGE state=5*/
		{
		    ALOGD("%s",replybuf);
            //add associating event
            pthread_mutex_lock(&EQ_Mutex);
            EventQueue[tail] = NETWORK_ASSOCIATING_EVENT;
            tail = (tail+1)%MAX_EVENT_QUEUE_SIZE;
            if(tail == head)
                ALOGE("Event overlapped, the head event may overlapped");
            pthread_mutex_unlock(&EQ_Mutex);
		}else if(strstr(replybuf, "CTRL-EVENT-EAP-STARTED")!=NULL)
		{
		    ALOGD("%s",replybuf);
            //add authenticating event, some case may not have this.
            pthread_mutex_lock(&EQ_Mutex);
            EventQueue[tail] = NETWORK_AUTHENTICATING_EVENT;
            tail = (tail+1)%MAX_EVENT_QUEUE_SIZE;
            if(tail == head)
                ALOGE("Event overlapped, the head event may overlapped");
            pthread_mutex_unlock(&EQ_Mutex);
		}else if(strstr(replybuf, "CTRL-EVENT-STATE-CHANGE")!=NULL)
		{
		    //ignore the event.
		    ALOGD("%s",replybuf);
		}else
		{
		    //ignore the event.
		    ALOGD("%s",replybuf);
		}
        //manager thread can run to deal with the event
        sem_post(&sem);
    }
}

#define COMMON_REPLY_SIZE   512
#define MAX_REPLY_SIZE      4096

static int automanager_started   = 0;

// wait for events and signal waiters when appropriate
static int AutoManagerThread(void * params)
{
    char commandbuf[50]={0};
    char replybuf[512] = {0};
    int replybuflen = sizeof(replybuf)-1;

    int ret = 0;

    if (!automanager_started) {
        automanager_started = 1;
    }else{
        ALOGE("Seems AutoManager already running");
        goto out1;
    }

    sem_init(&sem, 0, 0);

    pthread_t polling_thread;
    pthread_create(&polling_thread, NULL, &PollingThread, NULL);
    pthread_t eventloop_thread;
    pthread_create(&eventloop_thread, NULL, &EventLoopThread, NULL);

    while(1)
    {
        //check if there something to do
        sem_wait(&sem);

        struct NetworkRequest *request;
        request = GetPendingRequest();
        if(request != NULL)
        {
            //some command will set the reply length even to short, need reset every time!!!
            replybuflen = sizeof(replybuf)-1;

            memset(replybuf, 0, sizeof(replybuf));
            ALOGD("Sending Command %s to wlan0.", request->cmdbuf);
            if(wifi_command("wlan0", request->cmdbuf, replybuf, &replybuflen) == 0)
            {
                // Strip off trailing newline
                if (replybuflen > 0 && replybuf[replybuflen-1] == '\n')
                    replybuf[replybuflen-1] = '\0';
                else
                    replybuf[replybuflen] = '\0';

                if(request->RequestCallback != NULL)
                {
                    (request->RequestCallback)(replybuf);
                }

                pthread_mutex_lock(&NRQ_Mutex);
                NRQRequestDone(request->cmdbuf);
                pthread_mutex_unlock(&NRQ_Mutex);
            }
        }
        
        if( head != tail)
        {
            pthread_mutex_lock(&EQ_Mutex);
            switch (EventQueue[head])
            {
                case SCAN_RESULTS_EVENT:
                    if(wifi_state == ENABLED)
                        wifi_state = SCAN_COMPLETE;
                    pthread_mutex_lock(&scan_result_mutex);
                    pthread_cond_signal(&scan_result_cond);
                    pthread_mutex_unlock(&scan_result_mutex);
                    break;

                case NETWORK_CONNECTION_EVENT:
                    ALOGD("connected event, wifi state:%d", wifi_state);
                    //auto setup network
		            if(wifi_state == CONNECTING)
		            {
                        wifi_state = CONNECTING;
		                setup_wifi_networks();
		                wifi_state = CONNECTED;
		            }
                    break;
                case NETWORK_ASSOCIATING_EVENT:
                    wifi_state = CONNECTING;
                    WIFI_MSG_INFO_CALLBACK("trying connecting...");
                    //something todo
                    break;
                case NETWORK_AUTHENTICATING_EVENT:
                    //TODO deal with this?
                    break;
                case NETWORK_DISCONNECTION_EVENT:
                    wifi_state = DISCONNECTED;
                    setCurrConnectedSSID("");
                    WIFI_MSG_INFO_CALLBACK("Wifi disconnected.");
                    //something todo
                    break;
                case SUP_DISCONNECTION_EVENT:
                    //something todo
                    break;
                default:
                    //todo
                    break;
            }
            head = (head+1)%MAX_EVENT_QUEUE_SIZE;
            pthread_mutex_unlock(&EQ_Mutex);
        }

        if(wifi_state == DISABLED)
        {
            ALOGD("detect wifi disabled cmd, Automanager will exit.");
            break;
        }
    }

    sem_destroy(&sem);
out0:
    automanager_started = 0;
out1:
    return ret;
}

static void *start_autoManager()
{
    pthread_t auto_manager_thread;
    pthread_create(&auto_manager_thread, NULL, &AutoManagerThread, NULL);
    ALOGD("AutoManager thread started!");
    return NULL;
}
////////////////////////////////////////////////////////////////////

int enable_wifi()
{
    int ret = 0;
    wifi_state = ENABLING;
    ALOGD("load wlan driver...");
    wifi_load_driver();
    ALOGD("start supplicant...");
    if(wifi_start_supplicant(1) != 0)
    {
        ALOGE("start supplicant failed!");
        ret = -1;
        goto error_exit;
    }

    int count = 100;
    struct stat buf;
    while((count-->0) && (stat("/dev/socket/wpa_wlan0",&buf)!=0)) usleep(100);
    if(count==0)
    {
        ALOGE("WPA Supplicant not initialized, not wait and exit.");
        ret = -1;
        goto error_exit;
    }

    ALOGD("connect supplicant wlan0...");
    if(wifi_connect_to_supplicant("wlan0") != 0)
    {
        ALOGE("connect supplicant wlan0 failed!");
        ret = -2;
        goto error_exit;
    }
    ALOGD("connect supplicant p2p0...");
    if(wifi_connect_to_supplicant("p2p0") != 0)
    {
        ALOGE("connect supplicant p2p0 failed!");
        ret = -3;
        goto error_exit;
    }
  
    wifi_state = ENABLED;
    WIFI_MSG_INFO_CALLBACK("Wifi enabled.");
    start_autoManager();

    return 0;

error_exit:
    WIFI_MSG_ERR_CALLBACK("Wifi enable fail.");
    wifi_state = DISABLED;
    return ret;
}

void disable_wifi()
{
    wifi_state = DISABLING;

    ALOGD("stop dhcp for wlan0...");
    dhcp_stop("wlan0");
    ifc_disable("wlan0");
    ifc_clear_addresses("wlan0");

    ALOGD("stop supplicant...");
    if(wifi_stop_supplicant(1) != 0)
    {
        ALOGE("stop supplicant failed!");
    }

    ALOGD("unload wlan driver...");
    wifi_unload_driver();

    wifi_state = DISABLED;
    WIFI_MSG_INFO_CALLBACK("Wifi diabled.");
    //disable wifi also a event automanager should check.
    sem_post(&sem);

    return ;
}

int wifi_get_network_status()
{
    return wifi_state;
}

void set_connecting_msg_callback(void (*gui_msg_callback)(int, char*))
{
    wifi_msg_callback = gui_msg_callback;
    //WIFI_MSG_INFO_CALLBACK("setting wifi_msg_callback OK.");
    return ;
}

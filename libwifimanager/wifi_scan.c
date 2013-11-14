#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>

#define LOG_TAG "R_WifiScaner"
#include "cutils/log.h"
#include "wifimanager.h"
#include "hardware_legacy/wifi.h"

#define ID_STR         "id"
#define BSSID_STR      "bssid"
#define FREQ_STR       "freq"
#define LEVEL_STR      "level"
#define TSF_STR        "tsf"
#define FLAGS_STR      "flags"
#define SSID_STR       "ssid"
#define DELIMITER_STR  "===="
#define END_STR        "####"

#define MAX_SSID_LENG  128
#define MAX_LINE_LENG  138

#define PARSE_OK       0
#define NO_RESULT      1
#define PARSE_ERROR    2
#define SCAN_BUF_ERROR 3

#define MAX_STORE_ENTRY 8

#define wifi_command  thread_secure_wifi_command

/**
 * Format:
 * id=1
 * bssid=68:7f:76:d7:1a:6e
 * freq=2412
 * level=-44
 * tsf=1344626243700342
 * flags=[WPA2-PSK-CCMP][WPS][ESS]
 * ssid=zfdy
 * ====
 * id=2
 * bssid=68:5f:74:d7:1a:6f
 * freq=5180
 * level=-73
 * tsf=1344626243700373
 * flags=[WPA2-PSK-CCMP][WPS][ESS]
 * ssid=zuby
 * ====
 */

//store the scan result
static int scan_result_code = SCAN_NOT_START;
static struct scan_result scanres[8];

static int parseScanResult(const char * scan_buf)
{
    char tmpline[MAX_LINE_LENG], tmpstr1[10], tmpstr2[MAX_SSID_LENG];
    char *pStart = NULL, *pSplit = NULL, *psubSplit = NULL;
    int ret = PARSE_OK, count = 0;

    if(strlen(scan_buf)==0) return NO_RESULT;

    struct scan_result tmp_result;
    memset(&tmp_result, 0, sizeof(struct scan_result));

    memset(scanres, 0, sizeof(struct scan_result)*8);

    pStart = scan_buf;
    pSplit = strchr(pStart, '\n');
    for(; pSplit != NULL; pSplit = strchr(pStart, '\n'))
    {
        if((pSplit-pStart) >= MAX_LINE_LENG)
        {
            ALOGE("%s: the line is too long!", __func__);
            ret = SCAN_BUF_ERROR;
            break;
        }

        memset(tmpline, 0, MAX_LINE_LENG);
        strncpy(tmpline, pStart, pSplit-pStart);
        if((strcmp(DELIMITER_STR, tmpline)==0) || (strcmp(END_STR, tmpline)==0))
        {
            //go to new line
            pStart = pSplit+1;
            continue;
        }

        psubSplit = strchr(pStart, '=');
        if((psubSplit == NULL)||(psubSplit==pStart)||(pSplit - psubSplit)==1)
        {
            ret = SCAN_BUF_ERROR;
            ALOGE("%s: something miss with the scan result!", __func__);
            break;
        }
        memset(tmpstr1, 0, 10);
        strncpy(tmpstr1, pStart, psubSplit-pStart);
        if(strcmp(ID_STR, tmpstr1)==0)
        {
            memset(tmpstr2, 0, MAX_SSID_LENG);
            strncpy(tmpstr2, (char*)(psubSplit+1), pSplit-psubSplit+1);
            tmp_result.id = strtol(tmpstr2, NULL, 10);
        }else if(strcmp(BSSID_STR, tmpstr1)==0)
        {
            strncpy(tmp_result.bssid, (char*)(psubSplit+1), pSplit-psubSplit-1);
        }else if(strcmp(FREQ_STR, tmpstr1)==0)
        {
            memset(tmpstr2, 0, MAX_SSID_LENG);
            strncpy(tmpstr2, (char*)(psubSplit+1), pSplit-psubSplit-1);
            tmp_result.frequency = strtol(tmpstr2, NULL, 10);
        }else if(strcmp(LEVEL_STR, tmpstr1)==0)
        {
            memset(tmpstr2, 0, MAX_SSID_LENG);
            strncpy(tmpstr2, (char*)(psubSplit+1), pSplit-psubSplit-1);
            tmp_result.level = strtol(tmpstr2, NULL, 10);
        }else if(strcmp(TSF_STR, tmpstr1)==0)
        {
            strncpy(tmp_result.tsf, (char*)(psubSplit+1), pSplit-psubSplit-1);
        }else if(strcmp(FLAGS_STR, tmpstr1)==0)
        {
            strncpy(tmp_result.flags, (char*)(psubSplit+1), pSplit-psubSplit-1);
        }else if(strcmp(SSID_STR, tmpstr1)==0)
        {
            strncpy(tmp_result.ssid, (char*)(psubSplit+1), pSplit-psubSplit-1);
            //ssid should at the last.
            ALOGD("[Scanned]:\nid=%d\nbssid=%s\nfrequency=%d\nlevel=%d\ntsf=%s\nflags=%s\nssid=%s",
                          tmp_result.id, tmp_result.bssid, tmp_result.frequency,
                          tmp_result.level, tmp_result.tsf, tmp_result.flags, tmp_result.ssid);
            int i = 0;
            while(i<count)
            {
                if(strcmp(scanres[i].ssid, tmp_result.ssid) == 0)
                    break;
                i++;
            }
            if(i == count)
            {
                memcpy(&(scanres[count]), &tmp_result, sizeof(struct scan_result));
                count++;
            }else
            {
                if(scanres[count].level < tmp_result.level)
                    memcpy(&(scanres[count]), &tmp_result, sizeof(struct scan_result));
            }
            memset(&tmp_result, 0, sizeof(struct scan_result));
            if(count >= MAX_STORE_ENTRY) break;

        }else
        {
            //do not care this?
            ALOGD("%s:%s", __func__, tmpline);
        }
        //go to new line
        pStart = pSplit+1;
    }

    return ret;
}

////////////////////////////////////////////////////////////////////
// Manual Manual Scan Thread                    				  //
////////////////////////////////////////////////////////////////////

extern pthread_mutex_t NRQ_Mutex;
extern sem_t sem;

static struct scan_result* get_curr_scan_results()
{
    char commandbuf[50];
    char reply[4096];
    size_t reply_len = sizeof(reply) - 1;
    snprintf(commandbuf, 30, "BSS RANGE=0- MASK=0x21987");
    if(wifi_command("wlan0", commandbuf, reply, &reply_len)!=0)
    {
        ALOGE("wifi_command error");
        return NULL;
    }else
    {
        // Strip off trailing newline
        if (reply_len > 0 && reply[reply_len-1] == '\n')
            reply[reply_len-1] = '\0';
        else
            reply[reply_len] = '\0';
    }

    if(parseScanResult(reply) == PARSE_OK)
        return scanres;
    else
        return NULL;
}

pthread_cond_t scan_result_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t scan_result_mutex = PTHREAD_MUTEX_INITIALIZER;

static int Manual_Scan_started   = 0;
static int ManualScanThread(void (*callback)(struct scan_result*))
{
    int ret;
    char commandbuf[50]={0};
    char replybuf[512] = {0};
    int  replybuflen = sizeof(replybuf)-1;
    
    if (!Manual_Scan_started) {
        Manual_Scan_started = 1;
    }else{
        ALOGE("Seems a manual scan still in process");
        scan_result_code = ALREADY_IN_PROCESS;
        if(callback!=NULL) callback(NULL);
        goto out1;
    }

    pthread_mutex_lock(&NRQ_Mutex);
    ret = NewNetworkRequest("SCAN TYPE=ONLY", NULL);
    pthread_mutex_unlock(&NRQ_Mutex);
    if(ret == 0)  sem_post(&sem);

    struct timespec to;
    to.tv_sec = time(NULL) + 10;  
    to.tv_nsec = 0;  

    pthread_mutex_lock(&scan_result_mutex);
    ALOGD("wait for scan complete signal");
    ret = pthread_cond_timedwait(&scan_result_cond, &scan_result_mutex, &to);
    pthread_mutex_unlock(&scan_result_mutex);

    if(ret == ETIMEDOUT)   
    {
        scan_result_code = SCAN_TIMEOUT;
        if(callback!=NULL) callback(NULL);
        goto out0;
    }
    
    if(get_curr_scan_results() != NULL)
    {
        scan_result_code = SCAN_OK;
	    if(callback!=NULL) callback(scanres);
    }else
    {
        scan_result_code = SCAN_ERROR;
        if(callback!=NULL) callback(NULL);
    }

out0:
    Manual_Scan_started = 0;
out1:
    return NULL;
}

void *start_manual_scan(void (*callback)(struct scan_result*))
{
    pthread_t manual_scan_thread;
    pthread_create(&manual_scan_thread, NULL, &ManualScanThread, callback);
    ALOGD("Manual Scan thread started!");
    return NULL;
}
////////////////////////////////////////////////////////////////////

static int InitScanThread(void (*callback)(struct scan_result*))
{
    char commandbuf[50]={0};
    char replybuf[512] = {0};
    int  replybuflen = sizeof(replybuf)-1;

    struct timespec to;
    to.tv_sec = time(NULL) + 10;  
    to.tv_nsec = 0;  

    pthread_mutex_lock(&scan_result_mutex);
    ALOGD("wait for scan complete signal");
    int ret = pthread_cond_timedwait(&scan_result_cond, &scan_result_mutex, &to);
    pthread_mutex_unlock(&scan_result_mutex);

    if(ret == ETIMEDOUT)   
    {
        scan_result_code = SCAN_TIMEOUT;
        if(callback!=NULL) callback(NULL);
        return NULL;
    }
     
    if(get_curr_scan_results() != NULL)
    {
        scan_result_code = SCAN_OK;
	    if(callback!=NULL) callback(scanres);
    }else
    {
        scan_result_code = SCAN_ERROR;
        if(callback!=NULL) callback(NULL);
    }

    return NULL;
}

void *wait_for_init_scan(void (*callback)(struct scan_result*))
{
    pthread_t init_scan_thread;
    pthread_create(&init_scan_thread, NULL, &InitScanThread, callback);
    ALOGD("wait for initial scan result!");
    return NULL;
}

////////////////////////////////////////////////////////////////////
int get_scan_result_code()
{
   return scan_result_code;
}

//in scan: 1
int get_manual_scan_state()
{
   return Manual_Scan_started;
}


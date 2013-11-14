#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include "cutils/log.h"
#include "wifimanager_private.h"
#include "hardware_legacy/wifi.h"

#define LOG_TAG "R_WifiManager"

static struct NetworkRequest  *NRQ = NULL;
static struct EventHandler    *EventHandlerList = NULL;

int NewNetworkRequest(const char* cmdbuf, Func RequestCallback)
{ 
    if( (cmdbuf == NULL) || (strlen(cmdbuf) > MAX_REQUEST_BUFF_SIZE) )
    {
        ALOGE("Command is NULL or too large.");
        return -1;
    }

    if(NRQ == NULL)
    {
        NRQ =  (struct NetworkRequest*)malloc(sizeof(struct NetworkRequest));
        memset(NRQ, 0, sizeof(struct NetworkRequest));

        NRQ->prev = NULL;
        NRQ->next = NULL;
        NRQ->RequestCallback = RequestCallback;
        strcpy(NRQ->cmdbuf, cmdbuf);
        ALOGD("New Request [%s] Added at head...", cmdbuf);
        return 0;
    }

    struct NetworkRequest *p = NRQ;
    for(; p != NULL; p = p->next)
    {
        if(strcmp(p->cmdbuf, cmdbuf) == 0)
        {
            ALOGE("Previous command '%s' still in process, this will be ignored.", cmdbuf);
            return -1;
        }
    }
    if(p == NULL)
    {
        struct NetworkRequest *q = NRQ;
        while(q->next != NULL) q = q->next;

        q->next = malloc(sizeof(struct NetworkRequest));
        memset(q->next, 0, sizeof(struct NetworkRequest));

        q->next->next = NULL;
        q->next->prev = q;
        strcpy(q->next->cmdbuf, cmdbuf);
        q->next->RequestCallback = RequestCallback;
        ALOGD("New Request [%s] Added ...", cmdbuf);
    }
    else
        ALOGE("New Request Error!");   //Should not here

    return 0;
}

struct NetworkRequest * GetPendingRequest()
{
    return NRQ;
}

int NRQRequestDone(const char* cmdbuf)
{
    struct NetworkRequest *q = NRQ;

    if(q == NULL)
    {
        ALOGE("Request done called, but no request pending in queue.");
        return -1;
    }
    while(q != NULL)
    {
        if(strcmp(q->cmdbuf, cmdbuf) == 0)
        {
            if(q->prev == NULL)      //the request at head done
			{
                if(q->next != NULL)
                    q->next->prev = NULL;
                NRQ = q->next;
                free(q);
            }else if(q->next == NULL)//the request at tail done
            {
                q->prev->next = NULL;
                free(q);
            }else                    //the request at middle done
            {
                q->prev->next = q->next;
                q->next->prev = q->prev;
                free(q);
            }
            ALOGD("Request[%s] removed from queue.", cmdbuf);
            return 0;
        }
        q = q->next;
    }
    ALOGE("Command '%s' done, but not find in NRQ queue.", cmdbuf);
    return -1;
}

int RegisterEventHandler(int Event, Func EventHandler)
{
    if(EventHandlerList == NULL)
    {
        EventHandlerList = (struct EventHandler*)malloc(sizeof(struct EventHandler));
        memset(EventHandlerList, 0, sizeof(struct EventHandler));

        EventHandlerList->prev = NULL;
        EventHandlerList->next = NULL;
        EventHandlerList->EventHandler = EventHandler;
        EventHandlerList->EventType = Event;

        return 0;
    }

    struct EventHandler *p = EventHandlerList;
    for(; p != NULL; p = p->next)
    {
        if( p->EventType == Event)
        {
            ALOGE("EventType %d already registered, this will be ignored.", Event);
            return -1;
        }
    }
    if(p == NULL)	//add to the last
    {
        struct EventHandler *q = EventHandlerList;
        while(q->next != NULL) q = q->next;

        q->next = (struct EventHandler *)malloc(sizeof(struct EventHandler));
        memset(q->next, 0, sizeof(struct EventHandler));

        q->next->next = NULL;
        q->next->prev = q;
        q->next->EventType = Event;
        q->next->EventHandler = EventHandler;
    }
    else
        ALOGE("Register Event Handler Error!");   //Should not here

    return 0;
}

Func GetEventHandler(int Event)
{
    struct EventHandler *q = EventHandlerList;

    if(q == NULL)
    {
        ALOGE("No registered event handler.");
        return NULL;
    }
    while(q != NULL)
    {
        if( q->EventType == Event )
        {
            ALOGD("Event type %d handler found", Event);
            return q->EventHandler;
        }
        q = q->next;
    }
    ALOGE("Event type %d not found registered.", Event);
    return NULL;
}

static pthread_mutex_t wifi_command_mutex = PTHREAD_MUTEX_INITIALIZER;
int thread_secure_wifi_command(const char *iface, const char *command, char *reply, size_t *reply_len)
{
    int ret;
    pthread_mutex_lock(&wifi_command_mutex);
    ret = wifi_command(iface, command, reply, reply_len);
    pthread_mutex_unlock(&wifi_command_mutex);
    return ret;
}


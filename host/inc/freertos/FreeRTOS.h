#pragma once
typedef void* QueueHandle_t; typedef int BaseType_t; typedef unsigned TickType_t;
#define pdTRUE 1
#define pdMS_TO_TICKS(x) (x)
QueueHandle_t xQueueCreate(int,int); BaseType_t xQueueSend(QueueHandle_t,const void*,TickType_t); BaseType_t xQueueReceive(QueueHandle_t,void*,TickType_t);
int xTaskCreatePinnedToCore(void(*)(void*),const char*,int,void*,int,void*,int); inline void vTaskDelay(TickType_t){}
typedef void* SemaphoreHandle_t;
#define portMAX_DELAY 0xFFFFFFFFu
inline SemaphoreHandle_t xSemaphoreCreateMutex(){ return (void*)1; } inline BaseType_t xSemaphoreTake(SemaphoreHandle_t,TickType_t){ return 1; } inline BaseType_t xSemaphoreGive(SemaphoreHandle_t){ return 1; }

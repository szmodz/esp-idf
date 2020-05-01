/* Hello World Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <stdio.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_spi_flash.h"
#include <esp_task.h>

#include <setjmp.h>

#define LUAI_NOIPA __attribute__((__noipa__))
#define LUAI_THROW(c)		longjmp((c)->b, 1)
#define LUAI_TRY(c,a)		if (setjmp((c)->b) == 0) { a }

typedef struct {
    jmp_buf b;
} jmp_ctx;

LUAI_NOIPA
static void pret(jmp_ctx *jc) {
    LUAI_THROW(jc);
}

LUAI_NOIPA
static void precurse(jmp_ctx *jc, int n) {
    if (n) precurse(jc, n - 1);
    else pret(jc);
}

LUAI_NOIPA
static void ptest(jmp_ctx *jc) {
    precurse(jc, 64);
}

LUAI_NOIPA
void pcall(void (*func)(jmp_ctx *ctx)) {
    jmp_ctx jc;
    LUAI_TRY(&jc,
        func(&jc);
    );
}

static void sjlj_task(void *ctx) {
    uint32_t start = xTaskGetTickCount();
    for (;;) {
        pcall(ptest);
        uint32_t end = xTaskGetTickCount();

        uint32_t dt = end - start;
        if (dt >= 1000) {
            start = end;

            printf("[%u] sjlj tick %d\n", end, (int)ctx);
        }

    }
}

void app_main(void)
{
    printf("Hello world!\n");

    /* Print chip information */
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    printf("This is %s chip with %d CPU cores, WiFi%s%s, ",
            CONFIG_IDF_TARGET,
            chip_info.cores,
            (chip_info.features & CHIP_FEATURE_BT) ? "/BT" : "",
            (chip_info.features & CHIP_FEATURE_BLE) ? "/BLE" : "");

    printf("silicon revision %d, ", chip_info.revision);

    printf("%dMB %s flash\n", spi_flash_get_chip_size() / (1024 * 1024),
            (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "embedded" : "external");

    printf("Free heap: %d\n", esp_get_free_heap_size());


    xTaskCreate(sjlj_task, "sjlj_task", 8192, (void *)0, ESP_TASK_MAIN_PRIO, NULL);
    xTaskCreate(sjlj_task, "sjlj_task", 8192, (void *)1, ESP_TASK_MAIN_PRIO, NULL);

}

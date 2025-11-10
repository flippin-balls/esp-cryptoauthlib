/*
 * Copyright 2021 Espressif Systems (Shanghai) CO LTD
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdio.h>
#include <string.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include <driver/uart.h>

#include "esp_console.h"
#include "esp_log.h"

#include "cryptoauthlib.h"
#include "atcacert/atcacert_client.h"
#include "atcacert/atcacert_pem.h"

#include "commands.h"
#include "handlers.h"
#include "ecu_console_interface.h"

#define CRYPT_BUF_LEN 1200
#define CRYPT_BUF_PUB_KEY_LEN ATCA_PUB_KEY_SIZE

#ifdef CONFIG_ECU_DEBUGGING
#define ECU_DEBUG_LOG ESP_LOGI
#else
#define ECU_DEBUG_LOG(...)
#endif /* MFG_DEBUG */

static const char *TAG = "secure_element";

static unsigned char crypt_buf_public_key[CRYPT_BUF_PUB_KEY_LEN];
static unsigned char crypt_buf_csr[CRYPT_BUF_LEN];
static unsigned char crypt_buf_cert[CRYPT_BUF_LEN];
// Slot6 IO protection key (loaded at runtime from S3)
static uint8_t slot6_secret[32] = {0};
static bool slot6_secret_loaded = false;

static esp_err_t register_init_device();
static esp_err_t register_get_version();
static esp_err_t register_print_chip_info();
static esp_err_t register_generate_key_pair();
static esp_err_t register_generate_csr();
static esp_err_t register_generate_pub_key();
static esp_err_t register_provide_cert_def();
static esp_err_t register_program_device_cert();
static esp_err_t register_program_signer_cert();
static esp_err_t register_write_config();
static esp_err_t register_read_config();
static esp_err_t register_is_config_locked();
static esp_err_t register_is_data_locked();
static esp_err_t register_lock_config_zone();
static esp_err_t register_lock_data_zone();
static esp_err_t register_write_data();
static esp_err_t register_write_enc_data();
static esp_err_t register_load_slot6_secret();
static device_status_t atca_cli_status_object;
esp_err_t register_command_handler()
{
    esp_err_t ret = register_init_device();
    ret |= register_get_version();
    ret |= register_print_chip_info();
    ret |= register_generate_key_pair();
    ret |= register_generate_csr();
    ret |= register_generate_pub_key();
    ret |= register_provide_cert_def();
    ret |= register_program_device_cert();
    ret |= register_program_signer_cert();
    ret |= register_write_config();
    ret |= register_read_config();
    ret |= register_is_config_locked();
    ret |= register_is_data_locked();
    ret |= register_lock_config_zone();
    ret |= register_lock_data_zone();
    ret |= register_write_data();
    ret |= register_load_slot6_secret();
    ret |= register_write_enc_data();
    return ret;
}

static esp_err_t init_device(int argc, char **argv)
{
    esp_err_t ret = ESP_ERR_INVALID_ARG;
    int err_code;
    atca_cli_status_object = BEGIN;
    char device_type[20] = {};

    if(argc == 3) {
        uint8_t i2c_sda_pin = atoi(argv[1]);
        uint8_t i2c_scl_pin = atoi(argv[2]);
        ESP_LOGI(TAG, "I2C pins selected are SDA = %d, SCL = %d", i2c_sda_pin, i2c_scl_pin);
        ret = init_atecc608a(device_type, i2c_sda_pin, i2c_scl_pin, &err_code);
    }

    ESP_LOGI(TAG, "Status: %s\n", ret ? "Failure" : "Success");
    atca_cli_status_object = ret ? ATECC_INIT_FAIL : ATECC_INIT_SUCCESS;

    if (ret == ESP_ERR_INVALID_ARG) {
        ESP_LOGE(TAG, "Reason: Invalid Usage");
    } else if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Initilization of ATECC failed, returned %02x\nPlease check that the appropriate I2C pin numbers are provided to the python script", err_code);
    } else {
        ECU_DEBUG_LOG(TAG, "ATECC608 Device Type: %s\n", device_type);
    }
    fflush(stdout);
    return ESP_OK;
}

static esp_err_t register_init_device()
{
    const esp_console_cmd_t cmd = {
            .command = "init",
            .help = "Initialize the ATECC chip on WROOM32SE"
                    "  locks config, data zone if not locked already"
                    "  Usage:init\n"
                    "  Example:init",
            .func = &init_device,
    };
    return esp_console_cmd_register(&cmd);
}

static esp_err_t print_chip_info(int argc, char **argv)
{
    esp_err_t ret = ESP_ERR_INVALID_ARG;
    int err_code;
    uint8_t sn[9] = {};
    if (atca_cli_status_object >= ATECC_INIT_SUCCESS) {
        ret = atecc_print_info(sn, &err_code);
        ESP_LOGI(TAG, "Status: %s\n", ret ? "Failure" : "Success");
    }
    if (atca_cli_status_object < ATECC_INIT_SUCCESS) {
        ESP_LOGE(TAG, "Please Initialize device before calling this function");
    } else if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Error in generating keys, returned %02x", err_code);
    } else {
        printf("\n Serial Number:\n");
        for (int count = 0; count < 9; count ++) {
            printf("%02x ", sn[count]);
        }
    }
    fflush(stdout);
    return ESP_OK;
}

static esp_err_t register_print_chip_info()
{
    const esp_console_cmd_t cmd = {
            .command = "print-chip-info",
            .help = "Print the Serial Number of the atecc608a chip"
                    "  Serial number is a 9 byte number, unique to every chip"
                    "  Usage:print-chip-info\n"
                    "  Example:print-chip-info",
            .func = &print_chip_info,
    };
    return esp_console_cmd_register(&cmd);
}

static esp_err_t generate_key_pair(int argc, char **argv)
{
    esp_err_t ret = ESP_ERR_INVALID_ARG;
    int err_code;
    if (atca_cli_status_object >= ATECC_INIT_SUCCESS) {
        if (argc == 2 && (atoi(argv[1]) < 3)) {
            ret = atecc_keygen(atoi(argv[1]), crypt_buf_public_key, CRYPT_BUF_PUB_KEY_LEN, &err_code);
        }
        ESP_LOGI(TAG, "Status: %s\n", ret ? "Failure" : "Success");
        atca_cli_status_object = ret ? KEY_PAIR_GEN_FAIL : KEY_PAIR_GEN_SUCCESS;
    }

    if (atca_cli_status_object < ATECC_INIT_SUCCESS) {
        ESP_LOGE(TAG, "Please Initialize device before calling this function");
    } else if (ret == ESP_ERR_INVALID_ARG) {
        ESP_LOGE(TAG, "Reason: Invalid Usage");
    } else if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Error in generating keys, returned %02x", err_code);
    } else {
        printf("\nPublic Key:\n");
        for (int count = 0; count < CRYPT_BUF_PUB_KEY_LEN; count ++) {
            printf("%02x", crypt_buf_public_key[count]);
        }
    }
    fflush(stdout);
    return ESP_OK;
}

static esp_err_t register_generate_key_pair()
{
    const esp_console_cmd_t cmd = {
            .command = "generate-keys",
            .help = "Generates an internal ECC private key inside the given slot of ATECC608"
                    "  returns its public key \n  By default only slots 0,1,2 are supported"
                    "  Usage: generate-keys <slot number>\n"
                    "  Example:\ngenerate-keys 0",
            .func = &generate_key_pair,
    };
    return esp_console_cmd_register(&cmd);
}


static esp_err_t generate_csr(int argc, char **argv)
{
    esp_err_t ret = ESP_ERR_INVALID_ARG;
    int err_code;
    if (atca_cli_status_object >= ATECC_INIT_SUCCESS) {
        if (argc == 1) {
            ret = atecc_csr_gen(crypt_buf_csr, CRYPT_BUF_LEN, &err_code);
        }
        ESP_LOGI(TAG, "Status: %s\n", ret ? "Failure" : "Success");
        atca_cli_status_object = ret ? CSR_GEN_FAIL : CSR_GEN_SUCCESS;
    }

    if (atca_cli_status_object < ATECC_INIT_SUCCESS) {
        ESP_LOGE(TAG, "Please Initialize device before calling this function");
    } else if (ret == ESP_ERR_INVALID_ARG) {
        ESP_LOGE(TAG, "Reason: Invalid Usage");
    } else if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Generating CSR failed, returned %02x, \nNote: please check that you have called \n generate_keys command on slot mentioned in cert_def_3_device_csr.c in component/cryptoauthlib/port/ \nat least once before you debug error code", err_code);
    } else {
        printf("\n%s", crypt_buf_csr);
    }
    fflush(stdout);
    return ESP_OK;
}

static esp_err_t register_generate_csr()
{
    const esp_console_cmd_t cmd = {
            .command = "generate-csr",
            .help = "Generates a CSR from private key in specified slot."
                    "  Private key must be genereated at least once on specified slot for this command"
                    "  to succeed."
                    "  Information such as CN,O as well as the priv key slot etc. is picked\n"
                    "  from cert_def generated by python script.\n"
                    "  Usage:generate-csr\n"
                    "  Example:\n "
                    "  generate-csr ",
            .func = &generate_csr,
    };
    return esp_console_cmd_register(&cmd);
}

static esp_err_t generate_pub_key(int argc, char **argv)
{
    esp_err_t ret = ESP_ERR_INVALID_ARG;
    int err_code;
    if (atca_cli_status_object >= ATECC_INIT_SUCCESS) {
        if (argc == 2) {
            ret = atecc_gen_pubkey(atoi(argv[1]), crypt_buf_public_key, CRYPT_BUF_PUB_KEY_LEN, &err_code);
        }
        ESP_LOGI(TAG, "Status: %s\n", ret ? "Failure" : "Success");
        atca_cli_status_object = ret ? PUBKEY_GEN_FAIL : PUBKEY_GEN_SUCCESS;
    }

    if (atca_cli_status_object < ATECC_INIT_SUCCESS) {
        ESP_LOGE(TAG, "Please Initialize device before calling this function");
    } else if (ret == ESP_ERR_INVALID_ARG) {
        ESP_LOGE(TAG, "Reason: Invalid Usage");
    } else if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Generating Public key failed, returned %02x, \nNote: please check that you have called\ngenerate_keys command on slot %d at least once before you debug error code", err_code, atoi(argv[1]));
    } else {
        printf("\nPublic Key:\n");
        for (int count = 0; count < CRYPT_BUF_PUB_KEY_LEN; count ++) {
            printf("%02x ", crypt_buf_public_key[count]);
        }
    }
    fflush(stdout);
    return ESP_OK;
}

static esp_err_t register_generate_pub_key()
{
    const esp_console_cmd_t cmd = {
            .command = "generate-pubkey",
            .help = "Generates a public key from the present key-pair"
                    "  generate-keys must be executed at least once on specified slot to succeed\n"
                    "  Usage:generate-pubkey <slot number> "
                    "  Example:\n"
                    "  generate-pubkey 0",
            .func = &generate_pub_key,
    };
    return esp_console_cmd_register(&cmd);
}

static esp_err_t provide_cert_def(int argc, char **argv)
{
    int ret = -1;
    if (atca_cli_status_object >= ATECC_INIT_SUCCESS) {
        if (argc == 2) {
            if (atoi(argv[1]) == 0) {
                ret = get_cert_def(crypt_buf_cert, CRYPT_BUF_LEN, CERT_TYPE_DEVICE);
            } else if (atoi(argv[1]) == 1) {
                ret = get_cert_def(crypt_buf_cert, CRYPT_BUF_LEN, CERT_TYPE_SIGNER);
            }
        }
        ESP_LOGI(TAG, "Status: %s\n", ret ? "Failure" : "Success");
        atca_cli_status_object = ret ?  GET_CERT_DEF_SUCCESS : GET_CERT_DEF_FAIL;
    }

    if (atca_cli_status_object < ATECC_INIT_SUCCESS) {
        ESP_LOGE(TAG, "Please Initialize device before calling this function");
    } else if (ret == ESP_ERR_INVALID_ARG) {
        ESP_LOGE(TAG, "Reason: Invalid Usage");
    } else if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failure");
    }
    fflush(stdout);
    return ESP_OK;
}

static esp_err_t register_provide_cert_def()
{
    const esp_console_cmd_t cmd = {
            .command = "provide-cert-def",
            .help = "Provides the cert definition of device cert of signer cert to the atecc chip"
                    "  Usage:provide-cert-def 0 for device cert\n and provide cert def 1 for signer cert\n"
                    "  Example:provide-cert-def 0(device)",
            .func = &provide_cert_def,
    };
    return esp_console_cmd_register(&cmd);
}

static esp_err_t program_device_cert(int argc, char **argv)
{
    esp_err_t ret = ESP_ERR_INVALID_ARG;
    int err_code;
    uint32_t received_crc = 0;

    if (atca_cli_status_object >= CSR_GEN_SUCCESS) {
        if (argc == 2 || argc == 3) { // Expecting lock flag and optional CRC32
            bool lock = false;

            if (atoi(argv[1]) == 1) {
                lock = true;
            }

            if (argc == 3) {
                received_crc = (uint32_t)strtoul(argv[2], NULL, 10);
            }

            // Pass CRC32 to atecc_input_cert
            ret = atecc_input_cert(crypt_buf_cert, CRYPT_BUF_LEN, CERT_TYPE_DEVICE, lock, &err_code, received_crc);
        } else {
            ESP_LOGE(TAG, "Invalid arguments. Expected usage: program-dev-cert <lock> [CRC32]");
        }

        ESP_LOGI(TAG, "Status: %s\n", ret ? "Failure" : "Success");
        atca_cli_status_object = ret ? PROGRAM_CERT_FAIL : PROGRAM_CERT_SUCCESS;
    }

    if (atca_cli_status_object < CSR_GEN_SUCCESS) {
        ESP_LOGE(TAG, "Generate the CSR before calling this function.");
    } else if (ret == ESP_ERR_INVALID_ARG) {
        ESP_LOGE(TAG, "Reason: Invalid Usage");
    } else if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Programming device cert failed, returned %d", err_code);
    }

    fflush(stdout);
    return ESP_OK;
}

static esp_err_t register_program_device_cert()
{
    const esp_console_cmd_t cmd = {
            .command = "program-dev-cert",
            .help = "Sets the UART command handler to input the device certificate.\n"
                    "  Usage:program-dev-cert lock\n",
            "  Example: program-dev-cert 0 CRC_VALUE",
            .func = &program_device_cert,
    };
    return esp_console_cmd_register(&cmd);
}

static esp_err_t program_signer_cert(int argc, char **argv)
{
    esp_err_t ret = ESP_ERR_INVALID_ARG;
    int err_code;
    uint32_t received_crc = 0;
    if (atca_cli_status_object >= CSR_GEN_SUCCESS) {
        if (argc == 2 || argc == 3) {
            bool lock = false;

            if (atoi(argv[1]) == 1) {
                lock = true;
            }

            if (argc == 3) {
                received_crc = (uint32_t)strtoul(argv[2], NULL, 10);
            }

            // Pass CRC32 to atecc_input_cert
            ret = atecc_input_cert(crypt_buf_cert, CRYPT_BUF_LEN, CERT_TYPE_SIGNER, lock, &err_code, received_crc);
        } else {
            ESP_LOGE(TAG, "Invalid arguments. Expected usage: program-signer-cert <lock> [CRC32]");
        }

        ESP_LOGI(TAG, "Status: %s\n", ret ? "Failure" : "Success");
        atca_cli_status_object = ret ? PROGRAM_CERT_FAIL : PROGRAM_CERT_SUCCESS;
    }
    if (atca_cli_status_object < CSR_GEN_SUCCESS) {
        ESP_LOGE(TAG, "Generate the CSR before calling this function.");
    } else if (ret == ESP_ERR_INVALID_ARG) {
        ESP_LOGE(TAG, "Reason: Invalid Usage");
    } else if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Programming signer cert failed, returned %d", err_code);
    }


    fflush(stdout);
    return ret;
}

static esp_err_t register_program_signer_cert()
{
    const esp_console_cmd_t cmd = {
            .command = "program-signer-cert",
            .help = "Sets the UART command handler to input the signer certificate.\n"
                    "  Usage:program-signer-cert lock\n",
            "  Example: program-signer-cert 0 CRC_VALUE",
            .func = &program_signer_cert,
    };
    return esp_console_cmd_register(&cmd);
}

static esp_err_t get_version(int argc, char **argv)
{
    printf("%s\n", PROJECT_VER);

    fflush(stdout);
    return ESP_OK;
}

static esp_err_t register_get_version()
{
    const esp_console_cmd_t cmd = {
            .command = "version",
            .help = "get project version information",
            .func = &get_version,
    };
    return esp_console_cmd_register(&cmd);
}

static esp_err_t write_config(int argc, char **argv)
{
    esp_err_t ret = ESP_ERR_INVALID_ARG;
    int err_code;
    uint32_t received_crc = 0;

    if (atca_cli_status_object >= ATECC_INIT_SUCCESS) {
        if (argc == 2) {
            received_crc = (uint32_t)strtoul(argv[1], NULL, 10);
            ret = atecc_write_config(crypt_buf_cert, CRYPT_BUF_LEN, &err_code, received_crc);
        } else {
            ESP_LOGE(TAG, "Invalid arguments. Expected usage: write-config <CRC32>");
        }

        ESP_LOGI(TAG, "Status: %s\n", ret ? "Failure" : "Success");
    }

    if (atca_cli_status_object < ATECC_INIT_SUCCESS) {
        ESP_LOGE(TAG, "Please initialize device before calling this function");
    } else if (ret == ESP_ERR_INVALID_ARG) {
        ESP_LOGE(TAG, "Reason: Invalid Usage");
    } else if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Writing config failed, returned %d", err_code);
    }

    fflush(stdout);
    return ESP_OK;
}

static esp_err_t register_write_config()
{
    const esp_console_cmd_t cmd = {
            .command = "write-config",
            .help = "Write 128 bytes of configuration to ATECC608 config zone\n"
                    "  Must be called BEFORE init command locks the config zone\n"
                    "  Usage: write-config <CRC32>\n"
                    "  Example: write-config 1234567890",
            .func = &write_config,
    };
    return esp_console_cmd_register(&cmd);
}

static esp_err_t is_config_locked(int argc, char **argv)
{
    esp_err_t ret = ESP_ERR_INVALID_ARG;
    int err_code;
    bool is_locked = false;

    if (atca_cli_status_object >= ATECC_INIT_SUCCESS) {
        if (argc == 1) {
            ret = atecc_is_config_locked(&is_locked, &err_code);
        } else {
            ESP_LOGE(TAG, "Invalid arguments. Expected usage: is-config-locked");
        }

        ESP_LOGI(TAG, "Status: %s\n", ret ? "Failure" : "Success");
    }

    if (atca_cli_status_object < ATECC_INIT_SUCCESS) {
        ESP_LOGE(TAG, "Please initialize device before calling this function");
    } else if (ret == ESP_ERR_INVALID_ARG) {
        ESP_LOGE(TAG, "Reason: Invalid Usage");
    } else if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Checking config lock status failed, returned %d", err_code);
    } else {
        printf("\nConfig Zone: %s\n", is_locked ? "LOCKED" : "UNLOCKED");
    }

    fflush(stdout);
    return ESP_OK;
}

static esp_err_t register_is_config_locked()
{
    const esp_console_cmd_t cmd = {
            .command = "is-config-locked",
            .help = "Check if ATECC608 config zone is locked\n"
                    "  Returns LOCKED or UNLOCKED status\n"
                    "  Usage: is-config-locked\n"
                    "  Example: is-config-locked",
            .func = &is_config_locked,
    };
    return esp_console_cmd_register(&cmd);
}

static esp_err_t is_data_locked(int argc, char **argv)
{
    esp_err_t ret = ESP_ERR_INVALID_ARG;
    int err_code;
    bool is_locked = false;

    if (atca_cli_status_object >= ATECC_INIT_SUCCESS) {
        if (argc == 1) {
            ret = atecc_is_data_locked(&is_locked, &err_code);
        } else {
            ESP_LOGE(TAG, "Invalid arguments. Expected usage: is-data-locked");
        }

        ESP_LOGI(TAG, "Status: %s\n", ret ? "Failure" : "Success");
    }

    if (atca_cli_status_object < ATECC_INIT_SUCCESS) {
        ESP_LOGE(TAG, "Please initialize device before calling this function");
    } else if (ret == ESP_ERR_INVALID_ARG) {
        ESP_LOGE(TAG, "Reason: Invalid Usage");
    } else if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Checking data lock status failed, returned %d", err_code);
    } else {
        printf("\nData Zone: %s\n", is_locked ? "LOCKED" : "UNLOCKED");
    }

    fflush(stdout);
    return ESP_OK;
}

static esp_err_t register_is_data_locked()
{
    const esp_console_cmd_t cmd = {
            .command = "is-data-locked",
            .help = "Check if ATECC608 data zone is locked\n"
                    "  Returns LOCKED or UNLOCKED status\n"
                    "  Usage: is-data-locked\n"
                    "  Example: is-data-locked",
            .func = &is_data_locked,
    };
    return esp_console_cmd_register(&cmd);
}

static esp_err_t lock_config_zone(int argc, char **argv)
{
    esp_err_t ret = ESP_ERR_INVALID_ARG;
    int err_code;

    if (atca_cli_status_object >= ATECC_INIT_SUCCESS) {
        if (argc == 1) {
            ret = atecc_lock_config_zone(&err_code);
        } else {
            ESP_LOGE(TAG, "Invalid arguments. Expected usage: lock-config");
        }

        ESP_LOGI(TAG, "Status: %s\n", ret ? "Failure" : "Success");
    }

    if (atca_cli_status_object < ATECC_INIT_SUCCESS) {
        ESP_LOGE(TAG, "Please initialize device before calling this function");
    } else if (ret == ESP_ERR_INVALID_ARG) {
        ESP_LOGE(TAG, "Reason: Invalid Usage");
    } else if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Locking config zone failed, returned %d", err_code);
    }

    fflush(stdout);
    return ESP_OK;
}

static esp_err_t register_lock_config_zone()
{
    const esp_console_cmd_t cmd = {
            .command = "lock-config",
            .help = "Lock ATECC608 config zone (IRREVERSIBLE!)\n"
                    "  Must be called AFTER write-config command\n"
                    "  Usage: lock-config\n"
                    "  Example: lock-config",
            .func = &lock_config_zone,
    };
    return esp_console_cmd_register(&cmd);
}

static esp_err_t lock_data_zone(int argc, char **argv)
{
    esp_err_t ret = ESP_ERR_INVALID_ARG;
    int err_code;

    if (atca_cli_status_object >= ATECC_INIT_SUCCESS) {
        if (argc == 1) {
            ret = atecc_lock_data_zone(&err_code);
        } else {
            ESP_LOGE(TAG, "Invalid arguments. Expected usage: lock-data");
        }

        ESP_LOGI(TAG, "Status: %s\n", ret ? "Failure" : "Success");
    }

    if (atca_cli_status_object < ATECC_INIT_SUCCESS) {
        ESP_LOGE(TAG, "Please initialize device before calling this function");
    } else if (ret == ESP_ERR_INVALID_ARG) {
        ESP_LOGE(TAG, "Reason: Invalid Usage");
    } else if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Locking data zone failed, returned %d", err_code);
    }

    fflush(stdout);
    return ESP_OK;
}

static esp_err_t register_lock_data_zone()
{
    const esp_console_cmd_t cmd = {
            .command = "lock-data",
            .help = "Lock ATECC608 data zone (IRREVERSIBLE!)\n"
                    "  Must be called AFTER provisioning keys/certs\n"
                    "  Usage: lock-data\n"
                    "  Example: lock-data",
            .func = &lock_data_zone,
    };
    return esp_console_cmd_register(&cmd);
}

static esp_err_t read_config(int argc, char **argv)
{
    esp_err_t ret = ESP_ERR_INVALID_ARG;
    int err_code;
    uint8_t config_buf[128];

    if (atca_cli_status_object >= ATECC_INIT_SUCCESS) {
        if (argc == 1) {
            ret = atecc_read_config(config_buf, 128, &err_code);
        } else {
            ESP_LOGE(TAG, "Invalid arguments. Expected usage: read-config");
        }

        ESP_LOGI(TAG, "Status: %s\n", ret ? "Failure" : "Success");
    }

    if (atca_cli_status_object < ATECC_INIT_SUCCESS) {
        ESP_LOGE(TAG, "Please initialize device before calling this function");
    } else if (ret == ESP_ERR_INVALID_ARG) {
        ESP_LOGE(TAG, "Reason: Invalid Usage");
    } else if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Reading config failed, returned %d", err_code);
    } else {
        // Print formatted config output
        printf("\nATECC608 Configuration\n");
        printf("================================================================================\n\n");

        printf("Slot Configurations:\n");
        printf("--------------------------------------------------------------------------------\n");

        const char *slot_names[] = {
                "ECC Private         ",  // Slot 0
                "ECC Private         ",  // Slot 1
                "ECC Private         ",  // Slot 2
                "ECC Private         ",  // Slot 3
                "ECC Private         ",  // Slot 4
                "Secret              ",  // Slot 5
                "IO Protection       ",  // Slot 6
                "AES                 ",  // Slot 7
                "AES                 ",  // Slot 8
                "AES                 ",  // Slot 9
                "Cert Storage        ",  // Slot 10
                "Pubkey Storage      ",  // Slot 11
                "Cert Storage        ",  // Slot 12
                "Pubkey/Cert Storage ",  // Slot 13
                "Reserved            ",  // Slot 14
                "Reserved            "   // Slot 15
        };

        for (int slot = 0; slot < 16; slot++) {
            uint16_t slot_config = config_buf[20 + slot * 2] | (config_buf[20 + slot * 2 + 1] << 8);
            uint16_t key_config = config_buf[96 + slot * 2] | (config_buf[96 + slot * 2 + 1] << 8);

            printf("[OK] Slot %2d (%s): SlotCfg=0x%04X ", slot, slot_names[slot], slot_config);

            // Decode SlotConfig bits (ATECC608A datasheet Table 2-5)
            // Bit positions in 16-bit little-endian value:
            // Bit 0:   Private (always private flag, not used in display)
            // Bit 2:   GenKey - Key can be generated internally
            // Bit 6:   EncRead - Encrypted reads enabled
            // Bit 7:   IsSecret - Slot contains secret (vs public data)
            // Bit 8:   WriteKey[0]
            // Bit 9:   WriteKey[1]
            // Bit 10:  WriteKey[2]
            // Bit 11:  WriteKey[3]
            // Bit 12:  WriteConfig[0] - DeriveKey, GenKey, or Write commands
            // Bit 13:  WriteConfig[1] - ECDH operation
            // Bit 14:  WriteConfig[2] - Sign internally
            // Bit 15:  WriteConfig[3] - Sign externally (with external private key)

            bool first_flag = true;
            if (slot_config & 0x8000) {  // Bit 15
                printf("ExtSign");
                first_flag = false;
            }
            if (slot_config & 0x4000) {  // Bit 14
                if (!first_flag) printf(", ");
                printf("IntSign");
                first_flag = false;
            }
            if (slot_config & 0x2000) {  // Bit 13 - ECDH
                if (!first_flag) printf(", ");
                printf("ECDH");
                first_flag = false;
            }
            if (slot_config & 0x0080) {  // Bit 7 - IsSecret
                if (!first_flag) printf(", ");
                printf("Secret");
                first_flag = false;
            }
            if (slot_config & 0x0040) {  // Bit 6 - EncRead
                if (!first_flag) printf(", ");
                printf("EncRead");
                first_flag = false;
            }
            if (slot_config & 0x0004) {  // Bit 2 - GenKey
                if (!first_flag) printf(", ");
                printf("GenKey");
            }

            printf(" | KeyCfg=0x%04X ", key_config);

            // Decode KeyConfig
            uint8_t key_type = (key_config >> 2) & 0x07;
            if (key_type == 4) {
                printf("ECC-P256");
            } else if (key_type == 6) {
                printf("AES");
            } else if (key_type == 7) {
                printf("Other/Data");
            } else {
                printf("Type=%d", key_type);
            }

            printf("\n");
        }

        printf("\n================================================================================\n");
    }

    fflush(stdout);
    return ESP_OK;
}

static esp_err_t register_read_config()
{
    const esp_console_cmd_t cmd = {
            .command = "read-config",
            .help = "Read and display ATECC608 configuration\n"
                    "  Shows all 16 slot configurations with decoded flags\n"
                    "  Usage: read-config\n"
                    "  Example: read-config",
            .func = &read_config,
    };
    return esp_console_cmd_register(&cmd);
}

static esp_err_t write_data(int argc, char **argv)
{
    esp_err_t ret = ESP_ERR_INVALID_ARG;
    int err_code;
    uint8_t data_buf[32];
    int slot;
    uint32_t expected_crc;

    if (atca_cli_status_object >= ATECC_INIT_SUCCESS) {
        if (argc == 2) {
            slot = atoi(argv[1]);

            // Get CRC32 checksum
            expected_crc = strtoul(argv[1], NULL, 10);

            // Actually parse slot from argv[1]
            expected_crc = strtoul(argv[1], NULL, 10);
            slot = expected_crc; // First arg is slot number

            printf("Reading 32 bytes of data...\n");
            fflush(stdout);

            // Read 32 bytes via UART
            ecu_console_interface_t *console_interface = get_console_interface();
            for (int i = 0; i < 32; i++) {
                int read_ret = console_interface->read_bytes(&data_buf[i], 1, portMAX_DELAY);
                if (read_ret <= 0) {
                    ESP_LOGE(TAG, "Failed to read byte %d", i);
                    ret = ESP_FAIL;
                    goto end;
                }
            }

            // Read null terminator
            uint8_t null_term;
            console_interface->read_bytes(&null_term, 1, portMAX_DELAY);

            ret = atecc_write_data(slot, data_buf, 32, &err_code);
        } else {
            ESP_LOGE(TAG, "Invalid arguments. Expected: write-data <slot>");
        }

        ESP_LOGI(TAG, "Status: %s\n", ret ? "Failure" : "Success");
    }

end:
    if (atca_cli_status_object < ATECC_INIT_SUCCESS) {
        ESP_LOGE(TAG, "Please initialize device before calling this function");
    } else if (ret == ESP_ERR_INVALID_ARG) {
        ESP_LOGE(TAG, "Reason: Invalid Usage");
    } else if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Writing data failed, returned %d", err_code);
    }
    fflush(stdout);
    return ESP_OK;
}

static esp_err_t register_write_data()
{
    const esp_console_cmd_t cmd = {
            .command = "write-data",
            .help = "Write 32 bytes of data to a slot\n"
                    "  Data zone must be UNLOCKED for most slots\n"
                    "  Usage: write-data <slot>\n"
                    "  Example: write-data 6\n"
                    "  Note: Follow command with 32 bytes of data",
            .func = &write_data,
    };
    return esp_console_cmd_register(&cmd);
}

static esp_err_t write_enc_data(int argc, char **argv)
{
    esp_err_t ret = ESP_ERR_INVALID_ARG;
    int err_code;
    uint8_t data_buf[32];
    uint8_t enckey_buf[32];
    uint8_t num_in[NONCE_NUMIN_SIZE] = {0};
    ecu_console_interface_t *console_interface;
    uint8_t null_term;

    if (atca_cli_status_object < ATECC_INIT_SUCCESS) {
        ESP_LOGE(TAG, "Init device first");
        goto end;
    }

    if (argc < 4 || argc > 5) {
        ESP_LOGE(TAG, "Usage: write-enc-data <slot> <blk> <enckey_slot> [nonce]");
        goto end;
    }

    console_interface = get_console_interface();

    // Read data (32 bytes)
    printf("Reading data...\n");
    fflush(stdout);
    if (console_interface->read_bytes(data_buf, 32, portMAX_DELAY) <= 0) {
        ESP_LOGE(TAG, "Data read failed");
        ret = ESP_FAIL;
        goto end;
    }

    // Read encryption key (32 bytes)
    printf("Reading key...\n");
    fflush(stdout);
    if (console_interface->read_bytes(enckey_buf, 32, portMAX_DELAY) <= 0) {
        ESP_LOGE(TAG, "Key read failed");
        ret = ESP_FAIL;
        goto end;
    }

    // Read nonce if requested
    if (argc == 5 && atoi(argv[4]) == 1) {
        printf("Reading nonce...\n");
        fflush(stdout);
        if (console_interface->read_bytes(num_in, NONCE_NUMIN_SIZE, portMAX_DELAY) <= 0) {
            ESP_LOGE(TAG, "Nonce read failed");
            ret = ESP_FAIL;
            goto end;
        }
    }

    console_interface->read_bytes(&null_term, 1, portMAX_DELAY);

    ret = atecc_write_enc_data(atoi(argv[1]), atoi(argv[2]), atoi(argv[3]),
                                data_buf, enckey_buf,
                                (argc == 5 && atoi(argv[4]) == 1) ? num_in : NULL,
                                32, &err_code);

    ESP_LOGI(TAG, "Status: %s\n", ret ? "Fail" : "OK");

end:
    fflush(stdout);
    return ESP_OK;
}

static esp_err_t register_write_enc_data()
{
    const esp_console_cmd_t cmd = {
            .command = "write-enc-data",
            .help = "Write encrypted data to slot\n"
                    "  Usage: write-enc-data <slot> <blk> <enckey_slot> [nonce]\n"
                    "  Example: write-enc-data 7 0 6 0",
            .func = &write_enc_data,
    };
    return esp_console_cmd_register(&cmd);
}

static esp_err_t load_slot6_secret(int argc, char **argv)
{
    esp_err_t ret = ESP_ERR_INVALID_ARG;

    if (argc != 2) {
        ESP_LOGE(TAG, "Usage: load-slot6-secret <hex_string>");
        ESP_LOGE(TAG, "  hex_string must be 64 hex characters (32 bytes)");
        return ESP_ERR_INVALID_ARG;
    }

    const char* hex_str = argv[1];
    size_t hex_len = strlen(hex_str);

    // Validate length (64 hex chars = 32 bytes)
    if (hex_len != 64) {
        ESP_LOGE(TAG, "Invalid hex string length: %zu (expected 64)", hex_len);
        ESP_LOGE(TAG, "Status: Failure");
        fflush(stdout);
        return ESP_ERR_INVALID_SIZE;
    }

    // Convert hex string to bytes
    for (int i = 0; i < 32; i++) {
        char byte_str[3] = { hex_str[i*2], hex_str[i*2+1], '\0' };
        slot6_secret[i] = (uint8_t)strtol(byte_str, NULL, 16);
    }

    slot6_secret_loaded = true;

    ESP_LOGI(TAG, "Slot6 secret loaded successfully (%zu hex chars -> 32 bytes)", hex_len);
    ESP_LOGI(TAG, "Status: Success");
    fflush(stdout);

    return ESP_OK;
}

static esp_err_t register_load_slot6_secret()
{
    const esp_console_cmd_t cmd = {
            .command = "load-slot6-secret",
            .help = "Load slot6 IO protection key from host (for encrypted writes)\n"
                    "  Usage: load-slot6-secret <hex_string>\n"
                    "  Example: load-slot6-secret 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF\n",
            .func = &load_slot6_secret,
    };
    return esp_console_cmd_register(&cmd);
}

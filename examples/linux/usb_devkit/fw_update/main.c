/**
 * @file main.c
 * @brief Example showing how to perform an update of the TROPIC01 firmware using Libtropic with the
 * USB devkit.
 * @copyright Copyright (c) 2020-2026 Tropic Square s.r.o.
 *
 * @license For the license see LICENSE.md in the root directory of this source tree.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "fw_CPU.h"
#include "fw_SPECT.h"
#include "libtropic.h"
#include "libtropic_common.h"
#include "libtropic_mbedtls_v4.h"
#include "libtropic_port_posix_usb_dongle.h"
#include "psa/crypto.h"

// Choose pairing keypair for slot 0.
#if LT_USE_SH0_ENG_SAMPLE
#define LT_EX_SH0_PRIV sh0priv_eng_sample
#define LT_EX_SH0_PUB sh0pub_eng_sample
#elif LT_USE_SH0_PROD0
#define LT_EX_SH0_PRIV sh0priv_prod0
#define LT_EX_SH0_PUB sh0pub_prod0
#endif

lt_ret_t get_fw_versions(lt_handle_t *lt_handle)
{
    uint8_t cpu_fw_ver[TR01_L2_GET_INFO_RISCV_FW_SIZE] = {0};
    uint8_t spect_fw_ver[TR01_L2_GET_INFO_SPECT_FW_SIZE] = {0};

    printf("Reading firmware versions from TROPIC01...");
    lt_ret_t ret = lt_get_info_riscv_fw_ver(lt_handle, cpu_fw_ver);
    if (ret != LT_OK) {
        fprintf(stderr, "\nFailed to get RISC-V FW version, ret=%s\n", lt_ret_verbose(ret));
        return ret;
    }
    ret = lt_get_info_spect_fw_ver(lt_handle, spect_fw_ver);
    if (ret != LT_OK) {
        fprintf(stderr, "\nFailed to get SPECT FW version, ret=%s\n", lt_ret_verbose(ret));
        return ret;
    }
    printf("OK\n");

    printf("TROPIC01 firmware versions:\n");
    printf("  - RISC-V FW version: %d.%d.%d\n", cpu_fw_ver[3], cpu_fw_ver[2], cpu_fw_ver[1]);
    printf("  - SPECT FW version: %d.%d.%d\n", spect_fw_ver[3], spect_fw_ver[2], spect_fw_ver[1]);

    return LT_OK;
}

int main(void)
{
    // Cosmetics: Disable buffering to keep output in order. You do not need to do this in your app if
    // you don't care about stdout/stderr output being shuffled or you use stdout only (or different
    // output mechanism altogether).
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("==========================================\n");
    printf("==== TROPIC01 Firmware Update Example ====\n");
    printf("==========================================\n");

    // Cryptographic function provider initialization.
    //
    // In production, this would typically be done only once,
    // usually at the start of the application or before
    // the first use of cryptographic functions but no later than
    // the first occurrence of any Libtropic function
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        fprintf(stderr, "PSA Crypto initialization failed, status=%d (psa_status_t)\n", status);
        return -1;
    }

    // Libtropic handle.
    //
    // It is declared here (on stack) for
    // simplicity. In production, you put it on heap if needed.
    lt_handle_t lt_handle = {0};

    // Device structure.
    //
    // Modify this according to your environment. Default values
    // are compatible with RPi and our RPi shield.
    lt_dev_posix_usb_dongle_t device = {0};

    // LT_USB_DEVKIT_PATH is defined in CMakeLists.txt. Pass -DLT_USB_DEVKIT_PATH=<path>
    // to cmake if you want to change it.
    int dev_path_len = snprintf(device.dev_path, sizeof(device.dev_path), "%s", LT_USB_DEVKIT_PATH);
    if (dev_path_len < 0 || (size_t)dev_path_len >= sizeof(device.dev_path)) {
        fprintf(
            stderr,
            "Error: LT_USB_DEVKIT_PATH is too long for device.dev_path buffer (limit is %zu bytes).\n",
            sizeof(device.dev_path));
        mbedtls_psa_crypto_free();
        return -1;
    }

    device.baud_rate = 115200;
    lt_handle.l2.device = &device;

    // Crypto abstraction layer (CAL) context.
    lt_ctx_mbedtls_v4_t crypto_ctx;
    lt_handle.l3.crypto_ctx = &crypto_ctx;

    printf("Initializing handle...");
    lt_ret_t ret = lt_init(&lt_handle);
    if (LT_OK != ret) {
        fprintf(stderr, "\nFailed to initialize handle, ret=%s\n", lt_ret_verbose(ret));
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    // Establish Secure Channel Session so we can read I/R-Config.
    printf("Starting Secure Session with key slot %d...", (int)TR01_PAIRING_KEY_SLOT_INDEX_0);
    // Keys are chosen based on the CMake option LT_SH0_KEYS.
    ret = lt_verify_chip_and_start_secure_session(&lt_handle, LT_EX_SH0_PRIV, LT_EX_SH0_PUB,
                                                  TR01_PAIRING_KEY_SLOT_INDEX_0);
    if (LT_OK != ret) {
        fprintf(stderr, "\nFailed to start Secure Session with key %d, ret=%s\n",
                (int)TR01_PAIRING_KEY_SLOT_INDEX_0, lt_ret_verbose(ret));
        fprintf(stderr,
                "Check if you use correct SH0 keys! Hint: if you use an engineering sample chip, "
                "compile with "
                "-DLT_SH0_KEYS=eng_sample\n");
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    // Read I-Config and check if Maintenance Mode is enabled.
    uint32_t i_config_cfg_startup;
    printf("Reading I-Config[CFG_START_UP]...");
    ret = lt_i_config_read(&lt_handle, TR01_CFG_START_UP_ADDR, &i_config_cfg_startup);
    if (ret != LT_OK) {
        fprintf(stderr, "\nFailed to read I-Config[CFG_START_UP], ret=%s\n", lt_ret_verbose(ret));
        lt_session_abort(&lt_handle);
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    printf("Checking if Maintenance Mode is enabled in I-Config[CFG_START_UP]...");
    if (!(i_config_cfg_startup & BOOTLOADER_CO_CFG_START_UP_MAINTENANCE_ENA_MASK)) {
        fprintf(stderr,
                "\nMaintenance Mode is not enabled in I-Config -> FW Update cannot be performed.\n");
        lt_session_abort(&lt_handle);
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    // Read R-Config and check if Maintenance Mode is enabled.
    // The whole R-Config is read in case we need to modify it, as it has to be completely erased
    // before writing again.
    lt_config_t r_config;
    printf("Reading R-Config...");
    ret = lt_read_whole_R_config(&lt_handle, &r_config);
    if (ret != LT_OK) {
        fprintf(stderr, "\nFailed to read R-Config, ret=%s\n", lt_ret_verbose(ret));
        lt_session_abort(&lt_handle);
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    if (!(r_config.obj[TR01_CFG_START_UP_IDX] & BOOTLOADER_CO_CFG_START_UP_MAINTENANCE_ENA_MASK)) {
        printf("Maintenance Mode is not enabled in R-Config, enabling it now...");
        r_config.obj[TR01_CFG_START_UP_IDX] |= BOOTLOADER_CO_CFG_START_UP_MAINTENANCE_ENA_MASK;
        printf("Erasing R-Config...");
        ret = lt_r_config_erase(&lt_handle);
        if (ret != LT_OK) {
            fprintf(stderr, "\nFailed to erase R-Config, ret=%s\n", lt_ret_verbose(ret));
            lt_session_abort(&lt_handle);
            lt_deinit(&lt_handle);
            mbedtls_psa_crypto_free();
            return -1;
        }
        printf("OK\n");

        printf("Writing R-Config...");
        ret = lt_write_whole_R_config(&lt_handle, &r_config);
        if (ret != LT_OK) {
            fprintf(stderr, "\nFailed to write R-Config, ret=%s\n", lt_ret_verbose(ret));
            lt_session_abort(&lt_handle);
            lt_deinit(&lt_handle);
            mbedtls_psa_crypto_free();
            return -1;
        }
        printf("OK\n");
    }
    else {
        printf("Maintenance Mode is already enabled in R-Config.\n");
    }

    printf("Aborting Secure Session...");
    ret = lt_session_abort(&lt_handle);
    if (LT_OK != ret) {
        fprintf(stderr, "\nFailed to abort Secure Session, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    // First, we check versions of both updateable firmwares. To do that, we need TROPIC01 to
    // **not** be in the Start-up Mode. If there are valid firmwares, TROPIC01 will begin to
    // execute them automatically on boot.
    printf("Rebooting TROPIC01...");
    ret = lt_reboot(&lt_handle, TR01_REBOOT);
    if (ret != LT_OK) {
        fprintf(stderr, "\nlt_reboot() failed, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    if (get_fw_versions(&lt_handle) != LT_OK) {
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }

    printf("Versions to update to:\n");
    printf("  - RISC-V FW version: %d.%d.%d\n", 6, 6, 6);
    printf("  - SPECT FW version: %d.%d.%d\n", 6, 6, 6);

    printf("Proceed with update? [y/N]: ");
    char user_input = getchar();
    char c;
    while ((c = getchar()) != '\n' && c != EOF);  // Clear input buffer
    if (user_input != 'y' && user_input != 'Y') {
        printf("\nUpdate cancelled by user.\n");
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return 0;
    }

    bool disable_mtnc_mode_after_update = false;
    printf("Disable Maintenance Mode in R-Config after the FW update? [y/N]: ");
    user_input = getchar();
    if (user_input == 'y') {
        disable_mtnc_mode_after_update = true;
    }

    printf("\nStarting firmware update...\n");

    // The chip must be in Start-up Mode to be able to perform a firmware update.
    printf("- Sending maintenance reboot request...");
    ret = lt_reboot(&lt_handle, TR01_MAINTENANCE_REBOOT);
    if (ret != LT_OK) {
        fprintf(stderr, "\nlt_reboot() failed, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    printf("- Updating TR01_FW_BANK_FW1 and TR01_FW_BANK_SPECT1\n");
    printf("  - Updating RISC-V FW...");
    ret = lt_do_mutable_fw_update(&lt_handle, fw_CPU, sizeof(fw_CPU), TR01_FW_BANK_FW1);
    if (ret != LT_OK) {
        fprintf(stderr, "\nRISC-V FW update failed, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    printf("  - Updating SPECT FW...");
    ret = lt_do_mutable_fw_update(&lt_handle, fw_SPECT, sizeof(fw_SPECT), TR01_FW_BANK_SPECT1);
    if (ret != LT_OK) {
        fprintf(stderr, "\nSPECT FW update failed, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    printf("- Updating TR01_FW_BANK_FW2 and TR01_FW_BANK_SPECT2\n");
    printf("  - Updating RISC-V FW...");
    ret = lt_do_mutable_fw_update(&lt_handle, fw_CPU, sizeof(fw_CPU), TR01_FW_BANK_FW2);
    if (ret != LT_OK) {
        fprintf(stderr, "\nRISC-V FW update failed, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    printf("  - Updating SPECT FW...");
    ret = lt_do_mutable_fw_update(&lt_handle, fw_SPECT, sizeof(fw_SPECT), TR01_FW_BANK_SPECT2);
    if (ret != LT_OK) {
        fprintf(stderr, "\nSPECT FW update failed, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");
    printf("Successfully updated all 4 FW banks.\n\n");

    printf("Reading FW bank headers:\n");
    ret = lt_print_fw_header(&lt_handle, TR01_FW_BANK_FW1, printf);
    if (ret != LT_OK) {
        fprintf(stderr, "Failed to print TR01_FW_BANK_FW1 header, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    ret = lt_print_fw_header(&lt_handle, TR01_FW_BANK_FW2, printf);
    if (ret != LT_OK) {
        fprintf(stderr, "Failed to print TR01_FW_BANK_FW2 header, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    ret = lt_print_fw_header(&lt_handle, TR01_FW_BANK_SPECT1, printf);
    if (ret != LT_OK) {
        fprintf(stderr, "Failed to print TR01_FW_BANK_SPECT1 header, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    ret = lt_print_fw_header(&lt_handle, TR01_FW_BANK_SPECT2, printf);
    if (ret != LT_OK) {
        fprintf(stderr, "Failed to print TR01_FW_BANK_SPECT2 header, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }

    printf("Sending reboot request...");
    ret = lt_reboot(&lt_handle, TR01_REBOOT);
    if (ret != LT_OK) {
        fprintf(stderr, "\nlt_reboot() failed, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK!\nTROPIC01 is executing Application FW now\n");

    if (get_fw_versions(&lt_handle) != LT_OK) {
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }

    if (disable_mtnc_mode_after_update) {
        printf("Starting Secure Session with key slot %d...", (int)TR01_PAIRING_KEY_SLOT_INDEX_0);
        // Keys are chosen based on the CMake option LT_SH0_KEYS.
        ret = lt_verify_chip_and_start_secure_session(&lt_handle, LT_EX_SH0_PRIV, LT_EX_SH0_PUB,
                                                      TR01_PAIRING_KEY_SLOT_INDEX_0);
        if (LT_OK != ret) {
            fprintf(stderr, "\nFailed to start Secure Session with key %d, ret=%s\n",
                    (int)TR01_PAIRING_KEY_SLOT_INDEX_0, lt_ret_verbose(ret));
            lt_deinit(&lt_handle);
            mbedtls_psa_crypto_free();
            return -1;
        }
        printf("OK\n");

        printf("Reading R-Config...");
        ret = lt_read_whole_R_config(&lt_handle, &r_config);
        if (ret != LT_OK) {
            fprintf(stderr, "\nFailed to read R-Config, ret=%s\n", lt_ret_verbose(ret));
            lt_session_abort(&lt_handle);
            lt_deinit(&lt_handle);
            mbedtls_psa_crypto_free();
            return -1;
        }
        printf("OK\n");

        printf("Erasing R-Config...");
        ret = lt_r_config_erase(&lt_handle);
        if (ret != LT_OK) {
            fprintf(stderr, "\nFailed to erase R-Config, ret=%s\n", lt_ret_verbose(ret));
            lt_session_abort(&lt_handle);
            lt_deinit(&lt_handle);
            mbedtls_psa_crypto_free();
            return -1;
        }
        printf("OK\n");

        printf("Disabling Maintenance Mode in R-Config...");
        r_config.obj[TR01_CFG_START_UP_IDX] &= ~BOOTLOADER_CO_CFG_START_UP_MAINTENANCE_ENA_MASK;
        ret = lt_write_whole_R_config(&lt_handle, &r_config);
        if (ret != LT_OK) {
            fprintf(stderr, "\nFailed to write R-Config, ret=%s\n", lt_ret_verbose(ret));
            lt_session_abort(&lt_handle);
            lt_deinit(&lt_handle);
            mbedtls_psa_crypto_free();
            return -1;
        }
        printf("OK\n");

        printf("Aborting Secure Session...");
        ret = lt_session_abort(&lt_handle);
        if (LT_OK != ret) {
            fprintf(stderr, "\nFailed to abort Secure Session, ret=%s\n", lt_ret_verbose(ret));
            lt_deinit(&lt_handle);
            mbedtls_psa_crypto_free();
            return -1;
        }
        printf("OK\n");

        printf("Verifying that Maintenance Mode is not accessible...");
        ret = lt_reboot(&lt_handle, TR01_MAINTENANCE_REBOOT);
        if (ret == LT_REBOOT_UNSUCCESSFUL) {
            printf("OK\n");
        }
        else if (ret != LT_OK) {
            fprintf(stderr, "\nlt_reboot() failed, ret=%s\n", lt_ret_verbose(ret));
            lt_deinit(&lt_handle);
            mbedtls_psa_crypto_free();
            return -1;
        }
        else {
            fprintf(stderr, "\nMaintenance reboot succeeded! ret=%s\n", lt_ret_verbose(ret));
            lt_deinit(&lt_handle);
            mbedtls_psa_crypto_free();
            return -1;
        }
    }

    printf("Deinitializing handle...");
    ret = lt_deinit(&lt_handle);
    if (LT_OK != ret) {
        fprintf(stderr, "\nFailed to deinitialize handle, ret=%s\n", lt_ret_verbose(ret));
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("OK\n");

    // Cryptographic function provider deinitialization.
    //
    // In production, this would be done only once, typically
    // during termination of the application.
    mbedtls_psa_crypto_free();

    return 0;
}
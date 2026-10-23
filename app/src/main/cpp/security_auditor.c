#include <jni.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int path_exists(const char *path) {
    return access(path, F_OK) == 0;
}

static int contains_system_rw(void) {
    FILE *mounts = fopen("/proc/mounts", "r");
    if (mounts == NULL) {
        return 0;
    }

    char line[512];
    int result = 0;
    while (fgets(line, sizeof(line), mounts) != NULL) {
        if (strstr(line, " /system ") != NULL || strstr(line, " / ") != NULL) {
            if (strstr(line, " rw,") != NULL || strstr(line, " rw ") != NULL) {
                result = 1;
                break;
            }
        }
    }
    fclose(mounts);
    return result;
}

static int read_first_line(const char *path, char *output, size_t output_size) {
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        return 0;
    }
    int success = fgets(output, (int)output_size, file) != NULL;
    fclose(file);
    if (success) {
        output[strcspn(output, "\r\n")] = '\0';
    }
    return success;
}

JNIEXPORT jstring JNICALL
Java_com_h1rasse_securityauditor_MainActivity_nativeAudit(JNIEnv *env, jobject instance) {
    (void)instance;
    const char *su_paths[] = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/vendor/bin/su",
        "/data/adb/magisk", "/data/adb/ksu", "/data/adb/apatch"
    };
    int found_su = 0;
    for (size_t i = 0; i < sizeof(su_paths) / sizeof(su_paths[0]); ++i) {
        if (path_exists(su_paths[i])) {
            found_su = 1;
            break;
        }
    }

    char verified_boot[64] = "unknown";
    char verified_state[64] = "unknown";
    char vbmeta_state[64] = "unknown";
    (void)read_first_line("/sys/fs/selinux/enforce", verified_boot, sizeof(verified_boot));
    (void)read_first_line("/proc/sys/kernel/tainted", verified_state, sizeof(verified_state));
    (void)read_first_line("/sys/fs/selinux/enforce", vbmeta_state, sizeof(vbmeta_state));

    char json[512];
    int written = snprintf(json, sizeof(json),
        "{\"suPathDetected\":%s,\"systemWritable\":%s,\"selinuxEnforceFile\":\"%s\",\"kernelTainted\":\"%s\",\"nativeCheck\":true}",
        found_su ? "true" : "false", contains_system_rw() ? "true" : "false",
        verified_boot, verified_state);
    if (written < 0 || (size_t)written >= sizeof(json)) {
        return (*env)->NewStringUTF(env, "{\"nativeCheck\":false}");
    }
    return (*env)->NewStringUTF(env, json);
}

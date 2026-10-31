#import <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#import <bsm/libbsm.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "policy.h"

static const char *kDir = "/Library/Application Support/MadElfES";
static const char *kLog = "/var/log/madelf-es.log";

static void copy_token(es_string_token_t token, char *out, size_t cap) {
    size_t n;
    if (!out || cap == 0) return;
    out[0] = 0;
    if (token.data == NULL || token.length == 0) return;
    n = token.length;
    if (n >= cap) n = cap - 1;
    memcpy(out, token.data, n);
    out[n] = 0;
}

static void sanitize(char *s) {
    if (!s) return;
    for (; *s; s++) {
        if (*s == '\n' || *s == '\r' || *s == '\t') *s = ' ';
    }
}

static void write_log(const char *line) {
    int fd = open(kLog, O_CREAT | O_WRONLY | O_APPEND, 0644);
    size_t n;
    if (fd >= 0) {
        n = strlen(line);
        if (write(fd, line, n) < 0) {
            /* logging must not block the auth response */
        }
        close(fd);
    }
    fputs(line, stdout);
    fflush(stdout);
}

static const es_event_exec_t *exec_payload(const es_message_t *msg) {
    if (msg->event_type == ES_EVENT_TYPE_AUTH_EXEC) return &msg->event.exec;
#ifdef ES_EVENT_TYPE_AUTH_EXEC_TRANSITION
    /* AUTH_EXEC_TRANSITION is the point where the new image's signature is
     * known. SDKs that define the event deliver it through the same exec
     * union member used by AUTH_EXEC. If a future ESMessage.h moves the
     * fields to msg->event.exec_transition, read that member here instead. */
    if (msg->event_type == ES_EVENT_TYPE_AUTH_EXEC_TRANSITION) return &msg->event.exec;
#endif
    return NULL;
}

static const char *event_name(const es_message_t *msg) {
#ifdef ES_EVENT_TYPE_AUTH_EXEC_TRANSITION
    if (msg->event_type == ES_EVENT_TYPE_AUTH_EXEC_TRANSITION) return "AUTH_EXEC_TRANSITION";
#else
    (void)msg;
#endif
    return "AUTH_EXEC";
}

static void handle(es_client_t *client, const es_message_t *msg) {
    const es_event_exec_t *exec = exec_payload(msg);
    char path[4096], team[128], signing[256], args[1024], line[8192];
    char allow_path[4096], mode_path[4096];
    madelf_es_policy policy;
    const es_process_t *target = NULL;
    pid_t ppid = -1;
    int matched = 0;
    int allow = 1;
    const char *decision = "allow";
    uint32_t argc = 0;
    uint32_t i;
    size_t used = 0;

    path[0] = team[0] = signing[0] = args[0] = 0;
    if (msg->process) ppid = audit_token_to_pid(msg->process->audit_token);
    if (exec && exec->target) {
        target = exec->target;
        if (target->executable) copy_token(target->executable->path, path, sizeof path);
        copy_token(target->team_id, team, sizeof team);
        copy_token(target->signing_id, signing, sizeof signing);
        argc = es_exec_arg_count(exec);
        for (i = 0; i < argc && i < 16; i++) {
            es_string_token_t arg = es_exec_arg(exec, i);
            char piece[256];
            int wrote;
            copy_token(arg, piece, sizeof piece);
            sanitize(piece);
            wrote = snprintf(args + used, sizeof args - used, "%s%s", used ? " " : "", piece);
            if (wrote < 0 || (size_t)wrote >= sizeof args - used) break;
            used += (size_t)wrote;
        }
    }
    sanitize(path);
    sanitize(team);
    sanitize(signing);

    snprintf(allow_path, sizeof allow_path, "%s/allowlist", kDir);
    snprintf(mode_path, sizeof mode_path, "%s/mode", kDir);
    if (madelf_es_policy_load(allow_path, mode_path, &policy) != 0) {
        allow = 1;
        decision = "allow";
        snprintf(line, sizeof line,
                 "ts=%ld event=%s decision=allow reason=config-unreadable path=%s teamid=%s signingid=%s ppid=%d args=%s\n",
                 (long)time(NULL), event_name(msg), path[0] ? path : "-",
                 team[0] ? team : "-", signing[0] ? signing : "-", (int)ppid,
                 args[0] ? args : "-");
        write_log(line);
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
        return;
    }
    matched = madelf_es_policy_match(&policy, path, team, signing);
    if (policy.enforce) allow = matched;
    else allow = 1;
    decision = allow ? "allow" : "deny";
    snprintf(line, sizeof line,
             "ts=%ld event=%s decision=%s mode=%s matched=%d path=%s teamid=%s signingid=%s ppid=%d args=%s\n",
             (long)time(NULL), event_name(msg), decision,
             policy.enforce ? "enforce" : "monitor", matched,
             path[0] ? path : "-", team[0] ? team : "-", signing[0] ? signing : "-",
             (int)ppid, args[0] ? args : "-");
    madelf_es_policy_free(&policy);
    write_log(line);
    /* cache=false so an allowlist edit applies to the next exec. */
    es_respond_auth_result(client, msg, allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, false);
}

int main(void) {
    es_client_t *client = NULL;
    es_new_client_result_t rc;
    es_event_type_t events[2];
    uint32_t count = 0;
    es_return_t sub;

    @autoreleasepool {
        mkdir(kDir, 0755);
        rc = es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
            @autoreleasepool {
                handle(c, msg);
            }
        });
        if (rc != ES_NEW_CLIENT_RESULT_SUCCESS) {
            fprintf(stderr, "mad-elf-es: es_new_client failed (%d). "
                            "The extension needs the endpoint-security entitlement and Full Disk Access.\n",
                    (int)rc);
            return 1;
        }
        events[count++] = ES_EVENT_TYPE_AUTH_EXEC;
#ifdef ES_EVENT_TYPE_AUTH_EXEC_TRANSITION
        events[count++] = ES_EVENT_TYPE_AUTH_EXEC_TRANSITION;
#endif
        sub = es_subscribe(client, events, count);
        if (sub != ES_RETURN_SUCCESS && count == 2) {
            fprintf(stderr, "mad-elf-es: AUTH_EXEC_TRANSITION subscribe failed (%d); retrying AUTH_EXEC only\n",
                    (int)sub);
            events[0] = ES_EVENT_TYPE_AUTH_EXEC;
            count = 1;
            sub = es_subscribe(client, events, count);
        }
        if (sub != ES_RETURN_SUCCESS) {
            fprintf(stderr, "mad-elf-es: es_subscribe failed (%d)\n", (int)sub);
            return 1;
        }
        fprintf(stderr, "mad-elf-es: subscribed (%u event types). Default mode is monitor.\n", count);
        dispatch_main();
    }
    return 0;
}

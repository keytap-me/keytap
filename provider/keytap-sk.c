/*
 * keytap-sk — an OpenSSH security key provider (SecurityKeyProvider / SSH_SK_PROVIDER) that has an ed25519-sk
 * or ecdsa-sk signature made by the YubiKey tapped on the iPhone (KeyTap) instead of one plugged in here.
 *
 *   ssh -o SecurityKeyProvider=$HOME/.local/lib/keytap-sk.dylib -i ~/.ssh/id_ed25519_sk host
 *   (or: age-plugin-yubikey-phone ssh-opts <key file> prints those arguments)
 *
 * ssh loads this library in ssh-sk-helper and calls sk_sign. We start the KeyTap bridge
 * (`age-plugin-yubikey-phone sk-sign`), hand it the request on a pipe and read the answer: the bridge serves the
 * request to the paired phone, the phone runs the FIDO2 assertion on the YubiKey over NFC with the PIN entered on
 * the phone. The PIN ssh may have read is ignored (it never leaves this process). No key material is involved here
 * at all: the key handle and the data to sign go out, the signature comes back.
 *
 * Only signing is supported: keys are made with ssh-keygen and a YubiKey plugged in (enrolment and resident-key
 * download need the key on this machine anyway). Plain C, libc only. MIT OR Apache-2.0, like the rest of KeyTap.
 */
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sk-api.h"

#define BRIDGE_NAME "age-plugin-yubikey-phone"
#define MAX_ANSWER (64 * 1024)

uint32_t sk_api_version(void) { return SSH_SK_VERSION_MAJOR; }

int sk_enroll(uint32_t alg, const uint8_t *challenge, size_t challenge_len, const char *application, uint8_t flags,
              const char *pin, struct sk_option **options, struct sk_enroll_response **enroll_response) {
	(void)alg; (void)challenge; (void)challenge_len; (void)application; (void)flags; (void)pin; (void)options;
	if (enroll_response != NULL) *enroll_response = NULL;
	fprintf(stderr, "keytap-sk: creating keys is not supported; use ssh-keygen with the YubiKey plugged in\n");
	return SSH_SK_ERR_UNSUPPORTED;
}

int sk_load_resident_keys(const char *pin, struct sk_option **options, struct sk_resident_key ***rks, size_t *nrks) {
	(void)pin; (void)options;
	if (rks != NULL) *rks = NULL;
	if (nrks != NULL) *nrks = 0;
	return SSH_SK_ERR_UNSUPPORTED;
}

static int executable(const char *p) {
	struct stat st;
	return p != NULL && stat(p, &st) == 0 && S_ISREG(st.st_mode) && access(p, X_OK) == 0;
}

/* The bridge: $KEYTAP_BRIDGE, else next to this library (lib/../bin, or the same directory), else ~/.local/bin. */
static int find_bridge(char *out, size_t n) {
	const char *env = getenv("KEYTAP_BRIDGE");
	if (env != NULL && *env != '\0') {
		snprintf(out, n, "%s", env);
		return executable(out);
	}
	Dl_info info;
	if (dladdr((void *)sk_api_version, &info) != 0 && info.dli_fname != NULL) {
		char dir[PATH_MAX];
		snprintf(dir, sizeof(dir), "%s", info.dli_fname);
		char *slash = strrchr(dir, '/');
		if (slash != NULL) {
			*slash = '\0';
			snprintf(out, n, "%s/../bin/%s", dir, BRIDGE_NAME);
			if (executable(out)) return 1;
			snprintf(out, n, "%s/%s", dir, BRIDGE_NAME);
			if (executable(out)) return 1;
		}
	}
	const char *home = getenv("HOME");
	if (home != NULL) {
		snprintf(out, n, "%s/.local/bin/%s", home, BRIDGE_NAME);
		if (executable(out)) return 1;
	}
	return 0;
}

static int write_all(int fd, const char *p, size_t n) {
	while (n > 0) {
		ssize_t w = write(fd, p, n);
		if (w < 0 && errno == EINTR) continue;
		if (w <= 0) return -1;
		p += w;
		n -= (size_t)w;
	}
	return 0;
}

static int put_hex(int fd, const char *key, const uint8_t *b, size_t n) {
	static const char digits[] = "0123456789abcdef";
	char *line = malloc(strlen(key) + 2 * n + 3);
	if (line == NULL) return -1;
	size_t o = (size_t)sprintf(line, "%s ", key);
	for (size_t i = 0; i < n; i++) {
		line[o++] = digits[b[i] >> 4];
		line[o++] = digits[b[i] & 15];
	}
	line[o++] = '\n';
	int r = write_all(fd, line, o);
	free(line);
	return r;
}

static int hexval(char c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* Decodes a hex token into a fresh buffer; "-" is an empty value (NULL, 0). */
static int get_hex(const char *tok, uint8_t **out, size_t *outlen) {
	*out = NULL;
	*outlen = 0;
	if (strcmp(tok, "-") == 0) return 0;
	size_t n = strlen(tok);
	if (n == 0 || n % 2 != 0) return -1;
	uint8_t *b = calloc(1, n / 2);
	if (b == NULL) return -1;
	for (size_t i = 0; i < n / 2; i++) {
		int hi = hexval(tok[2 * i]), lo = hexval(tok[2 * i + 1]);
		if (hi < 0 || lo < 0) { free(b); return -1; }
		b[i] = (uint8_t)(hi << 4 | lo);
	}
	*out = b;
	*outlen = n / 2;
	return 0;
}

int sk_sign(uint32_t alg, const uint8_t *data, size_t data_len, const char *application, const uint8_t *key_handle,
            size_t key_handle_len, uint8_t flags, const char *pin, struct sk_option **options,
            struct sk_sign_response **sign_response) {
	(void)pin; (void)options; /* the PIN is entered on the phone and goes only to the YubiKey */
	if (sign_response == NULL) return SSH_SK_ERR_GENERAL;
	*sign_response = NULL;
	if ((alg != SSH_SK_ED25519 && alg != SSH_SK_ECDSA) || application == NULL || key_handle == NULL) {
		return SSH_SK_ERR_UNSUPPORTED;
	}
	char bridge[PATH_MAX];
	if (!find_bridge(bridge, sizeof(bridge))) {
		fprintf(stderr, "keytap-sk: the KeyTap bridge (%s) was not found; set KEYTAP_BRIDGE\n", BRIDGE_NAME);
		return SSH_SK_ERR_DEVICE_NOT_FOUND;
	}

	int in[2], out[2];
	if (pipe(in) != 0) return SSH_SK_ERR_GENERAL;
	if (pipe(out) != 0) { close(in[0]); close(in[1]); return SSH_SK_ERR_GENERAL; }
	void (*old_pipe)(int) = signal(SIGPIPE, SIG_IGN);
	pid_t pid = fork();
	if (pid < 0) {
		close(in[0]); close(in[1]); close(out[0]); close(out[1]);
		signal(SIGPIPE, old_pipe);
		return SSH_SK_ERR_GENERAL;
	}
	if (pid == 0) {
		dup2(in[0], STDIN_FILENO);
		dup2(out[1], STDOUT_FILENO);
		close(in[0]); close(in[1]); close(out[0]); close(out[1]);
		execl(bridge, BRIDGE_NAME, "sk-sign", (char *)NULL);
		_exit(127);
	}
	close(in[0]);
	close(out[1]);

	char head[512];
	int hn = snprintf(head, sizeof(head), "keytap-sk-v1\nalg %u\nflags %u\napplication %s\n", alg, flags, application);
	int ok = hn > 0 && (size_t)hn < sizeof(head) && strchr(application, '\n') == NULL &&
	         write_all(in[1], head, (size_t)hn) == 0 && put_hex(in[1], "key_handle", key_handle, key_handle_len) == 0 &&
	         put_hex(in[1], "data", data, data_len) == 0;
	close(in[1]);

	char *answer = calloc(1, MAX_ANSWER + 1);
	size_t got = 0;
	if (answer != NULL) {
		for (;;) {
			ssize_t r = read(out[0], answer + got, MAX_ANSWER - got);
			if (r < 0 && errno == EINTR) continue;
			if (r <= 0) break;
			got += (size_t)r;
			if (got == MAX_ANSWER) break;
		}
	}
	close(out[0]);
	int status = 0;
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
	signal(SIGPIPE, old_pipe);
	if (!ok || answer == NULL) { free(answer); return SSH_SK_ERR_GENERAL; }

	/* "ok <flags> <counter> <r hex> <s hex|->"  or  "error <code> <message>" */
	int ret = SSH_SK_ERR_GENERAL;
	char *nl = strchr(answer, '\n');
	if (nl != NULL) *nl = '\0';
	if (strncmp(answer, "error ", 6) == 0) {
		char *msg = NULL;
		long code = strtol(answer + 6, &msg, 10);
		fprintf(stderr, "keytap-sk:%s\n", msg != NULL ? msg : "");
		if (code <= -1 && code >= -5) ret = (int)code;
	} else if (strncmp(answer, "ok ", 3) == 0) {
		char rhex[1024], shex[1024];
		unsigned int fl = 0;
		unsigned long ctr = 0;
		if (sscanf(answer + 3, "%u %lu %1023s %1023s", &fl, &ctr, rhex, shex) == 4 && fl <= 0xff && ctr <= 0xffffffffUL) {
			struct sk_sign_response *resp = calloc(1, sizeof(*resp));
			if (resp != NULL && get_hex(rhex, &resp->sig_r, &resp->sig_r_len) == 0 &&
			    get_hex(shex, &resp->sig_s, &resp->sig_s_len) == 0 && resp->sig_r_len > 0 &&
			    (alg == SSH_SK_ED25519 ? (resp->sig_r_len == 64 && resp->sig_s_len == 0) : resp->sig_s_len > 0)) {
				resp->flags = (uint8_t)fl;
				resp->counter = (uint32_t)ctr;
				*sign_response = resp;
				ret = 0;
			} else if (resp != NULL) {
				free(resp->sig_r);
				free(resp->sig_s);
				free(resp);
			}
		}
	} else {
		fprintf(stderr, "keytap-sk: no answer from the KeyTap bridge (exit %d)\n",
		        WIFEXITED(status) ? WEXITSTATUS(status) : -1);
	}
	free(answer);
	return ret;
}

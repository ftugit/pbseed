// goget — fast self-contained Go installer into node_modules
// Downloads the official Go toolchain tarball, verifies SHA-256,
// unpacks it into <dir>/go, prunes ~80 MB of files not needed for
// compiling (test suites, docs, *_test.go, testdata) and writes go.env.
// Everything Go-related ends up inside <dir> (default: ./node_modules),
// which is excluded from workspace snapshots.
//
// Build:  gcc -O2 -Wall -o goget goget.c -lz
// Usage:  ./goget [target-dir]        (default: node_modules)

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <ftw.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <zlib.h>

#define GOVER "go1.27.1"

/* ---- known SHA-256 for official archives ------------------------------ */
struct known { const char *file, *sha; };
static const struct known KNOWN[] = {
    { GOVER ".linux-amd64.tar.gz",
      "63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445" },
    { GOVER ".linux-arm64.tar.gz",
      "3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec" },
};

static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fprintf(stderr, "goget: error: "); vfprintf(stderr, fmt, ap);
    fputc('\n', stderr); va_end(ap);
    exit(1);
}
static void step(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    printf("==> "); vprintf(fmt, ap);
    printf("\n"); fflush(stdout); va_end(ap);
}

/* ---- SHA-256 ----------------------------------------------------------- */
typedef struct { uint32_t s[8]; uint64_t bits; unsigned char buf[64]; size_t n; } sha256;
static const uint32_t K256[64] = {
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))
static void sha_block(sha256 *c, const unsigned char *p) {
    uint32_t w[64], a,b,d,e,f,g,h,t1,t2,cc; int i;
    for (i=0;i<16;i++) w[i]=(p[4*i]<<24)|(p[4*i+1]<<16)|(p[4*i+2]<<8)|p[4*i+3];
    for (i=16;i<64;i++){uint32_t s0=ROR(w[i-15],7)^ROR(w[i-15],18)^(w[i-15]>>3);
                      uint32_t s1=ROR(w[i-2],17)^ROR(w[i-2],19)^(w[i-2]>>10);
                      w[i]=w[i-16]+s0+w[i-7]+s1;}
    a=c->s[0];b=c->s[1];cc=c->s[2];d=c->s[3];e=c->s[4];f=c->s[5];g=c->s[6];h=c->s[7];
    for (i=0;i<64;i++){
        uint32_t S1=ROR(e,6)^ROR(e,11)^ROR(e,25), ch=(e&f)^((~e)&g);
        t1=h+S1+ch+K256[i]+w[i];
        uint32_t S0=ROR(a,2)^ROR(a,13)^ROR(a,22), mj=(a&b)^(a&cc)^(b&cc);
        t2=S0+mj; h=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2;
    }
    c->s[0]+=a;c->s[1]+=b;c->s[2]+=cc;c->s[3]+=d;c->s[4]+=e;c->s[5]+=f;c->s[6]+=g;c->s[7]+=h;
}
static void sha_write(sha256 *c, const void *data, size_t len) {
    const unsigned char *p = data;
    c->bits += (uint64_t)len*8;
    while (len) {
        size_t k = 64 - c->n; if (k > len) k = len;
        memcpy(c->buf + c->n, p, k); c->n += k; p += k; len -= k;
        if (c->n == 64) { sha_block(c, c->buf); c->n = 0; }
    }
}
static void sha_final(sha256 *c, unsigned char out[32]) {
    uint64_t bits = c->bits;
    unsigned char pad = 0x80;
    sha_write(c, &pad, 1);
    unsigned char z = 0;
    while (c->n != 56) sha_write(c, &z, 1);
    c->bits = bits; // restore (padding must not change length)
    unsigned char lenb[8];
    for (int i=0;i<8;i++) lenb[i] = (bits >> (56-8*i)) & 0xff;
    memcpy(c->buf + 56, lenb, 8);
    sha_block(c, c->buf);
    for (int i=0;i<8;i++){out[4*i]=(c->s[i]>>24)&0xff;out[4*i+1]=(c->s[i]>>16)&0xff;
                          out[4*i+2]=(c->s[i]>>8)&0xff;out[4*i+3]=c->s[i]&0xff;}
}
static int sha256_file(const char *path, unsigned char out[32]) {
    FILE *f = fopen(path, "rb"); if (!f) return -1;
    sha256 c = { .s={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19} };
    unsigned char buf[1<<16]; size_t n;
    while ((n = fread(buf,1,sizeof buf,f)) > 0) sha_write(&c, buf, n);
    int bad = ferror(f); fclose(f);
    if (bad) return -1;
    sha_final(&c, out);
    return 0;
}

/* ---- helpers ----------------------------------------------------------- */
static void mkdirs(const char *path) { // mkdir -p
    char tmp[PATH_MAX]; snprintf(tmp, sizeof tmp, "%s", path);
    for (char *p = tmp+1; *p; p++) if (*p=='/') { *p=0; mkdir(tmp,0755); *p='/'; }
    mkdir(tmp, 0755);
}
static void mkdirs_parent(const char *filepath) {
    char tmp[PATH_MAX]; snprintf(tmp, sizeof tmp, "%s", filepath);
    char *s = strrchr(tmp, '/'); if (s) { *s = 0; if (*tmp) mkdirs(tmp); }
}
static int rm_one(const char *p, const struct stat *st, int t, struct FTW *ftw) {
    (void)st; (void)ftw;
    return t == FTW_DP ? rmdir(p) : unlink(p);
}
static void rm_rf(const char *path) {
    struct stat st; if (lstat(path, &st)) return;
    nftw(path, rm_one, 16, FTW_DEPTH | FTW_PHYS);
}
static int is_suffix(const char *s, const char *suf) {
    size_t ls = strlen(s), lf = strlen(suf);
    return ls >= lf && !strcmp(s + ls - lf, suf);
}

/* ---- prune *_test.go and testdata under src/ --------------------------- */
static void prune_walk(const char *dir) {
    DIR *d = opendir(dir); if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name,".") || !strcmp(e->d_name,"..")) continue;
        char p[PATH_MAX]; snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
        struct stat st;
        if (lstat(p, &st)) continue;
        if (S_ISDIR(st.st_mode)) {
            if (!strcmp(e->d_name, "testdata")) rm_rf(p);
            else prune_walk(p);
        } else if (is_suffix(e->d_name, "_test.go")) unlink(p);
    }
    closedir(d);
}

/* ---- tar.gz extraction -------------------------------------------------- */
static unsigned long long octal(const char *s, size_t n) {
    char b[32]; size_t i = 0;
    while (i < n && i < sizeof b - 1 && s[i]) { b[i] = s[i]; i++; }
    b[i] = 0;
    return strtoull(b, NULL, 8);
}
static void read_exact(gzFile gz, void *buf, size_t n) {
    unsigned char *p = buf;
    while (n) {
        int r = gzread(gz, p, n > INT_MAX ? INT_MAX : (unsigned)n);
        if (r <= 0) die("unexpected end of archive");
        p += r; n -= (size_t)r;
    }
}
static void skip_payload(gzFile gz, unsigned long long size) {
    // tar pads every payload to a multiple of 512 — skip the padding too
    size += (512 - size % 512) % 512;
    unsigned char skip[512];
    while (size) { size_t k = size < 512 ? (size_t)size : 512; read_exact(gz, skip, k); size -= k; }
}
static void extract_targz(const char *tgz, const char *dest) {
    gzFile gz = gzopen(tgz, "rb");
    if (!gz) die("cannot open %s", tgz);
    gzbuffer(gz, 1 << 20);
    unsigned char hdr[512];
    char longname[PATH_MAX]; longname[0] = 0;
    int zero_blocks = 0;
    size_t entries = 0;

    for (;;) {
        read_exact(gz, hdr, 512);
        int allzero = 1;
        for (int i = 0; i < 512; i++) if (hdr[i]) { allzero = 0; break; }
        if (allzero) { if (++zero_blocks >= 2) break; continue; }
        zero_blocks = 0;

        char type = hdr[156];
        unsigned long long size = octal((char*)hdr+124, 12);

        if (type == 'g' || type == 'x') { // PAX headers: skip payload
            skip_payload(gz, size);
            continue;
        }
        if (type == 'L') { // GNU long name
            unsigned long long rem = size; size_t i = 0;
            char b[512];
            while (rem) { read_exact(gz, b, 512);
                          size_t k = rem < 512 ? (size_t)rem : 512;
                          if (i + k < sizeof longname) { memcpy(longname+i, b, k); i += k; }
                          rem = rem > 512 ? rem - 512 : 0; }
            longname[sizeof longname - 1] = 0;
            continue;
        }

        // resolve name
        char namebuf[PATH_MAX];
        char prefix[156], name[101];
        memcpy(prefix, hdr+345, 155); prefix[155] = 0;
        memcpy(name,   hdr+0,   100); name[100]   = 0;
        const char *entry;
        if (longname[0]) entry = longname;
        else if (prefix[0]) { snprintf(namebuf, sizeof namebuf, "%s/%s", prefix, name); entry = namebuf; }
        else entry = name;
        longname[0] = 0;

        // safety: no absolute paths, no ".."
        if (entry[0] == '/' || strstr(entry, "..")) {
            skip_payload(gz, size);
            continue;
        }

        char path[PATH_MAX*2];
        snprintf(path, sizeof path, "%s/%s", dest, entry);
        unsigned long mode = octal((char*)hdr+100, 8) | 0400;

        if (type == '5') { mkdirs(path); entries++; }
        else if (type == '2') { char ln[101]; memcpy(ln, hdr+157, 100); ln[100]=0;
                                mkdirs_parent(path); unlink(path);
                                if (symlink(ln, path)) die("symlink %s: %s", path, strerror(errno));
                                entries++; }
        else if (type == '1') { char ln[101]; memcpy(ln, hdr+157, 100); ln[100]=0;
                                char lp[PATH_MAX*2]; snprintf(lp, sizeof lp, "%s/%s", dest, ln);
                                mkdirs_parent(path); unlink(path);
                                if (link(lp, path)) die("hardlink %s: %s", path, strerror(errno));
                                entries++; }
        else if (type == '0' || type == 0) {
            mkdirs_parent(path);
            FILE *f = fopen(path, "wb");
            if (!f) die("cannot create %s: %s", path, strerror(errno));
            unsigned long long rem = size;
            unsigned char buf[1 << 16];
            while (rem) { size_t k = rem < sizeof buf ? (size_t)rem : sizeof buf;
                          read_exact(gz, buf, k);
                          if (fwrite(buf, 1, k, f) != k) die("write %s failed", path);
                          rem -= k; }
            fclose(f);
            chmod(path, mode & 07777);
            entries++;
            // skip padding
            size_t pad = (512 - size % 512) % 512;
            if (pad) { unsigned char skip[512]; read_exact(gz, skip, pad); }
            continue; // already consumed payload; skip common skip below
        } else { skip_payload(gz, size); continue; }
    }
    gzclose(gz);
    printf("    %zu entries extracted\n", entries);
}

/* ---- main ---------------------------------------------------------------- */
int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : "node_modules";

    struct utsname u; uname(&u);
    if (strcmp(u.sysname, "Linux")) die("unsupported OS: %s (Linux only)", u.sysname);
    const char *arch;
    if (!strcmp(u.machine, "x86_64")) arch = "amd64";
    else if (!strcmp(u.machine, "aarch64")) arch = "arm64";
    else die("unsupported arch: %s", u.machine);

    char fname[128]; snprintf(fname, sizeof fname, "%s.linux-%s.tar.gz", GOVER, arch);
    const char *want_sha = NULL;
    for (size_t i = 0; i < sizeof KNOWN/sizeof *KNOWN; i++)
        if (!strcmp(KNOWN[i].file, fname)) want_sha = KNOWN[i].sha;
    if (!want_sha) die("no known sha256 for %s", fname);

    char absdir[PATH_MAX];
    mkdirs(dir);
    if (!realpath(dir, absdir)) die("realpath(%s): %s", dir, strerror(errno));

    char tgz[PATH_MAX+160]; snprintf(tgz, sizeof tgz, "%s/%s", absdir, fname);
    char url[256];          snprintf(url, sizeof url, "https://go.dev/dl/%s", fname);

    step("downloading %s", fname);
    char cmd[PATH_MAX+512];
    if (system("command -v curl >/dev/null 2>&1") == 0)
        snprintf(cmd, sizeof cmd, "curl -fSL --retry 3 -o '%s' '%s'", tgz, url);
    else if (system("command -v wget >/dev/null 2>&1") == 0)
        snprintf(cmd, sizeof cmd, "wget -q -O '%s' '%s'", tgz, url);
    else die("need curl or wget");
    if (system(cmd) != 0) { unlink(tgz); die("download failed"); }

    step("verifying sha256");
    unsigned char dg[32];
    if (sha256_file(tgz, dg)) die("cannot hash %s", tgz);
    char hex[65]; for (int i = 0; i < 32; i++) sprintf(hex+2*i, "%02x", dg[i]); hex[64]=0;
    if (strcmp(hex, want_sha)) die("sha256 mismatch!\n  want %s\n  got  %s", want_sha, hex);

    char godir[PATH_MAX+16]; snprintf(godir, sizeof godir, "%s/go", absdir);
    if (access(godir, F_OK) == 0) { step("removing old %s/go", absdir); rm_rf(godir); }

    step("extracting into %s/go", absdir);
    extract_targz(tgz, absdir);
    unlink(tgz);

    step("pruning ~80 MB (test/, api/, doc/, misc/, *_test.go, testdata)");
    char p[PATH_MAX+32];
    const char *junk[] = { "test", "api", "doc", "misc" };
    for (size_t i = 0; i < 4; i++) { snprintf(p, sizeof p, "%s/%s", godir, junk[i]); rm_rf(p); }
    snprintf(p, sizeof p, "%s/src", godir); prune_walk(p);

    step("writing %s/go.env", absdir);
    char envp[PATH_MAX+16]; snprintf(envp, sizeof envp, "%s/go.env", absdir);
    FILE *ef = fopen(envp, "w");
    if (!ef) die("cannot write %s", envp);
    fprintf(ef,
        "export GOROOT=%s/go\n"
        "export GOPATH=%s/gopath\n"
        "export GOMODCACHE=$GOPATH/pkg/mod\n"
        "export GOCACHE=%s/gocache\n"
        "export PATH=$GOROOT/bin:$GOPATH/bin:$PATH\n",
        absdir, absdir, absdir);
    fclose(ef);

    printf("\nGo %s (%s) installed into %s/go\n", GOVER, arch, absdir);
    printf("Activate with:  source %s/go.env\n", absdir);
    return 0;
}

/* sitesrv - serve the cached Relapse website straight from PS5 storage.
 *
 * The webkit-autoloader idea (itsPLK), ported to this site with a custom
 * port: after a one-time "Cache site to PS5" from the exploit page (which
 * writes every site file to /data/relapse-site through ROP syscalls), this
 * payload serves that folder over HTTP on port 12423 - on the console
 * itself, fully offline. elfldr loads it from console storage via
 *     echo "file:/data/relapse-site/payloads/sitesrv.elf" | nc <ps5> 9021
 * and the page's PS5SiteCache module does exactly that automatically after
 * every jailbreak.
 *
 * Plain POSIX (sockets + fork + stdio) so the exact same source builds as:
 *   - a PS5 payload (ps5-payload-sdk, `make`)
 *   - a native test binary for the Playwright suite (`make native`)
 *
 * Concurrency: fork per connection (SIGCHLD is ignored, so children are
 * reaped by the kernel). If fork fails the connection is served inline -
 * a browser opening several sockets in parallel still gets every asset.
 */

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SITESRV_VERSION   "1.0"
#define SITESRV_PORT      12423
#define SITESRV_DOCROOT   "/data/relapse-site"

#define REQBUF_MAX   8192
#define PATHBUF_MAX  2048
#define IOBUF_MAX    (64 * 1024)

static const char* g_docroot = SITESRV_DOCROOT;
static int g_port = SITESRV_PORT;

/* ------------------------------------------------------------------ */
/* PS5 notification (same idiom as every ps5-payload-sdk payload)      */
/* ------------------------------------------------------------------ */

#ifdef SITESRV_NATIVE

static void notify(const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  printf("\n");
  fflush(stdout);
  va_end(args);
}

#else /* PS5 payload */

struct sitesrv_notify_request {
  char useless1[45];
  char message[1024];
  char useless2[2051];
};

extern int sceKernelSendNotificationRequest(const size_t,
                                            const struct sitesrv_notify_request*,
                                            const size_t, const int);

static void notify(const char* fmt, ...) {
  struct sitesrv_notify_request buf;
  va_list args;
  memset(&buf, 0, sizeof(buf));
  va_start(args, fmt);
  vsnprintf(buf.message, sizeof(buf.message) - 1, fmt, args);
  va_end(args);
  sceKernelSendNotificationRequest(0, &buf, sizeof(buf), 0);
}

#endif

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static void send_all(int fd, const void* buffer, size_t len) {
  const char* p = (const char*)buffer;
  while(len > 0) {
    ssize_t n = write(fd, p, len);
    if(n < 0) {
      if(errno == EINTR) continue;
      return; /* peer went away - nothing sensible left to do */
    }
    p += n;
    len -= (size_t)n;
  }
}

static void send_str(int fd, const char* s) {
  send_all(fd, s, strlen(s));
}

static const char* mime_for(const char* path) {
  const char* dot = strrchr(path, '.');
  if(!dot) return "application/octet-stream";
  if(!strcasecmp(dot, ".html")) return "text/html; charset=utf-8";
  if(!strcasecmp(dot, ".js"))   return "text/javascript; charset=utf-8";
  if(!strcasecmp(dot, ".css"))  return "text/css; charset=utf-8";
  if(!strcasecmp(dot, ".json")) return "application/json; charset=utf-8";
  if(!strcasecmp(dot, ".png"))  return "image/png";
  if(!strcasecmp(dot, ".jpg") || !strcasecmp(dot, ".jpeg")) return "image/jpeg";
  if(!strcasecmp(dot, ".svg"))  return "image/svg+xml";
  if(!strcasecmp(dot, ".ico"))  return "image/x-icon";
  if(!strcasecmp(dot, ".txt") || !strcasecmp(dot, ".md")) return "text/plain; charset=utf-8";
  if(!strcasecmp(dot, ".elf") || !strcasecmp(dot, ".bin")) return "application/octet-stream";
  return "application/octet-stream";
}

/* Mirror of serve.py's cache policy: HTML always revalidates, offsets are
 * short-lived, JS/payloads cache hard. The PS5 webkit disk cache then keeps
 * the whole site available even before this server runs again. */
static const char* cache_control_for(const char* path) {
  if(strstr(path, "/offsets/")) return "max-age=600";
  if(strstr(path, ".html") || !strrchr(path, '.')) return "no-cache, must-revalidate";
  if(strstr(path, ".js")) return "max-age=604800";
  if(strstr(path, ".elf") || strstr(path, ".bin")) return "max-age=2592000";
  return "max-age=86400";
}

static int hexval(char c) {
  if(c >= '0' && c <= '9') return c - '0';
  if(c >= 'a' && c <= 'f') return c - 'a' + 10;
  if(c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* Decode %XX in place. Returns 0 on success, -1 on malformed input. */
static int url_decode(char* s) {
  char* out = s;
  while(*s) {
    if(*s == '%' && s[1] && s[2]) {
      int hi = hexval(s[1]);
      int lo = hexval(s[2]);
      if(hi < 0 || lo < 0) return -1;
      *out++ = (char)((hi << 4) | lo);
      s += 3;
    } else {
      *out++ = *s++;
    }
  }
  *out = 0;
  return 0;
}

/* Reject anything that could escape the docroot. */
static int path_is_safe(const char* path) {
  if(path[0] != '/') return 0;
  if(strstr(path, "..")) return 0;
  if(strchr(path, '\\')) return 0;
  return 1;
}

/* ------------------------------------------------------------------ */
/* responses                                                           */
/* ------------------------------------------------------------------ */

static void send_error(int fd, int status, const char* reason, int head_only) {
  char body[256];
  char head[512];
  int n;

  n = snprintf(body, sizeof(body),
               "<!DOCTYPE html><html><head><title>%d %s</title></head>"
               "<body><h1>sitesrv: %d %s</h1></body></html>\r\n",
               status, reason, status, reason);
  snprintf(head, sizeof(head),
           "HTTP/1.1 %d %s\r\n"
           "Content-Type: text/html; charset=utf-8\r\n"
           "Content-Length: %d\r\n"
           "Cache-Control: no-cache\r\n"
           "Connection: close\r\n"
           "\r\n",
           status, reason, n);
  send_str(fd, head);
  if(!head_only) send_all(fd, body, (size_t)n);
}

static void send_file(int fd, const char* path, int head_only) {
  char head[512];
  struct stat st;
  int f;

  if(stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
    send_error(fd, 404, "Not Found", head_only);
    return;
  }

  f = open(path, O_RDONLY);
  if(f < 0) {
    send_error(fd, 403, "Forbidden", head_only);
    return;
  }

  snprintf(head, sizeof(head),
           "HTTP/1.1 200 OK\r\n"
           "Content-Type: %s\r\n"
           "Content-Length: %lld\r\n"
           "Cache-Control: %s\r\n"
           "Connection: close\r\n"
           "\r\n",
           mime_for(path), (long long)st.st_size, cache_control_for(path));
  send_str(fd, head);

  if(!head_only) {
    char* buf = malloc(IOBUF_MAX);
    if(buf) {
      ssize_t n;
      while((n = read(f, buf, IOBUF_MAX)) > 0)
        send_all(fd, buf, (size_t)n);
      free(buf);
    }
  }
  close(f);
}

/* ------------------------------------------------------------------ */
/* /manifest.json - live directory listing of payloads (ELF files)      */
/* ------------------------------------------------------------------ */

static int json_escape(char* dst, size_t dstlen, const char* s) {
  size_t o = 0;
  for(; *s; s++) {
    unsigned char c = (unsigned char)*s;
    const char* rep = NULL;
    char tmp[8];
    if(c == '"' || c == '\\') {
      snprintf(tmp, sizeof(tmp), "\\%c", c);
      rep = tmp;
    } else if(c < 0x20) {
      snprintf(tmp, sizeof(tmp), "\\u%04x", c);
      rep = tmp;
    }
    if(rep) {
      size_t rl = strlen(rep);
      if(o + rl + 1 > dstlen) return -1;
      memcpy(dst + o, rep, rl);
      o += rl;
    } else {
      if(o + 2 > dstlen) return -1;
      dst[o++] = (char)c;
    }
  }
  dst[o] = 0;
  return 0;
}

/* Pretty name from a filename: "sitesrv.elf" -> "Sitesrv",
 * "omnipad-ps5_v1.0.4.elf" -> "Omnipad-ps5 v1.0.4". */
static void display_name(char* dst, size_t dstlen, const char* fname) {
  char tmp[256];
  char* dot;
  size_t n = strlen(fname);
  if(n >= sizeof(tmp)) n = sizeof(tmp) - 1;
  memcpy(tmp, fname, n);
  tmp[n] = 0;
  dot = strrchr(tmp, '.');
  if(dot) *dot = 0;
  for(char* p = tmp; *p; p++)
    if(*p == '_') *p = ' ';
  if(tmp[0] >= 'a' && tmp[0] <= 'z') tmp[0] -= 'a' - 'A';
  snprintf(dst, dstlen, "%s", tmp);
}

static int manifest_append(char** buf, size_t* len, size_t* cap,
                           const char* fmt, ...) {
  va_list args;
  int n;
  va_start(args, fmt);
  n = vsnprintf(NULL, 0, fmt, args);
  va_end(args);
  if(n < 0) return -1;
  if(*len + (size_t)n + 1 > *cap) {
    size_t newcap = *cap ? *cap * 2 : 8192;
    char* p;
    while(*len + (size_t)n + 1 > newcap) newcap *= 2;
    p = realloc(*buf, newcap);
    if(!p) return -1;
    *buf = p;
    *cap = newcap;
  }
  va_start(args, fmt);
  vsnprintf(*buf + *len, (size_t)n + 1, fmt, args);
  va_end(args);
  *len += (size_t)n;
  return 0;
}

static void send_manifest(int fd, int head_only) {
  char dirpath[PATHBUF_MAX];
  char head[512];
  DIR* dir;
  struct dirent* ent;
  char* body = NULL;
  size_t len = 0, cap = 0;
  int count = 0;

  snprintf(dirpath, sizeof(dirpath), "%s/payloads", g_docroot);
  dir = opendir(dirpath);
  if(!dir) {
    send_error(fd, 404, "No Payloads", head_only);
    return;
  }

  if(manifest_append(&body, &len, &cap, "{\"source\":\"relapse-site\","
                     "\"generated\":true,\"payloads\":[") != 0) {
    closedir(dir);
    free(body);
    send_error(fd, 500, "Out Of Memory", head_only);
    return;
  }

  while((ent = readdir(dir)) != NULL) {
    const char* fname = ent->d_name;
    char fpath[PATHBUF_MAX];
    char esc[512];
    char name[256];
    struct stat st;
    size_t flen = strlen(fname);

    if(flen < 5 || strcasecmp(fname + flen - 4, ".elf") != 0)
      continue;                          /* only ELF payloads */
    if(!strncmp(fname, "elfldr-ps5", 10))
      continue;                          /* auto-loaded by the chain, noise */
    if(!strncmp(fname, "kexp", 4))
      continue;                          /* kernel shellcode, not sendable */

    snprintf(fpath, sizeof(fpath), "%s/payloads/%s", g_docroot, fname);
    if(stat(fpath, &st) != 0 || !S_ISREG(st.st_mode))
      continue;

    display_name(name, sizeof(name), fname);
    if(json_escape(esc, sizeof(esc), fname) != 0 ||
       manifest_append(&body, &len, &cap,
                       "%s{\"filename\":\"%s\",\"name\":\"%s\","
                       "\"url\":\"payloads/%s\",\"bytes\":%lld,"
                       "\"category\":\"PS5 Storage\","
                       "\"description\":\"Payload stored on this console - "
                       "no internet needed to send it\"}",
                       count ? "," : "", esc, name,
                       esc, (long long)st.st_size) != 0) {
      count = -1;
      break;
    }
    count++;
  }
  closedir(dir);

  if(count < 0 || manifest_append(&body, &len, &cap, "]}") != 0 || !body) {
    free(body);
    send_error(fd, 500, "Manifest Failed", head_only);
    return;
  }

  snprintf(head, sizeof(head),
           "HTTP/1.1 200 OK\r\n"
           "Content-Type: application/json; charset=utf-8\r\n"
           "Content-Length: %zu\r\n"
           "Cache-Control: no-cache\r\n"
           "Connection: close\r\n"
           "\r\n",
           len);
  send_str(fd, head);
  if(!head_only) send_all(fd, body, len);
  free(body);
}

/* ------------------------------------------------------------------ */
/* request handling                                                    */
/* ------------------------------------------------------------------ */

/* Read until the end of the request head (or the buffer fills up). */
static int read_request(int fd, char* buf, size_t buflen) {
  size_t have = 0;
  while(have < buflen - 1) {
    ssize_t n = recv(fd, buf + have, buflen - 1 - have, 0);
    if(n < 0) {
      if(errno == EINTR) continue;
      return -1;
    }
    if(n == 0) break;
    have += (size_t)n;
    buf[have] = 0;
    if(strstr(buf, "\r\n\r\n") || strstr(buf, "\n\n"))
      return 0;
  }
  buf[have] = 0;
  return (strstr(buf, "\r\n\r\n") || strstr(buf, "\n\n")) ? 0 : -1;
}

static void handle_connection(int connfd) {
  char req[REQBUF_MAX];
  char target[PATHBUF_MAX];
  char* method;
  char* path;
  char* sp;
  char* q;
  int head_only;
  struct timeval tv;
#ifdef SO_NOSIGPIPE
  {
    int optval = 1;
    setsockopt(connfd, SOL_SOCKET, SO_NOSIGPIPE, &optval, sizeof(optval));
  }
#endif
  tv.tv_sec = 15;
  tv.tv_usec = 0;
  setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  tv.tv_sec = 30;
  setsockopt(connfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  if(read_request(connfd, req, sizeof(req)) != 0) {
    send_error(connfd, 400, "Bad Request", 0);
    return;
  }

  /* first line: METHOD SP TARGET SP VERSION */
  method = req;
  sp = strchr(req, ' ');
  if(!sp) {
    send_error(connfd, 400, "Bad Request", 0);
    return;
  }
  *sp = 0;
  path = sp + 1;
  sp = strchr(path, ' ');
  if(!sp) {
    send_error(connfd, 400, "Bad Request", 0);
    return;
  }
  *sp = 0;
  /* the rest of the head (headers) is ignored - no request bodies here */

  head_only = !strcmp(method, "HEAD");
  if(!head_only && strcmp(method, "GET") != 0) {
    send_error(connfd, 405, "Method Not Allowed", 0);
    return;
  }

  if(strlen(path) >= sizeof(target)) {
    send_error(connfd, 414, "URI Too Long", head_only);
    return;
  }
  strcpy(target, path);
  q = strchr(target, '?');
  if(q) *q = 0;
  if(url_decode(target) != 0) {
    send_error(connfd, 400, "Bad Request", head_only);
    return;
  }
  if(!path_is_safe(target)) {
    send_error(connfd, 403, "Forbidden", head_only);
    return;
  }

  if(!strcmp(target, "/manifest.json")) {
    send_manifest(connfd, head_only);
    return;
  }

  /* directories (and "/") serve index.html */
  {
    char full[PATHBUF_MAX];
    struct stat st;
    int n = snprintf(full, sizeof(full), "%s%s", g_docroot, target);
    if(n <= 0 || (size_t)n >= sizeof(full)) {
      send_error(connfd, 414, "URI Too Long", head_only);
      return;
    }
    if(stat(full, &st) == 0 && S_ISDIR(st.st_mode)) {
      if(full[n - 1] != '/') {
        full[n] = '/';
        full[n + 1] = 0;
      }
      if(strlen(full) + sizeof("index.html") >= sizeof(full)) {
        send_error(connfd, 414, "URI Too Long", head_only);
        return;
      }
      strcat(full, "index.html");
    }
    send_file(connfd, full, head_only);
  }
}

/* ------------------------------------------------------------------ */
/* server loop                                                         */
/* ------------------------------------------------------------------ */

static void lan_address(char* out, size_t outlen) {
  struct ifaddrs* ifaddr;
  snprintf(out, outlen, "127.0.0.1");
  if(getifaddrs(&ifaddr) != 0)
    return;
  for(struct ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    struct sockaddr_in* in;
    char ip[INET_ADDRSTRLEN];
    if(!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
      continue;
    if(!strncmp("lo", ifa->ifa_name, 2))
      continue;
    in = (struct sockaddr_in*)ifa->ifa_addr;
    if(!inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip)))
      continue;
    if(!strncmp("0.", ip, 2))
      continue;
    snprintf(out, outlen, "%s", ip);
    break;
  }
  freeifaddrs(ifaddr);
}

#ifdef SITESRV_NATIVE
int main(int argc, char** argv) {
  if(argc > 1) g_docroot = argv[1];
  if(argc > 2) g_port = atoi(argv[2]);
#else
int main(void) {
#endif
  struct sockaddr_in srvaddr;
  struct sockaddr_in cliaddr;
  socklen_t socklen;
  char ip[INET_ADDRSTRLEN];
  int srvfd;

  signal(SIGPIPE, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);

  if((srvfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("sitesrv: socket");
    return -1;
  }
  setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

  memset(&srvaddr, 0, sizeof(srvaddr));
  srvaddr.sin_family = AF_INET;
  srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  srvaddr.sin_port = htons((uint16_t)g_port);

  if(bind(srvfd, (struct sockaddr*)&srvaddr, sizeof(srvaddr)) != 0) {
    perror("sitesrv: bind");
    printf("sitesrv: is another copy already serving port %d?\n", g_port);
    return -1;
  }
  if(listen(srvfd, 16) != 0) {
    perror("sitesrv: listen");
    return -1;
  }

  lan_address(ip, sizeof(ip));
  printf("sitesrv v%s - Relapse site on %s:%d (doc: %s)\n",
         SITESRV_VERSION, ip, g_port, g_docroot);
  fflush(stdout);
  notify("Relapse site serving on %s:%d", ip, g_port);

  for(;;) {
    int connfd;
    pid_t pid;

    socklen = sizeof(cliaddr);
    connfd = accept(srvfd, (struct sockaddr*)&cliaddr, &socklen);
    if(connfd < 0) {
      if(errno == EINTR) continue;
      perror("sitesrv: accept");
      sleep(1);
      continue;
    }

    pid = fork();
    if(pid == 0) {
      /* child: one connection, then done */
      close(srvfd);
      handle_connection(connfd);
      close(connfd);
      _exit(0);
    } else if(pid < 0) {
      /* no fork available - serve inline and carry on */
      handle_connection(connfd);
      close(connfd);
    }
    /* parent: the child owns the connection now */
    close(connfd);
  }
}

#include "common.h"

#include <elf.h>
#include <sys/mman.h>
#include <signal.h>

/*
 * koload — a minimal C port of YukiSU ksud's kernelsu_loader: pre-resolve
 * every undefined module symbol against /proc/kallsyms (SHN_ABS), then
 * init_module(). kernelsu.ko can never raw-load on this device: most of its
 * imports are non-exported, and kernel_write/kernel_read are on Samsung's
 * CONFIG_MODULE_SIG_PROTECT list (err -13 = Samsung-signed modules only).
 * Pre-resolution bypasses both checks; whatever happens after init_module
 * is then attributable to the module itself, not the loader.
 */

/* If the ghostlock-trace sentinel exists, fork a busy spinner watching a
 * page shared with the module (ghost_trace_phys param) and fsync every
 * init-step change into the markers log, which survives PANIC_ON_OOPS.
 * Returns child pid (kill after init_module) or -1 when disabled. */
static pid_t ghost_trace_setup(char *params, size_t params_len) {
  if (access("/data/local/tmp/ghostlock-trace", F_OK) != 0)
    return -1;
  void *tpage = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (tpage == MAP_FAILED)
    return -1;
  *(volatile uint64_t *)tpage = 0;
  mlock(tpage, 4096);

  uint64_t ent = 0, pfn = 0;
  int pm = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
  if (pm >= 0) {
    off_t off = (off_t)((uint64_t)(uintptr_t)tpage >> 12) * 8;
    if (pread(pm, &ent, 8, off) == 8 && (ent & (1ULL << 63)))
      pfn = ent & ((1ULL << 55) - 1);
    close(pm);
  }
  if (!pfn) {
    ghost_mark("koload: trace pagemap unavailable");
    munlock(tpage, 4096);
    munmap(tpage, 4096);
    return -1;
  }
  size_t cur = strlen(params);
  snprintf(params + cur, params_len - cur, " ghost_trace_phys=0x%llx",
      (unsigned long long)(pfn << 12));
  ghost_mark("koload: trace page pfn 0x%llx", (unsigned long long)pfn);

  pid_t pid = fork();
  if (pid == 0) {
    /* O_SYNC: every write() is durable on flash before it returns, so the
     * ack below means "this step is in the panic-surviving log". One
     * persistent fd keeps per-step latency ~2ms (vs ~40ms open+fsync). */
    int lf = open("/data/local/tmp/ghostlock-markers.log",
        O_WRONLY | O_APPEND | O_SYNC | O_CLOEXEC);
    volatile uint64_t *page = (volatile uint64_t *)tpage;
    uint64_t last = 0;
    struct timespec hb = { 0, 0 };
    for (;;) {
      uint64_t v = page[0];
      if (v != last) {
        char b[64];
        int n;
        if (v == 0xFFFFULL)
          n = snprintf(b, sizeof(b), "[hb] koload: trace done\n");
        else
          n = snprintf(b, sizeof(b), "[hb] koload: kostep %llu\n",
              (unsigned long long)v);
        if (lf >= 0)
          (void)!write(lf, b, (size_t)n);
        page[1] = v; /* ack only after the durable write completed */
        __sync_synchronize();
        last = v;
        if (v == 0xFFFFULL)
          _exit(0);
        continue;
      }
      struct timespec ts;
      clock_gettime(CLOCK_MONOTONIC, &ts);
      long dms = (ts.tv_sec - hb.tv_sec) * 1000 +
          (ts.tv_nsec - hb.tv_nsec) / 1000000;
      if (dms >= 300) {
        char b[64];
        int n = snprintf(b, sizeof(b), "[hb] spin alive last=%llu\n",
            (unsigned long long)last);
        if (lf >= 0)
          (void)!write(lf, b, (size_t)n);
        hb = ts;
      }
    }
  }
  return pid;
}

int koload_with_kallsyms(const char *path, const char *params) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    ghost_mark("koload: open %s: %s", path, strerror(errno));
    return -1;
  }
  struct stat st;
  if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
    ghost_mark("koload: stat/size failed");
    close(fd);
    return -1;
  }
  size_t size = (size_t)st.st_size;
  uint8_t *buf = malloc(size);
  ssize_t rd = buf ? read(fd, buf, size) : -1;
  close(fd);
  if (rd != (ssize_t)size) {
    ghost_mark("koload: read failed");
    return -1;
  }

  Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
  if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
      eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_type != ET_REL) {
    ghost_mark("koload: not an aarch64 relocatable ELF");
    return -1;
  }

  Elf64_Shdr *sh = (Elf64_Shdr *)(buf + eh->e_shoff);
  Elf64_Shdr *symtab = NULL;
  for (int i = 0; i < eh->e_shnum; i++) {
    if (sh[i].sh_type == SHT_SYMTAB) {
      symtab = &sh[i];
      break;
    }
  }
  if (!symtab) {
    ghost_mark("koload: no symtab");
    return -1;
  }
  const char *strtab = (const char *)(buf + sh[symtab->sh_link].sh_offset);
  Elf64_Sym *syms = (Elf64_Sym *)(buf + symtab->sh_offset);
  size_t nsyms = symtab->sh_size / sizeof(Elf64_Sym);

  /* Collect undef symbols, names normalized like ksud does (strip "$"
   * and ".llvm." suffixes the clang LTO build decorates them with). */
  size_t *undef = malloc(sizeof(size_t) * nsyms);
  char (*names)[128] = malloc(nsyms * 128);
  if (!undef || !names) {
    ghost_mark("koload: oom");
    return -1;
  }
  size_t nundef = 0;
  for (size_t i = 1; i < nsyms; i++) {
    if (syms[i].st_shndx != SHN_UNDEF)
      continue;
    const char *nm = strtab + syms[i].st_name;
    if (!nm[0])
      continue;
    snprintf(names[nundef], 128, "%s", nm);
    char *cut = strchr(names[nundef], '$');
    if (!cut)
      cut = strstr(names[nundef], ".llvm.");
    if (cut)
      *cut = '\0';
    undef[nundef] = i;
    nundef++;
  }
  ghost_mark("koload: %zu undefined symbols to resolve", nundef);

  /* Same trick as ksud's KptrGuard: kptr_restrict=1 so root sees real
   * addresses in /proc/kallsyms (SELinux is permissive post-exploit). */
  int kf = open("/proc/sys/kernel/kptr_restrict", O_WRONLY | O_CLOEXEC);
  if (kf >= 0) {
    if (write(kf, "1", 1) != 1)
      ghost_mark("koload: kptr_restrict write failed: %s", strerror(errno));
    close(kf);
  }

  FILE *ks = fopen("/proc/kallsyms", "re");
  if (!ks) {
    ghost_mark("koload: cannot open /proc/kallsyms: %s", strerror(errno));
    return -1;
  }
  char *resolved = calloc(nundef, 1);
  size_t nresolved = 0;
  char line[512];
  while (nresolved < nundef && fgets(line, sizeof(line), ks)) {
    char *sp = strchr(line, ' ');
    if (!sp)
      continue;
    *sp = '\0';
    uint64_t addr = strtoull(line, NULL, 16);
    if (!addr)
      continue;
    /* line: "<addr> <type> <name> [optional [module]]" */
    char *name = strchr(sp + 1, ' ');
    if (!name)
      continue;
    name++;
    char *end = strpbrk(name, " \t\n");
    if (end)
      *end = '\0';
    for (size_t j = 0; j < nundef; j++) {
      if (!resolved[j] && strcmp(name, names[j]) == 0) {
        syms[undef[j]].st_shndx = SHN_ABS;
        syms[undef[j]].st_value = addr;
        resolved[j] = 1;
        nresolved++;
        break;
      }
    }
  }
  fclose(ks);
  ghost_mark("koload: resolved %zu/%zu", nresolved, nundef);
  for (size_t j = 0; j < nundef; j++)
    if (!resolved[j])
      ghost_mark("koload: UNRESOLVED %s", names[j]);
  free(resolved);
  free(names);
  free(undef);

  char params2[2048];
  snprintf(params2, sizeof(params2), "%s", params ? params : "");
  pid_t tracer = ghost_trace_setup(params2, sizeof(params2));
  ghost_mark("koload: init_module %zu bytes params='%s' ...", size, params2);
  int rc = syscall(__NR_init_module, buf, (unsigned long)size, params2);
  if (tracer > 0)
    kill(tracer, SIGKILL);
  ghost_mark("koload: init_module rc=%d errno=%d (%s)", rc, errno, strerror(errno));
  return rc;
}

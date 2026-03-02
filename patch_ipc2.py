import re

with open('nexus_auditor/ipc_protocol.h', 'r') as f:
    content = f.read()

# Add CMD_EXEC_ELF to aegis_ipc_cmd_t
# I previously used the wrong enum definition file. It is defined in common/types.h!

with open('common/types.h', 'r') as f:
    content2 = f.read()

new_enum = """    CMD_SCATTER_EXEC     = 0x0C,  /* Temporal execution scattering          */
    CMD_STACK_SPOOF      = 0x0D,  /* Stack frame spoofing activation        */
    CMD_EXEC_ELF         = 0x0E,  /* Execute full ELF with args             */"""
content2 = content2.replace("CMD_SCATTER_EXEC     = 0x0C,  /* Temporal execution scattering          */\n    CMD_STACK_SPOOF      = 0x0D,  /* Stack frame spoofing activation        */", new_enum)

with open('common/types.h', 'w') as f:
    f.write(content2)

print("types.h updated successfully.")

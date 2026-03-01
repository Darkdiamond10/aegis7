import re

with open('nexus_auditor/alpha_node.c', 'r') as f:
    content = f.read()

# I need to add the forward declaration or rearrange to fix the warning
new_decl = "aegis_result_t alpha_broadcast_command(aegis_ipc_cmd_t cmd, const uint8_t *payload, size_t len);"

if "alpha_broadcast_command(" in content and new_decl not in content:
    content = content.replace("/* ── Thread: C2 Worker (Botnet) ──────────────────────────────────────────── */", new_decl + "\n\n/* ── Thread: C2 Worker (Botnet) ──────────────────────────────────────────── */")

with open('nexus_auditor/alpha_node.c', 'w') as f:
    f.write(content)

print("alpha_node.c updated successfully to fix the warning.")

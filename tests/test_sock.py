# # # import psutil
# # # import socket
# # #
# # # for conn in psutil.net_connections(kind="inet"):
# # #     proto = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
# # #     print(proto, conn.laddr, conn.raddr, conn.status)
# # dict1=[1,2,3]
# # print(dict1[0])
#
# elif cmd == 'CONFIG_UPDATE':
# # Controller wants to update part of the agent's config
# # (e.g. fim_paths, enable_* flags, thresholds).
# params = message.get('params') or {}
#
# updated_keys = []
# error_message = None
#
# # Handle fim_paths update
# if 'fim_paths' in params:
#     raw_paths = params.get('fim_paths')
#
#     if not isinstance(raw_paths, list) or not all(isinstance(p, str) for p in raw_paths):
#         error_message = 'fim_paths must be a list of strings'
#     else:
#         # Existing FIM paths from config (may be empty or missing).
#         existing = cfg.get("fim_paths") or []
#
#         if raw_paths:
#             # APPEND mode: add new paths on top of existing, de-duplicate.
#             merged = existing + raw_paths
#             seen = set()
#             merged_unique = []
#             for p in merged:
#                 if p not in seen:
#                     seen.add(p)
#                     merged_unique.append(p)
#             cfg['fim_paths'] = merged_unique
#             print('[CFG] Merged FIM paths (existing + new)')
#         else:
#             # Special case: empty list means "clear all FIM paths".
#             cfg['fim_paths'] = []
#             print('[CFG] Cleared all FIM paths')
#
#         updated_keys.append('fim_paths')
#
#         # -------- Feature toggles (booleans) --------
#         bool_fields = [
#             'enable_process_monitor',
#             'enable_network_monitor',
#             'enable_fim',
#             'enable_vulncheck',
#         ]
#         for field in bool_fields:
#             if field in params:
#                 val = params.get(field)
#                 if not isinstance(val, bool):
#                     error_message = f'{field} must be a boolean (true/false)'
#                     break
#                 cfg[field] = val
#                 updated_keys.append(field)
#
#         # -------- Numeric thresholds --------
#         num_fields = [
#             'cpu_spike_percent_over_baseline',
#             'ram_spike_percent_over_baseline',
#         ]
#         if error_message is None:
#             for field in num_fields:
#                 if field in params:
#                     val = params.get(field)
#                     # allow ints or floats; store as int.
#                     if not isinstance(val, (int, float)):
#                         error_message = f'{field} must be a number.'
#                         break
#                     # Simple sanity: no negative thresholds.
#                     if val < 0 or val > 100:
#                         error_message = f'{field} must be between 0 and 100.'
#                         break
#                     cfg[field] = int(val)
#                     updated_keys.append(field)
#
#         if error_message is not None:
#             # Send error result back to controller.
#             result_msg = {
#                 'type': 'command_result',
#                 'command': 'CONFIG_UPDATE',
#                 'command_id': cmd_id,
#                 'status': 'error',
#                 'agent_id': cfg['agent_id'],
#                 'details': {'message': error_message},
#             }
#             try:
#                 send_message(sock, result_msg)
#             except Exception:
#                 pass
#             print(f'[CFG] CONFIG_UPDATE error: {error_message}')
#             return
#
#         # If we updated something, save the config and apply FIM auditing.
#         if updated_keys:
#             save_config(cfg)
#             apply_fim_auditing_from_config(cfg)
#             print(f'[CFG] Updated config keys: {", ".join(updated_keys)}')
#
#         result_msg = {
#             'type': 'command_result',
#             'command': 'CONFIG_UPDATE',
#             'command_id': cmd_id,
#             'status': 'ok',
#             'agent_id': cfg['agent_id'],
#             'details': {
#                 'updated_keys': updated_keys,
#             },
#         }
#         try:
#             send_message(sock, result_msg)
#             print('[<] Sent CONFIG_UPDATE result to controller.')
#         except Exception as e:
#             print(f"[!] Failed to send CONFIG_UPDATE result: {e}")
#
# if error_message is not None:
#     # Send error result back to controller.
#     result_msg = {
#         'type': 'command_result',
#         'command': 'CONFIG_UPDATE',
#         'command_id': cmd_id,
#         'status': 'error',
#         'agent_id': cfg['agent_id'],
#         'details': {'message': error_message},
#     }
#     try:
#         send_message(sock, result_msg)
#     except Exception:
#         pass
#     print(f'[CFG] CONFIG_UPDATE error: {error_message}')
#     return
#
# # If we updated something, save the config and apply FIM auditing.
# if updated_keys:
#     save_config(cfg)
#     apply_fim_auditing_from_config(cfg)
#     print(f'[CFG] Updated config keys: {', '.join(updated_keys)}')
#
# result_msg = {
#     'type': 'command_result',
#     'command': 'CONFIG_UPDATE',
#     'command_id': cmd_id,
#     'status': 'ok',
#     'agent_id': cfg['agent_id'],
#     'details': {
#         'updated_keys': updated_keys,
#     },
# }
# try:
#     send_message(sock, result_msg)
#     print('[<] Sent CONFIG_UPDATE result to controller.')
# except Exception as e:
#     print(f"[!] Failed to send CONFIG_UPDATE result: {e}")
#pragma once

int gd_read_file(char *path, char **buf, size_t *len);
int gd_parse_mac_address_ascii(char *mac_address_ascii, uint8_t *mac_address);
int gd_format_mac_address_string(const uint8_t *mac_address, char *mac_address_string);
int gd_buffer_to_hexstring(const uint8_t *buf, size_t len, uint8_t *hexstring);

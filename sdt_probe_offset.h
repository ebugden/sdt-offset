/*
 * sdt_probe_offset.h
 *
 * Copyright (C) 2017 - Erica Bugden <erica.bugden@efficios.com>
 *                      Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * Determines the offset of a specified SystemTap SDT probe in the specified
 * ELF executable. The fd parameter must be a valid file descriptor that refers
 * to an open ELF executable.
 *
 * Returns the offset on success. Returns -1 if an error occurred.
 */
long get_sdt_probe_offset(int fd, const char *probe_provider,
		const char *probe_name);

/*
 * Determines the offset of a specified function name in the specified
 * ELF executable. The fd parameter must be a valid file descriptor that refers
 * to an open ELF executable.
 *
 * Returns the offset on success. Returns -1 if an error occurred.
 */
long elf_get_function_offset(int fd, const char *func_name);


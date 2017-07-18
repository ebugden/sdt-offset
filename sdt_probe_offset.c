/*
 * sdt_probe_offset.c
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

#include <fcntl.h>
#include <stdio.h>
#include <libelf.h>
#include <gelf.h>
#include <string.h>
#include <unistd.h>
#include "sdt_probe_offset.h"

#define TEXT_SECTION_NAME ".text"
#define NOTE_STAPSDT_STR ".note.stapsdt"

/*
 * Default value of MAXSTRINGLEN in SystemTap is 128 but this value can be
 * changed by the user.
 */
#define MAX_STR_LEN 128
#define ARRAY_LEN(a) sizeof(a)/sizeof(a[0])

/*
 * Convert the virtual address in binary to the offset of the instruction in the
 * binary file.
 * Returns the offset on success,
 * Returns -1 in case of failure
 */
static long convert_addr_to_offset(Elf *elf_handle, size_t addr)
{
	long ret;
	int text_section_found;
	size_t text_section_offset, text_section_addr, offset_in_section;
	char *section_name;
	size_t section_idx;
	Elf_Scn *elf_section;
	GElf_Shdr elf_section_hdr;
	
	if (!elf_handle) {
		fprintf (stderr , "Invalid ELF handle.\n");
		ret = -1; 
		goto err;
	}	

	ret = elf_getshdrstrndx(elf_handle, &section_idx);
	if (ret) {
		fprintf(stderr, "ELF get header index failed: %s.\n", elf_errmsg(-1));
		ret = -1; 
		goto err;
	}

	elf_section = NULL;
	text_section_found = 0;

	while((elf_section = elf_nextscn(elf_handle, elf_section)) != NULL) {
		if (gelf_getshdr(elf_section, &elf_section_hdr) == NULL) {
			fprintf(stderr,
				"GELF get section header failed: %s.\n", elf_errmsg(-1));
			ret = -1;
			goto err;
		}

		section_name = elf_strptr(elf_handle, section_idx, elf_section_hdr.sh_name);
		if (section_name == NULL) {
			fprintf(stderr,
				"ELF retrieve string pointer failed: %s.\n", elf_errmsg(-1));
			ret = -1;
			goto err;
		}

		if (strncmp(section_name, TEXT_SECTION_NAME, sizeof(TEXT_SECTION_NAME)) == 0) {
			text_section_offset = elf_section_hdr.sh_offset;
			text_section_addr = elf_section_hdr.sh_addr;
			text_section_found = 1;
			break;
		}
	}

	if (!text_section_found) {
		fprintf(stderr, "Text section not found in binary.\n");
		ret = -1;
		goto err;
	}

	/*
	 * To find the offset of the addr from the beginning of the .text
	 * section.
	 */
	offset_in_section = addr - text_section_addr;
			      
	/*
	 * Add the offset in the section to the offset of the section from the
	 * beginning of the binary.
	 */
	ret = text_section_offset + offset_in_section;

err:
	return ret;
}

long get_sdt_probe_offset(int fd, char *probe_provider, char *probe_name)
{
	long ret;
	int stap_note_section_found, probe_provider_found, probe_name_found;
	char *section_name, *note_probe_provider, *note_probe_name;
	Elf *elf_handle;
	size_t section_idx;
	Elf_Scn *elf_section;
	GElf_Shdr elf_section_hdr;
	Elf_Data *elf_section_data_desc;

	if (probe_provider == NULL) {
		fprintf(stderr, "Invalid probe provider.\n");
		ret = -1;
		goto err;
	}

	if (probe_name == NULL) {
		fprintf(stderr, "Invalid probe name.\n");
		ret = -1;
		goto err;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr,
			"ELF library initialization failed: %s.\n", elf_errmsg(-1));
		ret = -1;
		goto err;
	}

	elf_handle = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf_handle) {
		fprintf (stderr , "elf_begin() failed: %s.\n" , elf_errmsg (-1));
		ret = -1; 
		goto err;
	}	

	ret = elf_getshdrstrndx(elf_handle, &section_idx);
	if (ret) {
		fprintf(stderr, "ELF get header index failed: %s.\n", elf_errmsg(-1));
		ret = -1; 
		goto err2;
	}

	elf_section = NULL;
	elf_section_data_desc = NULL;
	stap_note_section_found = 0;

	/*
	 * Search ELF sections for stap note section which contains probe
	 * descriptions.
	 */
	while ((elf_section = elf_nextscn(elf_handle, elf_section)) != NULL) {
		size_t next_note, note_offset, note_name_offset, note_desc_offset,
			size_probe_data;
		char *section_data_ptr, *elf_format;
		GElf_Nhdr note_hdr;

		/*
		 * System is assumed to be 64 bit.
		 * TODO Add support for 32 bit systems
		 * TODO Change probe_data array to probe_addr and only translate the
		 * address
		 */
		Elf64_Addr probe_data[3];

		/*
		 * Will contain the in-file and in-memory representations of the probe
		 * data.
		 */
		Elf_Data probe_data_in_file, probe_data_in_mem;

		if (gelf_getshdr(elf_section, &elf_section_hdr) == NULL) {
			fprintf(stderr,
				"GELF get section header failed: %s.\n", elf_errmsg(-1));
			ret = -1;
			goto err2;
		}

		section_name = elf_strptr(elf_handle, section_idx, elf_section_hdr.sh_name);
		if (section_name == NULL) {
			fprintf(stderr,
				"ELF retrieve string pointer failed: %s.\n", elf_errmsg(-1));
			ret = -1;
			goto err2;
		}

		if (strncmp(section_name, NOTE_STAPSDT_STR, sizeof(NOTE_STAPSDT_STR)) != 0) {
			continue;
		}

		stap_note_section_found = 1;

		elf_section_data_desc = elf_getdata(elf_section, NULL);
		if (elf_section_data_desc == NULL) {
			fprintf(stderr, "ELF get data failed: %s.\n", elf_errmsg(-1));
			ret = -1;
			goto err2;
		}

		size_probe_data = gelf_fsize(elf_handle, ELF_T_ADDR,
			ARRAY_LEN(probe_data), EV_CURRENT);

		probe_data_in_mem.d_buf = &probe_data;
		probe_data_in_mem.d_type = ELF_T_ADDR;
		probe_data_in_mem.d_version = EV_CURRENT;
		probe_data_in_mem.d_size = size_probe_data;

		probe_data_in_file.d_buf = NULL;
		probe_data_in_file.d_type = ELF_T_ADDR;
		probe_data_in_file.d_version = EV_CURRENT;
		probe_data_in_file.d_size = probe_data_in_mem.d_size;

		section_data_ptr = (char*)elf_section_data_desc->d_buf;
		note_offset = 0;
		probe_provider_found = 0;
		probe_name_found = 0;
		note_probe_provider = "";
		note_probe_name = "";
		next_note = gelf_getnote(elf_section_data_desc, note_offset, &note_hdr,
			&note_name_offset, &note_desc_offset);

		/*
		 * Search in the stap note section for a probe description matching the
		 * requested probe provider and probe name.
		 */
		while (next_note > 0) {
			/*
			 * Set source of data to be translated to the beginning of the
			 * current note's data.
			 */
			probe_data_in_file.d_buf = section_data_ptr + note_desc_offset;

			/*
			 * Translate ELF data to in-memory representation in order to
			 * respect byte ordering and data alignment restrictions
			 * of the host processor.
			 */
			elf_format = elf_getident(elf_handle, NULL);
			if (gelf_xlatetom(elf_handle, &probe_data_in_mem, &probe_data_in_file,
				elf_format[EI_DATA]) == NULL) {
				fprintf(stderr, "GELF Translation from file "
					"to memory representation failed: %s.\n", elf_errmsg(-1));
				ret = -1;
				goto err2;
			}

			/*
			 * Retrieve the provider and name of the probe in the note section.
			 * Structure of the data in the note is defined in the systemtap
			 * header sdt.h.
			 */
			note_probe_provider = section_data_ptr + note_desc_offset
				+ probe_data_in_mem.d_size;
			note_probe_name = note_probe_provider + strlen(note_probe_provider) + 1;

			if (strncmp(note_probe_provider, probe_provider, strnlen(probe_provider,
				MAX_STR_LEN)) == 0) {
				probe_provider_found = 1;

				if (strncmp(note_probe_name, probe_name, strnlen(probe_name,
					MAX_STR_LEN)) == 0) {
					probe_name_found = 1;
					break;
				}
			}

			note_offset = next_note;
			next_note = gelf_getnote(elf_section_data_desc, note_offset,
				&note_hdr, &note_name_offset, &note_desc_offset);
		}

		if (!probe_provider_found) {
			fprintf(stderr, "No provider %s found.\n", probe_provider);
			ret = -1;
			goto err2;
		}

		if (!probe_name_found) {
			fprintf(stderr, "No probe with name %s found for provider %s.\n",
				probe_name, probe_provider);
			ret = -1;
			goto err2;
		}

		ret = convert_addr_to_offset(elf_handle, probe_data[0]);
		if (ret == -1) {
			fprintf(stderr,	"Conversion from address to offset in binary "
				"failed. Address: %lu\n", probe_data[0]);
			ret = -1;
			goto err2;
		}
	}

	if (!stap_note_section_found) {
		fprintf(stderr, "%s not found in binary. No SDT probes.\n",
			NOTE_STAPSDT_STR);
		ret = -1;
		goto err2;
	}

err2:
	elf_end(elf_handle);
err:
	return ret;
}

long elf_get_function_offset(int fd, char *func_name)
{
	long ret;
	char *section_name, *sym_name;
	Elf *elf_handle;
	size_t section_idx;
	Elf_Scn *elf_section;
	GElf_Shdr elf_section_hdr;
	Elf_Data *elf_section_data_desc;
	GElf_Sym sym;
	int sym_table_found, sym_found, sym_count;

	if (func_name == NULL) {
		fprintf(stderr, "Invalid function name.\n");
		ret = -1;
		goto err;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "ELF library initialization failed: %s.\n",
			elf_errmsg(-1));
		ret = -1;
		goto err;
	}

	elf_handle = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf_handle) {
		fprintf (stderr , "elf_begin() failed: %s.\n" , elf_errmsg (-1));
		ret = -1;
		goto err;
	}

	ret = elf_getshdrstrndx(elf_handle, &section_idx);
	if (ret) {
		fprintf(stderr, "ELF get header index failed: %s.\n", elf_errmsg(-1));
		ret = -1;
		goto err2;
	}

	elf_section = NULL;
	elf_section_data_desc = NULL;
	sym_table_found = 0;

	/*
	 * Loop over ELF sections to find symbol table.
	 */
	while ((elf_section = elf_nextscn(elf_handle, elf_section)) != NULL) {
		int sym_idx;

		if (gelf_getshdr(elf_section, &elf_section_hdr) == NULL) {
			fprintf(stderr,	"GELF get section header failed: %s.\n",
				elf_errmsg(-1));
			ret = -1;
			goto err2;
		}

		if (elf_section_hdr.sh_type != SHT_SYMTAB) {
			continue;
		}

		sym_table_found = 1;

		section_name = elf_strptr(elf_handle, section_idx, elf_section_hdr.sh_name);
		if (section_name == NULL) {
			fprintf(stderr, "ELF retrieve string pointer failed: %s.\n",
				elf_errmsg(-1));
			ret = -1;
			goto err2;
		}

		elf_section_data_desc = elf_getdata(elf_section, NULL);
		if (elf_section_data_desc == NULL) {
			fprintf(stderr, "ELF get data failed: %s.\n", elf_errmsg(-1));
			ret = -1;
			goto err2;
		}

		sym_count = elf_section_hdr.sh_size / elf_section_hdr.sh_entsize;
		sym_name = NULL;
		sym_found = 0;

		/*
		 * Loop over all symbols in symbol table and compare them against
		 * the requested symbol.
		 */
		for (sym_idx = 0; sym_idx < sym_count; sym_idx++) {
			if (gelf_getsym(elf_section_data_desc, sym_idx, &sym) == NULL) {
				fprintf(stderr, "GELF get symbol failed: %s.\n",
					elf_errmsg(-1));
				ret = -1;
				goto err2;
			}

			sym_name = elf_strptr(elf_handle, elf_section_hdr.sh_link, sym.st_name);
			if (sym_name == NULL) {
				fprintf(stderr, "ELF retrieve string pointer failed: %s.\n",
					elf_errmsg(-1));
				ret = -1;
				goto err2;
			}

			if (strcmp(sym_name, func_name) == 0) {
				sym_found = 1;
				break;
			}
		}

		if (!sym_found) {
			fprintf(stderr, "Requested symbol %s does not exist in symbol "
				"table.\n", func_name);
			ret = -1;
			goto err2;
		}

		if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC) {
			fprintf(stderr, "Requested symbol %s does not refer to a "
				"function.\n", func_name);
			ret = -1;
			goto err2;
		}

		ret = convert_addr_to_offset(elf_handle, sym.st_value);
		if (ret == -1) {
			fprintf(stderr, "Conversion from address to offset in binary "
				"failed. Address: %lu\n", sym.st_value);
			ret = -1;
			goto err2;
		}
	}

	if (!sym_table_found) {
		fprintf(stderr, "No symbol table in binary.\n");
		ret = -1;
		goto err2;
	}

err2:
	elf_end(elf_handle);
err:
	return ret;
}

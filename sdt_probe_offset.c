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
#include <stdbool.h>

#define TEXT_SECTION_NAME 	".text"
#define NOTE_STAPSDT_STR	".note.stapsdt"

/*
 * Default value of MAXSTRINGLEN in SystemTap is 128 but this value can be
 * changed by the user.
 */
#define MAX_STR_LEN	128
#define ARRAY_LEN(a)	(sizeof(a) / sizeof(a[0]))

/*
 * Convert the virtual address in a binary's mapping to the offset of
 * the corresponding instruction in the binary file.
 *
 * Returns the offset on success or -1 in case of failure.
 */
static long convert_addr_to_offset(Elf *elf_handle, size_t addr)
{
	long ret;
	bool text_section_found = false;
	size_t text_section_offset, text_section_addr, offset_in_section;
	char *section_name;
	size_t section_idx;
	Elf_Scn *elf_section = NULL;
	GElf_Shdr elf_section_hdr;
	
	if (!elf_handle) {
		fprintf (stderr, "Invalid ELF handle.\n");
		ret = -1; 
		goto error;
	}	

	ret = elf_getshdrstrndx(elf_handle, &section_idx);
	if (ret) {
		fprintf(stderr, "ELF get header index failed: %s.\n",
				elf_errmsg(-1));
		ret = -1; 
		goto error;
	}

	while((elf_section = elf_nextscn(elf_handle, elf_section)) != NULL) {
		if (gelf_getshdr(elf_section, &elf_section_hdr) == NULL) {
			fprintf(stderr, "GELF get section header failed: %s.\n",
					elf_errmsg(-1));
			ret = -1;
			goto error;
		}

		section_name = elf_strptr(elf_handle, section_idx,
				elf_section_hdr.sh_name);
		if (section_name == NULL) {
			fprintf(stderr, "ELF retrieve string pointer failed: %s.\n",
					elf_errmsg(-1));
			ret = -1;
			goto error;
		}

		if (strncmp(section_name, TEXT_SECTION_NAME,
				sizeof(TEXT_SECTION_NAME)) == 0) {
			text_section_offset = elf_section_hdr.sh_offset;
			text_section_addr = elf_section_hdr.sh_addr;
			text_section_found = true;
			break;
		}
	}

	if (!text_section_found) {
		fprintf(stderr, "Text section not found in binary.\n");
		ret = -1;
		goto error;
	}

	/*
	 * To find the offset of the addr from the beginning of the .text
	 * section.
	 */
	if (text_section_addr > addr) {
		fprintf(stderr, "Invalid section address found: addr=%zux, text_section_addr=%zux.\n",
				addr, text_section_addr);
		ret = -1;
		goto error;
	}
	offset_in_section = addr - text_section_addr;
			      
	/*
	 * Add the offset in the section to the offset of the section from the
	 * beginning of the binary's file.
	 */
	ret = text_section_offset + offset_in_section;

error:
	return ret;
}

long get_sdt_probe_offset(int fd, const char *probe_provider,
		const char *probe_name)
{
	long ret;
	bool stap_note_section_found = false;
	bool probe_provider_found = false;
	bool probe_name_found = false;
	char *section_name;
	char *note_probe_provider_name = "";
	char *note_probe_name = "";
	Elf *elf_handle;
	size_t section_idx;
	Elf_Scn *elf_section = NULL;
	GElf_Shdr elf_section_hdr;
	Elf_Data *elf_section_data_desc = NULL;

	if (probe_provider == NULL || probe_provider[0] == '\0') {
		fprintf(stderr, "Invalid probe provider.\n");
		ret = -1;
		goto error;
	}

	if (probe_name == NULL || probe_name[0] == '\0') {
		fprintf(stderr, "Invalid probe name.\n");
		ret = -1;
		goto error;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "ELF library initialization failed: %s.\n",
				elf_errmsg(-1));
		ret = -1;
		goto error;
	}

	elf_handle = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf_handle) {
		fprintf(stderr, "elf_begin() failed: %s.\n", elf_errmsg(-1));
		ret = -1; 
		goto error;
	}	

	ret = elf_getshdrstrndx(elf_handle, &section_idx);
	if (ret) {
		fprintf(stderr, "ELF get header index failed: %s.\n",
				elf_errmsg(-1));
		ret = -1; 
		goto error_free;
	}

	/*
	 * Search ELF sections for stap note section which contains probe
	 * descriptions.
	 */
	while ((elf_section = elf_nextscn(elf_handle, elf_section)) != NULL) {
		/*
		 * TODO The body of this loop (and the other while-loop it
		 * contains) should eventually be moved to separate functions.
		 *
		 * I would tend to structure the code as:
		 *   - get_sdt_probe_offset()
		 *     - get_elf_section(..., const char *the_section_name)
		 *     - if found, use the returned elf_section:
		 *       - get_probe_addr(section, provider, probe_name)
		 *     - if an address is returned, convert it to a file offset.
		 */
		size_t next_note, note_name_offset,note_desc_offset,
				probe_data_size;
		size_t note_offset = 0;
		char *section_data_ptr, *elf_format;
		GElf_Nhdr note_hdr;

		/*
		 * System is assumed to be 64 bit.
		 * TODO Add support for 32 bit systems.
		 * TODO Change probe_data array to probe_addr and only translate
		 * the address.
		 * TODO Document why the array's size is 3.
		 */
		Elf64_Addr probe_data[3];

		/*
		 * Will contain the in-file and in-memory representations of the
		 * probe data.
		 *
		 * TODO Check if those structures contain fields that we are not
		 * initializing explicitly, in which case it would be safer to
		 * zero-out their content (using memset()).
		 */
		Elf_Data probe_data_in_file, probe_data_in_mem;

		if (gelf_getshdr(elf_section, &elf_section_hdr) == NULL) {
			fprintf(stderr, "GELF get section header failed: %s.\n",
					elf_errmsg(-1));
			ret = -1;
			goto error_free;
		}

		section_name = elf_strptr(elf_handle, section_idx,
				elf_section_hdr.sh_name);
		if (section_name == NULL) {
			fprintf(stderr, "ELF retrieve string pointer failed: %s.\n",
					elf_errmsg(-1));
			ret = -1;
			goto error_free;
		}

		if (strncmp(section_name, NOTE_STAPSDT_STR,
				sizeof(NOTE_STAPSDT_STR)) != 0) {
			continue;
		}

		stap_note_section_found = true;

		elf_section_data_desc = elf_getdata(elf_section, NULL);
		if (elf_section_data_desc == NULL) {
			fprintf(stderr, "ELF get data failed: %s.\n",
					elf_errmsg(-1));
			ret = -1;
			goto error_free;
		}

		probe_data_size = gelf_fsize(elf_handle, ELF_T_ADDR,
				ARRAY_LEN(probe_data), EV_CURRENT);

		probe_data_in_mem.d_buf = &probe_data;
		probe_data_in_mem.d_type = ELF_T_ADDR;
		probe_data_in_mem.d_version = EV_CURRENT;
		probe_data_in_mem.d_size = probe_data_size;

		probe_data_in_file.d_buf = NULL;
		probe_data_in_file.d_type = ELF_T_ADDR;
		probe_data_in_file.d_version = EV_CURRENT;
		probe_data_in_file.d_size = probe_data_in_mem.d_size;

		section_data_ptr = (char *) elf_section_data_desc->d_buf;
		next_note = gelf_getnote(elf_section_data_desc, note_offset,
				&note_hdr, &note_name_offset,
				&note_desc_offset);

		/*
		 * Search in the stap note section for a probe description
		 * matching the requested probe provider and probe name.
		 */
		while (next_note > 0) {
			/*
			 * Set source of data to be translated to the beginning
			 * of the current note's data.
			 */
			probe_data_in_file.d_buf = section_data_ptr +
					note_desc_offset;

			/*
			 * Translate ELF data to in-memory representation in
			 * order to respect byte ordering and data alignment
			 * restrictions of the host processor.
			 */
			elf_format = elf_getident(elf_handle, NULL);
			if (gelf_xlatetom(elf_handle, &probe_data_in_mem,
					&probe_data_in_file,
					elf_format[EI_DATA]) == NULL) {
				fprintf(stderr, "GELF Translation from file to memory "
						"representation failed: %s.\n",
						elf_errmsg(-1));
				ret = -1;
				goto error_free;
			}

			/*
			 * Retrieve the provider and name of the probe in the
			 * note section. The structure of the data in the note
			 * is defined in the systemtap header (sdt.h).
			 */
			note_probe_provider_name = section_data_ptr +
					note_desc_offset +
					probe_data_in_mem.d_size;
			note_probe_name = note_probe_provider_name +
					strlen(note_probe_provider_name) + 1;

			if (strncmp(note_probe_provider_name, probe_provider,
					MAX_STR_LEN) == 0) {
				probe_provider_found = true;

				if (strncmp(note_probe_name, probe_name,
						MAX_STR_LEN) == 0) {
					probe_name_found = true;
					break;
				}
			}

			note_offset = next_note;
			next_note = gelf_getnote(elf_section_data_desc,
					note_offset, &note_hdr,
					&note_name_offset, &note_desc_offset);
		}

		if (!probe_provider_found) {
			fprintf(stderr, "No provider \"%s\" found.\n",
					probe_provider);
			ret = -1;
			goto error_free;
		}

		if (!probe_name_found) {
			fprintf(stderr, "No probe with name \"%s\" found for provider \"%s\".\n",
					probe_name, probe_provider);
			ret = -1;
			goto error_free;
		}

		ret = convert_addr_to_offset(elf_handle, probe_data[0]);
		if (ret == -1) {
			fprintf(stderr,	"Conversion from address to offset in "
					"binary failed. Address: %lu\n",
					probe_data[0]);
			ret = -1;
			goto error_free;
		}
	}

	if (!stap_note_section_found) {
		fprintf(stderr, "Section \"%s\" not found in binary. No SDT probes.\n",
				NOTE_STAPSDT_STR);
		ret = -1;
		goto error_free;
	}

error_free:
	elf_end(elf_handle);
error:
	return ret;
}

long elf_get_function_offset(int fd, const char *func_name)
{
	long ret;
	char *section_name, *sym_name;
	Elf *elf_handle;
	size_t section_idx;
	Elf_Scn *elf_section = NULL;
	GElf_Shdr elf_section_hdr;
	Elf_Data *elf_section_data_desc = NULL;
	GElf_Sym sym;
	int sym_count;
	bool sym_table_found = false;
	bool sym_found;

	if (func_name == NULL || func_name[0] == '\0') {
		fprintf(stderr, "Invalid function name.\n");
		ret = -1;
		goto error;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "ELF library initialization failed: %s.\n",
				elf_errmsg(-1));
		ret = -1;
		goto error;
	}

	elf_handle = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf_handle) {
		fprintf(stderr, "elf_begin() failed: %s.\n", elf_errmsg(-1));
		ret = -1;
		goto error;
	}

	ret = elf_getshdrstrndx(elf_handle, &section_idx);
	if (ret) {
		fprintf(stderr, "ELF get header index failed: %s.\n",
				elf_errmsg(-1));
		ret = -1;
		goto error_free;
	}

	/* Loop over ELF sections to find the symbol table. */
	/*
	 * TODO Right now, the loop's body iterates over the sections
	 * and skips to the next iteration if the section is not the
	 * symbol table. After the continue, the rest of the loop's body
	 * assumes that the section was found and starts looking for the
	 * symbol we are looking for.
	 *
	 * I suggest you break out of the loop as soon as the symbol table is
	 * found and then look for the symbol (or goto error if the table was
	 * not found). This will decrease the overall indentation level of the
	 * code and bring the nested for-loop out of the while's body.
	 */
	while ((elf_section = elf_nextscn(elf_handle, elf_section)) != NULL) {
		int sym_idx;

		if (gelf_getshdr(elf_section, &elf_section_hdr) == NULL) {
			fprintf(stderr,	"GELF get section header failed: %s.\n",
					elf_errmsg(-1));
			ret = -1;
			goto error_free;
		}

		if (elf_section_hdr.sh_type != SHT_SYMTAB) {
			continue;
		}

		sym_table_found = true;

		section_name = elf_strptr(elf_handle, section_idx,
				elf_section_hdr.sh_name);
		if (section_name == NULL) {
			fprintf(stderr, "ELF retrieve string pointer failed: %s.\n",
					elf_errmsg(-1));
			ret = -1;
			goto error_free;
		}

		elf_section_data_desc = elf_getdata(elf_section, NULL);
		if (elf_section_data_desc == NULL) {
			fprintf(stderr, "ELF get data failed: %s.\n", elf_errmsg(-1));
			ret = -1;
			goto error_free;
		}

		sym_count = elf_section_hdr.sh_size /
				elf_section_hdr.sh_entsize;
		sym_name = NULL;
		sym_found = false;

		/*
		 * Loop over all symbols in symbol table and compare them
		 * against the requested symbol.
		 */
		for (sym_idx = 0; sym_idx < sym_count; sym_idx++) {
			if (gelf_getsym(elf_section_data_desc, sym_idx, &sym) ==
					NULL) {
				fprintf(stderr, "GELF get symbol failed: %s.\n",
						elf_errmsg(-1));
				ret = -1;
				goto error_free;
			}

			sym_name = elf_strptr(elf_handle,
					elf_section_hdr.sh_link, sym.st_name);
			if (sym_name == NULL) {
				fprintf(stderr, "ELF retrieve string pointer failed: %s.\n",
						elf_errmsg(-1));
				ret = -1;
				goto error_free;
			}

			if (strncmp(sym_name, func_name, MAX_STR_LEN) == 0) {
				sym_found = true;
				break;
			}
		}

		if (!sym_found) {
			fprintf(stderr, "Requested symbol %s does not exist in symbol "
					"table.\n", func_name);
			ret = -1;
			goto error_free;
		}

		if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC) {
			fprintf(stderr, "Requested symbol %s does not refer to a "
					"function.\n", func_name);
			ret = -1;
			goto error_free;
		}

		ret = convert_addr_to_offset(elf_handle, sym.st_value);
		if (ret == -1) {
			fprintf(stderr, "Conversion from address to offset in binary "
					"failed. Address: %lu\n", sym.st_value);
			ret = -1;
			goto error_free;
		}
	}

	if (!sym_table_found) {
		fprintf(stderr, "No symbol table found in binary.\n");
		ret = -1;
		goto error_free;
	}

error_free:
	elf_end(elf_handle);
error:
	return ret;
}

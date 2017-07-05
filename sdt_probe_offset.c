#include <fcntl.h>
#include <stdio.h>
#include <libelf.h>
#include <gelf.h>
#include <string.h>
#include <unistd.h>
#include "sdt_probe_offset.h"

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
	size_t section_index;
	Elf_Scn *elf_section;
	GElf_Shdr elf_section_header;
	
	if (!elf_handle) {
		fprintf (stderr , "Invalid ELF handle.\n");
		ret = -1; 
		goto err;
	}	

	ret = elf_getshdrstrndx(elf_handle, &section_index);
	if (ret) {
		fprintf(stderr, "ELF get header index failed: %s.\n", elf_errmsg(-1));
		ret = -1; 
		goto err;
	}

	elf_section = NULL;
	text_section_found = 0;

	while((elf_section = elf_nextscn(elf_handle, elf_section)) != NULL) {
		if (gelf_getshdr(elf_section, &elf_section_header) != &elf_section_header) {
			fprintf(stderr, "GELF get section header failed: %s.\n", elf_errmsg(-1));
			ret = -1;
			goto err;
		}

		if ((section_name = elf_strptr(elf_handle, section_index, elf_section_header.sh_name)) == NULL) {
			fprintf(stderr, "ELF retrieve string pointer failed: %s.\n", elf_errmsg(-1));
			ret = -1;
			goto err;
		}

		if (strncmp(section_name, ".text", 5) == 0) {
			text_section_offset = elf_section_header.sh_offset;
			text_section_addr = elf_section_header.sh_addr;
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

long get_sdt_probe_offset(int fd, char *probe_name)
{
	long ret;
	char *section_name;
	char *name;
	Elf *elf_handle;
	size_t section_index;
	Elf_Scn *elf_section;
	GElf_Shdr elf_section_header;
	Elf_Data *elf_data;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "ELF library initialization failed: %s.\n", elf_errmsg(-1));
		ret = -1;
		goto err;
	}

	elf_handle = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf_handle) {
		fprintf (stderr , "elf_begin() failed: %s.\n" , elf_errmsg (-1));
		ret = -1; 
		goto err;
	}	

	ret = elf_getshdrstrndx(elf_handle, &section_index);
	if (ret) {
		fprintf(stderr, "ELF get header index failed: %s.\n", elf_errmsg(-1));
		ret = -1; 
		goto err2;
	}

	elf_section = NULL;
	elf_data = NULL;

	while ((elf_section = elf_nextscn(elf_handle, elf_section)) != NULL) {
		if (gelf_getshdr(elf_section, &elf_section_header) != &elf_section_header) {
			fprintf(stderr, "GELF get section header failed: %s.\n", elf_errmsg(-1));
			ret = -1;
			goto err2;
		}

		if ((section_name = elf_strptr(elf_handle, section_index, elf_section_header.sh_name)) == NULL) {
			fprintf(stderr, "ELF retrieve string pointer failed: %s.\n", elf_errmsg(-1));
			ret = -1;
			goto err2;
		}

		if (strcmp(section_name, ".note.stapsdt") != 0) {
			continue;
		}

		elf_data = elf_getdata(elf_section, NULL);

		size_t next;
		GElf_Nhdr nhdr;
		size_t name_offset;
		size_t desc_offset;

		name = "";

		for (size_t offset = 0;
		  (next = gelf_getnote(elf_data, offset, &nhdr, &name_offset, &desc_offset)) > 0, strcmp(name, probe_name) != 0;
		  offset = next) {
			char *cdata = (char*)elf_data->d_buf;

			/*
			 * System is assumed to be 64 bit.
			 * TODO Add support for 32 bit systems
			 */
			Elf64_Addr buf[3];

			Elf_Data dst = {
				&buf, ELF_T_ADDR, EV_CURRENT,
				gelf_fsize(elf_handle, ELF_T_ADDR, 3, EV_CURRENT), 0, 0
			};

			if (nhdr.n_descsz < dst.d_size + 3) {
				continue;
			}

			Elf_Data src = {
				cdata + desc_offset, ELF_T_ADDR, EV_CURRENT,
				dst.d_size, 0, 0
			};

			if (gelf_xlatetom(elf_handle, &dst, &src, elf_getident(elf_handle, NULL)[EI_DATA]) == NULL) {
				fprintf(stderr, "GELF Translation from file to memory representation failed: %s.\n", elf_errmsg(-1));
				ret = -1;
				goto err2;
			}

			char *provider = cdata + desc_offset + dst.d_size;
			name = provider + strlen(provider) + 1;
			
			if ((ret = convert_addr_to_offset(elf_handle, buf[0])) == -1) {
				fprintf(stderr, "Conversion from address to offset in binary failed. Address: %lu\n", buf[0]);
				ret = -1;
				goto err2;
			}
		}
	}

err2:
	elf_end(elf_handle);
err:
	return ret;
}


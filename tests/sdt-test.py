#! /usr/bin/python3

# Copyright (C) 2017 - Erica Bugden <erica.bugden@efficios.com>
#                      Francis Deslauriers <francis.deslauriers@efficios.com>
#
# This library is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; version 2.1 of the License.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301 USA

import sys
import subprocess
import os.path
import re
import binascii
from collections import namedtuple
from ctypes import *

class InvalidInputError(Exception):
    pass

class ElfReadError(Exception):
    pass

class ConversionError(Exception):
    pass

def convert_addr_to_offset(file_path, addr):
    '''
        Convert the virtual address in the binary to the offset of the
        corresponding instruction in the binary file.

        This function is necessary for directly comparing results with
        those returned by the library. The library returns an offset in
        the file because uprobe uses a file offset to determine the
        location to be instrumented.
    '''

    if addr == None:
        # TODO Check addr type (expecting an int)
        raise InvalidInputError('Invalid address.')

    # Use objdump (command line tool) to get .text ELF section header
    # info.
    objdump_params_text_section_hdr = ['objdump', '--headers',
                                       '--section=.text', file_path]
    process = subprocess.Popen(objdump_params_text_section_hdr,
                               stdout=subprocess.PIPE)
    out, err = process.communicate()
    text_section_hdr_info = out.decode('utf-8')

    if process.returncode != 0:
        raise ElfReadError('Invalid file path or no .text section in '
                           'binary.')

    # Find the line containing the address and offset of the section
    # in the file. objdump returns section header info on several
    # lines, but only one line contains the relevant information.
    text_section_info_found = 0
    text_section_info_regex = re.compile('^(.*?(\.text)[^$]*)$')
    for line in text_section_hdr_info.split('\n'):
        line_matched = text_section_info_regex.match(line)

        if line_matched:
            text_section_info_found = 1
            break;

    if not text_section_info_found:
        raise ElfReadError('.text section header information parse '
                           'error.')

    # Extract the address and the offset of the .text section.
    # This data is always at the same place in the relevant line.
    text_section_addr = int(line.split()[4], 16)
    text_section_offset = int(line.split()[5], 16)

    # Find offset of the address from the beginning of the .text
    # section.
    offset_in_text_section = addr - text_section_addr

    # TODO Check that calculated offset is smaller than .text section
    # size

    # Add offset in the section to the offset of the .text section
    # in the binary. The result is the offset in the binary file.
    return text_section_offset + offset_in_text_section

def get_sdt_note_section_hex_str(file_path, sdt_note_section):
    '''
        Converts the contents of the .note.stapsdt section to a single
        string of hex.
    '''

    # Use objdump (command line tool) to retrieve section header.
    objdump_params_note_section_hdr = ['objdump', '--headers',
                                       '--section=.note.stapsdt',
                                       file_path]
    process = subprocess.Popen(objdump_params_note_section_hdr,
                               stdout=subprocess.PIPE)
    out, err = process.communicate()
    sdt_note_section_hdr = out.decode('utf-8')

    if process.returncode != 0:
        raise ElfReadError('Invalid file path or .note.stapsdt section '
                           'does not exist in binary.')

    # Get section size to know how many bytes to read.
    # This information is always at the same place in the objdump
    # output.
    section_size_line = sdt_note_section_hdr.split('\n')[5]
    section_size = int(section_size_line.split()[2], 16)

    # Turn note section into single hex string.
    sdt_note_section_str = ''
    hex_start_idx = 4
    hex_end_idx = -1
    section_contents = sdt_note_section.split('\n')[hex_start_idx:hex_end_idx]
    for lines_read, line in enumerate(section_contents):
        line_sections = line.split()

        if lines_read == len(section_contents) - 1:
            # Last line of hex could be less than 16 bytes so it is
            # parsed differently.

            # Calculate number of bytes in section that have been read.
            # When there is enough data left, objdump always displays
            # 16 bytes of hex data per line.
            bytes_per_line = 16
            bytes_read = lines_read * bytes_per_line
            bytes_left_in_section = section_size - bytes_read

            # Read last bytes.
            # Skip first element in split because corresponds to that
            # line's address and not hex content.
            last_line = ''.join(line.split()[1:])
            bytes_per_char = 0.5
            note_section_end_idx = int(bytes_left_in_section / bytes_per_char)
            last_bytes = last_line[:note_section_end_idx]

            sdt_note_section_str = ''.join([sdt_note_section_str,
                                            last_bytes])
            break

        # According to objdump's output format, hex content will only
        # be in line elements 2 to 4.
        sdt_note_section_str += ''.join(line_sections[1:5])

    return sdt_note_section_str

def get_sdt_probe_offset(file_path, probe_provider, probe_name):
    '''
        Determines the offset in the binary file of the specified
        SystemTap SDT probe.
    '''

    # Use objdump (command line tool) to retrieve .note.stapsdt section.
    objdump_params_note_section_hex = ['objdump', '--full-contents',
                                       '--section=.note.stapsdt',
                                       file_path]
    process = subprocess.Popen(objdump_params_note_section_hex,
                               stdout=subprocess.PIPE)
    out, err = process.communicate()
    sdt_note_section = out.decode('utf-8')

    if process.returncode != 0:
        raise ElfReadError('Invalid file path or .note.stapsdt section '
                           'does not exist in binary.')

    try:
        sdt_note_section_str = get_sdt_note_section_hex_str(file_path,
                                                            sdt_note_section)
    except ElfReadError as e:
        print('ElfReadError: ' + str(e))
        raise ConversionError('Conversion of .note.stapsdt section to '
                              'string failed.')

    # Represent probe provider and name in the same way they are
    # represented in the note section hex so that it is possible
    # to search for it. The structure of a probe description in
    # the note section is defined in the systemtap header sdt.h.
    probe_provider += '\0'
    probe_name += '\0'
    probe_str = ''.join([probe_provider, probe_name])
    probe_byte_str = probe_str.encode('utf-8')
    probe_hex_str = binascii.hexlify(probe_byte_str)

    # Search for probe description in .note.stapsdt section.
    # This will determine position of the probe name in the hex string
    # representing the note section.
    probe_desc_idx = sdt_note_section_str.find(probe_hex_str.decode('utf-8'))
    if probe_desc_idx == -1:
        raise ElfReadError('Probe not found in binary.')

    # Determine the address of the probe.
    # The probe address is always found at the same place with
    # reference to the start of the probe provider (3 addresses
    # behind).
    #
    # Binary is assumed to be 64 bit since the tested API does
    # not currently support 32 bit.
    # TODO If tested API changed to support 32 bit architectures, the
    # following code will need to be changed to check the size of
    # addresses.
    bin_addr_size_bytes = 8
    bytes_per_char = 0.5
    n_bin_addr_behind = 3
    addr_start_idx = int(probe_desc_idx
                        - (n_bin_addr_behind*bin_addr_size_bytes
                        / bytes_per_char))
    addr_end_idx = int(probe_desc_idx
                    - ((n_bin_addr_behind - 1)*bin_addr_size_bytes
                    / bytes_per_char))
    addr = sdt_note_section_str[addr_start_idx:addr_end_idx]

    # Convert address to big endian.
    # TODO Conversion conditional on if ELF file is little-endian.
    addr_big_endian = ''
    addr_len_bytes = 8
    for i in range(addr_len_bytes):
        start_idx = i * 2
        end_idx = i*2 + 2
        addr_big_endian = ''.join([addr[start_idx: end_idx],
                                   addr_big_endian])

    try:
        probe_file_offset = convert_addr_to_offset(file_path,
                                                   int(addr_big_endian, 16))
    except InvalidInputError as e:
        print('InvalidInputError: ' + str(e))
        raise ConversionError('Conversion from address to offset failed.')
    except ElfReadError as e:
        print('ElfReadError: ' + str(e))
        raise ConversionError('Conversion from address to offset failed.')

    return probe_file_offset

def test_get_sdt_probe_offset(lib):
    '''
        Tests the function get_sdt_probe_offset.
    '''

    # Define test cases.
    TestCase = namedtuple(
                    'TestCase', 'test_num, test_name, file_path,'
                    'probe_provider, probe_name, expected_result')

    test1 = TestCase(test_num=1,
                     test_name='Invalid file descriptor',
                     file_path='sdt-probe',
                     probe_provider='hello_provider',
                     probe_name='tracepoint_nargs_2',
                     expected_result=-1)

    test2 = TestCase(test_num=2,
                     test_name='NULL SDT probe provider',
                     file_path='sdt-probe',
                     probe_provider=None,
                     probe_name='tracepoint_nargs_2',
                     expected_result=-1)

    test3 = TestCase(test_num=3,
                     test_name='NULL SDT probe name',
                     file_path='sdt-probe',
                     probe_provider='hello_provider',
                     probe_name=None,
                     expected_result=-1)

    test4 = TestCase(test_num=4,
                     test_name='File not an ELF file',
                     file_path='/etc/passwd',
                     probe_provider='hello_provider',
                     probe_name='tracepoint_nargs_2',
                     expected_result=-1)

    test5 = TestCase(test_num=5,
                     test_name='No SDT probes in binary',
                     file_path='sdt-no-probe',
                     probe_provider='hello_provider',
                     probe_name='tracepoint_nargs_2',
                     expected_result=-1)

    test6 = TestCase(test_num=6,
                     test_name='No matching SDT probe provider',
                     file_path='sdt-probe',
                     probe_provider='goodbye_provider',
                     probe_name='tracepoint_nargs_2',
                     expected_result=-1)

    test7 = TestCase(test_num=7,
                     test_name='No matching SDT probe in binary',
                     file_path='sdt-probe',
                     probe_provider='hello_provider',
                     probe_name='tracepoint_nargs_3',
                     expected_result=-1)

    try:
        test8_expected_result = get_sdt_probe_offset(
                                file_path='sdt-probe',
                                probe_provider='hello_provider',
                                probe_name='tracepoint_nargs_2')
    except ElfReadError as e:
        print('ElfReadError: ' + str(e))
        print('Calculation of expected result for get_std_probe_offset '
              'test 8 failed. Test 8 will not be performed.\n')
        test_cases = [test1, test2, test3, test4, test5, test6, test7]
    except ConversionError as e:
        print('ConversionError: ' + str(e))
        print('Calculation of expected result for get_std_probe_offset '
              'test 8 failed. Test 8 will not be performed.\n')
        test_cases = [test1, test2, test3, test4, test5, test6, test7]
    else:
        test8 = TestCase(test_num=8,
                         test_name='Matching SDT probe in binary',
                         file_path='sdt-probe',
                         probe_provider='hello_provider',
                         probe_name='tracepoint_nargs_2',
                         expected_result=test8_expected_result)

        test_cases = [test1, test2, test3, test4, test5, test6, test7,
                      test8]

    print('TESTING FUNCTION: get_sdt_probe_offset')

    # TEST 1 - Invalid file descriptor
    # First test done separately because file descriptor must be closed
    # before test end.
    f = open(test1.file_path)
    fd = f.fileno()
    f.close()

    probe_provider_byte_str = test1.probe_provider.encode('utf-8')
    probe_name_byte_str = test1.probe_name.encode('utf-8')
    offset = lib.get_sdt_probe_offset(fd,
                                      c_char_p(probe_provider_byte_str),
                                      c_char_p(probe_name_byte_str))

    if offset == test1.expected_result:
        print(str(test1.test_num) + ' - ' + test1.test_name + ': pass\n')
    else:
        print(str(test1.test_num) + ' - ' + test1.test_name + ': fail\n')

    # TEST 2 - TEST 8
    for test in test_cases[1:]:
        with open(test.file_path) as f:
            fd = f.fileno()

            if test.probe_provider != None:
                probe_provider_byte_str = test.probe_provider.encode('utf-8')
            else:
                probe_provider_byte_str = None

            if test.probe_name != None:
                probe_name_byte_str = test.probe_name.encode('utf8')
            else:
                probe_name_byte_str = None

            offset = lib.get_sdt_probe_offset(fd,
                                              c_char_p(probe_provider_byte_str),
                                              c_char_p(probe_name_byte_str))

            if offset == test.expected_result:
                print(str(test.test_num) + ' - ' + test.test_name + ': pass\n')
            else:
                print(str(test.test_num) + ' - ' + test.test_name + ': fail\n')

    return 0

def elf_get_function_offset(file_path, func_name):
    '''
        Determines the offset in the binary file of the specified
        function name.
    '''

    # Use objdump (command line tool) to retrieve symbol table.
    objdump_args_sym_table = ['objdump', '--syms', file_path]
    process = subprocess.Popen(objdump_args_sym_table,
                               stdout=subprocess.PIPE)
    out, err = process.communicate()
    sym_table = out.decode('utf-8')

    if process.returncode != 0:
        raise ElfReadError('Symbol table does not exist in binary.')

    # In the objdump output the symbol table starts after 4 lines.
    sym_table_start_idx = 4
    sym_found = 0
    for line in sym_table.split('\n')[sym_table_start_idx:]:
        if (line.find(func_name) == -1):
            continue

        sym_found = 1

        # Check if symbol refers to a function.
        sym_type_idx = 2
        sym_type = line.split()[sym_type_idx]
        if sym_type != 'F':
            raise ElfReadError('Requested symbol does not refer to a '
                               'function.')

        # Retrieve function symbol offset in the binary file.
        addr_idx = 0
        func_addr = int(line.split()[addr_idx], 16)
        try:
            func_offset = convert_addr_to_offset(file_path, func_addr)
        except InvalidInputError as e:
            print('InvalidInputError: ' + str(e))
            raise ConversionError('Conversion from address to offset '
                                  'failed.')
        except ElfReadError as e:
            print('ElfReadError: ' + str(e))
            raise ConversionError('Conversion from address to offset '
                                  'failed.')

    if not sym_found:
        raise ElfReadError('Symbol does not exist in symbol table.')

    return func_offset

def test_elf_get_function_offset(lib):
    '''
        Tests the function elf_get_function_offset.
    '''

    # Define test cases.
    TestCase = namedtuple(
                    'TestCase', 'test_num, test_name, file_path,'
                    'function_name, expected_result')

    test1 = TestCase(test_num=1,
                     test_name='Invalid file descriptor',
                     file_path='function-test',
                     function_name='test_function',
                     expected_result=-1)

    test2 = TestCase(test_num=2,
                     test_name='NULL function name',
                     file_path='function-test',
                     function_name=None,
                     expected_result=-1)

    test3 = TestCase(test_num=3,
                     test_name='File not an ELF file',
                     file_path='/etc/passwd',
                     function_name='test_function',
                     expected_result=-1)

    test4 = TestCase(test_num=4,
                     test_name='No matching symbol for requested function',
                     file_path='function-test',
                     function_name='wrong_function',
                     expected_result=-1)

    test5 = TestCase(test_num=5,
                     test_name='Requested symbol does not correspond to '
                        'function',
                     file_path='function-test',
                     function_name='return_val',
                     expected_result=-1)

    try:
        test6_expected_result = elf_get_function_offset('function-test',
                                                        'test_function')
    except ElfReadError as e:
        print('ElfReadError: ' + str(e))
        print('Calculation of expected result for elf_get_function_offset '
              'test 6 failed. Test 6 will not be performed.\n')
        test_cases = [test1, test2, test3, test4, test5]
    except ConversionError as e:
        print('ConversionError: ' + str(e))
        print('Calculation of expected result for elf_get_function_offset '
              'test 6 failed. Test 6 will not be performed.\n')
        test_cases = [test1, test2, test3, test4, test5]
    else:
        test6 = TestCase(test_num=6,
                         test_name='Function name match',
                         file_path='function-test',
                         function_name='test_function',
                         expected_result=test6_expected_result)

        test_cases = [test1, test2, test3, test4, test5, test6]

    print('TESTING FUNCTION: elf_get_function_offset')

    # TEST 1 - Invalid file descriptor
    # First test done separately because file descriptor must be closed
    # before test end.
    f = open(test1.file_path)
    fd = f.fileno()
    f.close()

    function_name_bytes = test1.function_name.encode('utf-8')
    offset = lib.elf_get_function_offset(fd, c_char_p(function_name_bytes))

    if offset == test1.expected_result:
        print(str(test1.test_num) + ' - ' + test1.test_name + ': pass\n')
    else:
        print(str(test1.test_num) + ' - ' + test1.test_name + ': fail\n')

    # TEST 2 - TEST 6
    for test in test_cases[1:]:
        with open(test.file_path) as f:
            fd = f.fileno()

            if test.function_name != None:
                function_name_bytes = test.function_name.encode('utf-8')
            else:
                function_name_bytes = None

            offset = lib.elf_get_function_offset(fd,
                                                 c_char_p(function_name_bytes))

            if offset == test.expected_result:
                print(str(test.test_num) + ' - ' + test.test_name + ': pass\n')
            else:
                print(str(test.test_num) + ' - ' + test.test_name + ': fail\n')

    return 0

def main():
    # Import libsdt-offset
    current_dir = os.getcwd()
    lib = cdll.LoadLibrary(os.path.join(current_dir, '..', 'libsdt-offset.so'))

    if test_get_sdt_probe_offset(lib) != 0:
        print('Error while testing get_sdt_probe_offset.')

    if test_elf_get_function_offset(lib) != 0:
        print('Error while testing elf_get_function_offset.')

if __name__ == '__main__':
    main()


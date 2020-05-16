#!/usr/bin/env python
import sys
sys.path.insert(1, './pyelftools')
import elftools.elf.elffile
import elftools.dwarf.descriptions

def load_dwarf(filename):
    with open(filename, 'rb') as f:
        elffile = elftools.elf.elffile.ELFFile(f)

        if not elffile.has_dwarf_info():
            print('file has no DWARF info')
            return
        return elffile.get_dwarf_info()

def location_to_abs_address(dwarf, filename, line):
    addresses = []
    for cu in dwarf.iter_CUs():
        lineprog = dwarf.line_program_for_CU(cu)
        prevstate = None
        for entry in lineprog.get_entries():
            if entry.state is None:
                continue
            f = lineprog['file_entry'][entry.state.file - 1].name
            if f != filename:
                prevstate = None
                continue
            if entry.state.end_sequence:
                prevstate = None
                continue
            if prevstate:
                if prevstate.line <= line < entry.state.line:
                    addresses.append(prevstate)
                if addresses and entry.state.line <= line:
                    for address in addresses:
                        if address.is_stmt:
                            return cu, address.address
                    return cu, addresses[0].address
            prevstate = entry.state
    print('error: not able to find location in binary file')
    exit(1)

def die_to_pubname(dwarf, die):
    pubnames = dwarf.get_pubnames()
    if not pubnames:
        print('error no pubnames in dwarf')
        exit(1)
    entries = [n for (n, entry) in pubnames.items() if entry.die_ofs == die.offset]
    if len(entries) > 1:
        print('error multiple DIEs have the same offset')
        sys.exit(1)
    return entries[0]

def cu_to_filename(cu):
    return cu.get_top_DIE().attributes['DW_AT_name'].value

def die_check_address(dwarf, die, address):
    if 'DW_AT_ranges' in die.attributes:
        range = die.attributes['DW_AT_ranges'].value
        ranges = dwarf.range_lists().get_range_list_at_offset(range)
        for r in ranges:
            if r.begin_offset <= address <= r.end_offset:
                return die, r.begin_offset
    elif 'DW_AT_low_pc' in die.attributes and 'DW_AT_high_pc' in die.attributes:
        low_pc = die.attributes['DW_AT_low_pc'].value
        high_pc_attr = die.attributes['DW_AT_high_pc']
        high_pc_attr_class = elftools.dwarf.descriptions.describe_form_class(high_pc_attr.form)
        if high_pc_attr_class == 'address':
            high_pc = high_pc_attr.value
        elif high_pc_attr_class == 'constant':
            high_pc = low_pc + high_pc_attr.value
        else:
            print('error: invalid DW_AT_high_pc class:', high_pc_attr_class)
        if low_pc <= address <= high_pc:
            return die, low_pc
            pass
    elif 'DW_AT_low_pc' in die.attributes:
        print('error subprogram with only DW_AT_low_pc is not handled yet')
        sys.exit(1)
    return None

def address_to_subprogram_die(dwarf, address, cu_suggest=None):
    cu = cu_suggest
    if cu is None:
        aranges = dwarf.get_aranges()
        cu_ofs = aranges.cu_offset_at_addr(address)
        cu = dwarf.get_CU_at(cu_ofs)
    if cu is None:
        print('not implemented yet')
        sys.exit(1)

    for die in cu.iter_DIEs():
        if die.tag == 'DW_TAG_subprogram':
            tmp = die_check_address(dwarf, die, address)
            if tmp is not None:
                return tmp
        elif die.tag == 'DW_TAG_lexical_block':
            tmp = die_check_address(dwarf, die, address)
            if tmp is not None:
                #TODO do something with program structure
                pass
    return None

def location_to_rel_address(dwarf, filename, line):
    cu, abs_address = location_to_abs_address(dwarf, filename, line)
    subprogram_die, subprogram_address = address_to_subprogram_die(dwarf, abs_address, cu)
    name = die_to_pubname(dwarf, subprogram_die)
    rel_address = abs_address - subprogram_address
    return name, rel_address, abs_address

def get_variable_location(dwarf, variable):
    for cu in dwarf.iter_CUs():
        for die in cu.iter_DIEs():
            if die.tag == 'DW_TAG_variable':
                if 'DW_AT_name' in die.attributes:
                    var = die.attributes['DW_AT_name'].value
                    if var == b'tick':
                        offset = die.attributes['DW_AT_location'].value
                        return offset

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("usage:", sys.argv[0], "binary filename line_number")
        sys.exit(1)
    binary = sys.argv[1]
    filename = sys.argv[2].encode()
    line = int(sys.argv[3])

    name, rel_address, abs_address = location_to_rel_address(load_dwarf(binary), filename, line)

    print('name', name)
    print('rel address', rel_address)
    print('abs address', hex(abs_address))

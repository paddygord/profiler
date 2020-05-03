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

def die_to_pubname(dwarf, die):
    pubnames = dwarf.get_pubnames()
    entries = [n for (n, entry) in pubnames.items() if entry.die_ofs == die.offset]
    if len(entries) > 1:
        print('error multiple DIEs have the same offset')
        sys.exit(1)
    return entries[0]

def cu_to_filename(cu):
    return cu.get_top_DIE().attributes['DW_AT_name'].value

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
            if 'DW_AT_ranges' in die.attributes:
                range = die.attributes['DW_AT_ranges'].value
                ranges = dwarf.debug_ranges_sec.index(range)
                print('error DW_AT_ranges is not handled yet')
                sys.exit(1)
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
                    continue
                if low_pc <= address <= high_pc:
                    return die, low_pc
            elif 'DW_AT_low_pc' in die.attributes:
                print('error subprogram with only DW_AT_low_pc is not handled yet')
                sys.exit(1)
            else:
                pass
    return None

def process_dwarf(dwarf, filename, line):
    cu, address = location_to_abs_address(dwarf, filename, line)
    subprogram_die, subprogram_address = address_to_subprogram_die(dwarf, address, cu)
    name = die_to_pubname(dwarf, subprogram_die)
    rel_address = address - subprogram_address
    return name, address, rel_address

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("error too few arguments")
        sys.exit(1)
    bin_filename = sys.argv[1]
    location = sys.argv[2]
    if ':' not in location:
        print("error location specifier must be 'file:line'")
        sys.exit(1)
    filename = location.split(':')[0].encode()
    line = int(location.split(':')[1])

    dwarf = load_dwarf(bin_filename)

    name, address, rel_address = process_dwarf(dwarf, filename, line)

    print('name', name)
    print('abs address', address)
    print('rel address', rel_address)

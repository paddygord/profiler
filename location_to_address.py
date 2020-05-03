#!/usr/bin/env python
import sys
import elftools.elf.elffile

def process_file(filename, location):
    with open(filename, 'rb') as f:
        elffile = elftools.elf.elffile.ELFFile(f)

        if not elffile.has_dwarf_info():
            print('file has no DWARF info')
            return

        if ':' not in location:
            return None
        filename = location.split(':')[0].encode()
        line = int(location.split(':')[1])
        address = location_to_address(elffile.get_dwarf_info(), filename, line)
        return address

def location_to_address(dwarfinfo, filename, line):
    addresses = []
    for CU in dwarfinfo.iter_CUs():
        lineprog = dwarfinfo.line_program_for_CU(CU)
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
                    addresses.append((prevstate.address, prevstate.is_stmt))
                if addresses and entry.state.line <= line:
                    for (address, stmt) in addresses:
                        if stmt:
                            return address
                    return addresses[0]
            prevstate = entry.state

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("error too few arguments")
        sys.exit(1)
    address = process_file(sys.argv[1], sys.argv[2])
    print('address', hex(address))

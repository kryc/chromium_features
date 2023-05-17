import argparse
import capstone
from capstone.x86 import *
import logging
import os
import re
import struct
import pefile

def find_features(dll: str) -> None:
    ''' Feature settings are stored as a structure of char*, bool*
    The address of the configuration directly follows this string '''
    pe_hndl = pefile.PE(dll, fast_load=True)

    # Find the rdata section
    for section in pe_hndl.sections:
        if section.Name.rstrip(b'\0') == b'.rdata':
            rdata_section = section
        if section.Name.rstrip(b'\0') == b'.data':
            data_section = section
        if section.Name.rstrip(b'\0') == b'.text':
            text_section = section

    with open(dll, 'rb') as file_hndl:
        file_hndl.seek(rdata_section.PointerToRawData, os.SEEK_SET)
        rdata_data = file_hndl.read(rdata_section.SizeOfRawData)
        file_hndl.seek(data_section.PointerToRawData, os.SEEK_SET)
        data_data = file_hndl.read(data_section.SizeOfRawData)
        
        # Find and ms[A-Z] match
        m = re.search(b'(ms[A-Z][a-zA-Z]+\0){2}', rdata_data)
        if m is None:
            logging.critical('Unable to find any msFlags')
            return None

        # Find where that string resides in the .rdata section
        string_sctn_offset = rdata_data.find(m.group(1))
        string_offset = rdata_section.PointerToRawData + string_sctn_offset
        string_rva = pe_hndl.get_rva_from_offset(string_offset)
        string_va = pe_hndl.OPTIONAL_HEADER.ImageBase + string_rva
        logging.info(f'VA of String:   {hex(string_va)}')
        raw_string_pointer = struct.pack('Q', string_va)

        # Find the FeatureList entry for that feature name
        string_pointer_sectn_offset = data_data.find(raw_string_pointer)
        string_pointer_offset = data_section.PointerToRawData + string_pointer_sectn_offset
        string_pointer_offset_rva = pe_hndl.get_rva_from_offset(string_pointer_offset)
        string_pointer_offset_va = string_pointer_offset_rva + pe_hndl.OPTIONAL_HEADER.ImageBase
        logging.info(f'Ptr to string:  {hex(string_pointer_offset_va)}')

        # Now for the REAL work. We need to go find a mov ecx, <offset>; call IsEnabled code block
        # First load the .text section (I hope you have enough RAM)
        logging.info('Finding reference to feature in code...')
        file_hndl.seek(text_section.PointerToRawData, os.SEEK_SET)
        text_data = file_hndl.read(text_section.SizeOfRawData)

        last_offset = 0
        lea_ins_addr = None
        call_ins_addr = None

        # Initialize the capstone disassembler
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True

        while last_offset != -1 and last_offset < len(text_data):
            base = text_section.VirtualAddress + pe_hndl.OPTIONAL_HEADER.ImageBase + last_offset
            remaining_text_data = text_data[last_offset:]

            for i in md.disasm(remaining_text_data, base):
                last_offset += i.size

                if lea_ins_addr is None:
                    if i.id != X86_INS_LEA:
                        continue
                    if i.operands[0].type != X86_OP_REG:
                        continue
                    if i.operands[0].reg != X86_REG_RCX:
                        continue
                    if i.operands[1].type != X86_OP_MEM:
                        continue
                    if i.operands[1].mem.base != X86_REG_RIP:
                        continue
                    if i.address + i.size + i.operands[1].mem.disp == string_pointer_offset_va:
                        lea_ins_addr = i.address
                        logging.info(f'Found lea instruction:  {hex(lea_ins_addr)} {i.mnemonic} {i.op_str}')
                else:
                    if i.id == X86_INS_CALL:
                        call_ins_addr = i.address
                        logging.info(f'Found call instruction: {hex(call_ins_addr)} {i.mnemonic} {i.op_str}')
                        is_enabled_addr = i.operands[0].imm
                        logging.info(f'Address of IsEnabled:   {hex(is_enabled_addr)}')
                        break
                
            if call_ins_addr is not None:
                break

            if last_offset < len(text_data):
                nops = text_data.find(b'\x90\x90\x90', last_offset)
                if nops != -1:
                    logging.debug('Encountered bad instruction. Recovering.')
                last_offset = nops
                
        # Now we scan the whole code segment again, looking for calls
        last_offset = 0
        last_lea_rcx = None
        found = []
        while last_offset != -1 and last_offset < len(text_data):
            base = text_section.VirtualAddress + pe_hndl.OPTIONAL_HEADER.ImageBase + last_offset
            remaining_text_data = text_data[last_offset:]
            for i in md.disasm(remaining_text_data, base):
                last_offset += i.size

                if i.id == X86_INS_LEA and i.operands[0].type == X86_OP_REG and i.operands[0].reg == X86_REG_RCX:
                    last_lea_rcx = i.address + i.size + i.operands[1].mem.disp
                elif i.id == X86_INS_CALL:
                    if i.operands[0].imm == is_enabled_addr and last_lea_rcx is not None:
                        feature_data_offset = last_lea_rcx - data_section.VirtualAddress - pe_hndl.OPTIONAL_HEADER.ImageBase
                        if feature_data_offset in found:
                            continue
                        found.append(feature_data_offset)
                        feature_string_ptr = data_data[feature_data_offset:feature_data_offset+8]
                        if len(feature_string_ptr) == 8:
                            feature_name_va = struct.unpack('Q', feature_string_ptr)[0]
                            feature_name_offset = feature_name_va - rdata_section.VirtualAddress - pe_hndl.OPTIONAL_HEADER.ImageBase
                            m = re.match(b'([\w\-_]+)\0', rdata_data[feature_name_offset:feature_name_offset+100])
                            if m is not None:
                                name = m.group(1).decode('utf8')
                                logging.info(f'{hex(last_lea_rcx)} {name}')
                            else:
                                logging.info(f'{hex(last_lea_rcx)} <UNKNOWN>')
                        else:
                            logging.info(f'{hex(last_lea_rcx)} <UNKNOWN OFFSET>')
                    else:
                        last_lea_rcx = None

            if last_offset < len(text_data):
                nops = text_data.find(b'\x90\x90\x90', last_offset)
                if nops != -1:
                    logging.debug('Encountered bad instruction. Recovering.')
                last_offset = nops

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Find all Chromium feature flags.')
    parser.add_argument('dll', help='chrome.dll (or equivalent) file to search')
    parser.add_argument('--loglevel', default='INFO', choices=('INFO', 'DEBUG',), help='Set output verbosity')
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.loglevel), format='%(message)s')

    find_features(args.dll)

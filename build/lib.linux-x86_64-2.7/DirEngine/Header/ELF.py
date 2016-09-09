# -*- coding: utf-8 -*-
try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.segments import InterpSegment, NoteSegment
    from elftools.elf.dynamic import DynamicSection, DynamicSegment
    from elftools.elf.descriptions import (
        describe_ei_class, describe_ei_data, describe_ei_version,
        describe_ei_osabi, describe_e_type, describe_e_machine,
        describe_e_version_numeric, describe_p_type, describe_p_flags,
        describe_sh_type, describe_sh_flags,
        describe_symbol_type, describe_symbol_bind, describe_symbol_visibility,
        describe_symbol_shndx, describe_reloc_type, describe_dyn_tag,
        describe_ver_flags, describe_note
        )    
    from elftools.elf.enums import ENUM_D_TAG
    from elftools.elf.relocation import RelocationSection
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.gnuversions import (
        GNUVerSymSection, GNUVerDefSection,
        GNUVerNeedSection,
        )

except ImportError:
    ELFFile = None
import hashlib

from ..error import Error
from ._header import _header
from .Archinfo.ArchSelector import ArchSelector

class ELF(_header):
    _backend = None
    _elf = None
    _versioninfo = None
    def __init__(self,path,filetype,stream=None,backend=None):
        if ELFFile is None:
            raise INSTALLerror("Install the ELFFile module to use the ELF backend!") 
        super(ELF, self).__init__(path,filetype)
        self._backend = backend
        if stream is None:
            f = open(path,'rb')
            self._elf = ELFFile(f)
        else:
            self._elf = ELFFile(stream)  
        
        bindata = self._elf.stream.read()
        self.fileMd5 = hashlib.md5(bindata).hexdigest()
        self.fileSha1 = hashlib.sha1(bindata).hexdigest()
        self.fileSha256 = hashlib.sha256(bindata).hexdigest()
        self.fileSha512 = hashlib.sha512(bindata).hexdigest()
        del bindata

        self._elf.stream.seek(0)
        self.bin_data = self._elf.stream.read()
        self._elf.stream.seek(0)
        self.arch_str = self._elf.header.e_machine
        self._entry = self._elf.header.e_entry
        if(self._elf.little_endian):
            self.endness = "Iend_LE"
        else:
            self.endness = "Iend_BE"
        self.set_arch(ArchSelector().search(self.arch_str,self.endness))


    def read_addr(self,addr):
        return addr


    def get_elf_header(self):
        result = {}
        header = self._elf.header
        if(hasattr(header,'e_ident')):          
            e_ident = header['e_ident']
            EI_MAG = ''
            for MAG in e_ident['EI_MAG']:
                EI_MAG += str(hex(MAG)).replace("0x",'')
            result['EI_MAG'] = EI_MAG
            result['EI_CLASS'] = describe_ei_class(e_ident['EI_CLASS'])
            result['EI_DATA'] = describe_ei_data(e_ident['EI_DATA'])
            result['EI_VERSION'] = describe_ei_version(e_ident['EI_VERSION'])
            result['EI_OSABI'] = describe_ei_osabi(e_ident['EI_OSABI'])
        if(hasattr(header,'e_type')):                            
            result['e_type'] = describe_e_type(header['e_type'])
        if(hasattr(header,'e_machine')):                            
            result['e_machine'] = describe_e_machine(header['e_machine'])
        if(hasattr(header,'e_version')):                            
            result['e_version'] = header['e_version']
        if(hasattr(header,'e_entry')):
            result['e_entry'] = header['e_entry']
        if(hasattr(header,'e_phoff')):
            result['e_phoff'] = header['e_phoff']
        if(hasattr(header,'e_shoff')):
            result['e_shoff'] = header['e_shoff']
        if(hasattr(header,'e_flags')):
            result['e_flags'] = header['e_flags']
        if(hasattr(header,'e_ehsize')):
            result['e_ehsize'] = header['e_ehsize']
        if(hasattr(header,'e_phentsize')):
            result['e_phentsize'] = header['e_phentsize']
        if(hasattr(header,'e_phnum')):
            result['e_phnum'] = header['e_phnum']
        if(hasattr(header,'e_shentsize')):
            result['e_shentsize'] = header['e_shentsize']
        if(hasattr(header,'e_shnum')):
            result['e_shnum'] = header['e_shnum']
        if(hasattr(header,'e_shstrndx')):
            result['e_shstrndx'] = header['e_shstrndx']
        return result


    def get_sections(self):
        sections = []
        for nsec, section in enumerate(self._elf.iter_sections()):
            result = {}
            result['nsec'] = nsec
            result['name'] = section.name
            result['sh_type'] = describe_sh_type(section['sh_type'])
            if self._elf.elfclass == 32:
                result['sh_addr'] = section['sh_addr']
                result['shoffset'] = section['sh_offset']
                result['sh_size'] = section['sh_size']
                result['sh_entsize'] = section['sh_entsize']
                result['sh_flags'] = describe_sh_flags(section['sh_flags'])
                result['sh_link'] = section['sh_link']
                result['sh_info'] = section['sh_info']
                result['sh_addralign'] = section['sh_addralign']
            else: # 64
                result['sh_addr'] = section['sh_addr']
                result['sh_offset'] = section['sh_offset']
                result['sh_size'] = section['sh_size']
                result['sh_entsize'] = section['sh_entsize']
                result['sh_flags'] = describe_sh_flags(section['sh_flags'])
                result['sh_link'] = section['sh_link'], section['sh_info']
                result['sh_addralign'] = section['sh_addralign']
            

            # Dynamic Section
            if isinstance(section, DynamicSection):
                result['special_type'] = 'dynamic'
                result['dynamic'] = []
                has_dynamic_sections = True
                for tag in section.iter_tags():
                    dynamic = {}
                    if tag.entry.d_tag == 'DT_NEEDED':
                        parsed = 'Shared library: [%s]' % tag.needed
                    elif tag.entry.d_tag == 'DT_RPATH':
                        parsed = 'Library rpath: [%s]' % tag.rpath
                    elif tag.entry.d_tag == 'DT_RUNPATH':
                        parsed = 'Library runpath: [%s]' % tag.runpath
                    elif tag.entry.d_tag == 'DT_SONAME':
                        parsed = 'Library soname: [%s]' % tag.soname
                    elif tag.entry.d_tag.endswith(('SZ', 'ENT')):
                        parsed = '%i (bytes)' % tag['d_val']
                    elif tag.entry.d_tag.endswith(('NUM', 'COUNT')):
                        parsed = '%i' % tag['d_val']
                    elif tag.entry.d_tag == 'DT_PLTREL':
                        s = describe_dyn_tag(tag.entry.d_val)
                        if s.startswith('DT_'):
                            s = s[3:]
                        parsed = '%s' % s
                    else:
                        parsed = '%#x' % tag['d_val']
                        dynamic['tag'] = ENUM_D_TAG.get(tag.entry.d_tag, tag.entry.d_tag)                    
                        dynamic['tag_type'] = tag.entry.d_tag[3:]
                        dynamic['tag_value'] = parsed
                    result['dynamic'].append(dynamic)

            #Relocation Section
            if isinstance(section, RelocationSection):
                result['special_type'] = 'relocation'
                result['relocation'] = []
                has_relocation_sections = True
                # The symbol table section pointed to in sh_link
                symtable = self._elf.get_section(section['sh_link'])

                for rel in section.iter_relocations():
                    relocation = {}
                    relocation['r_offset'] = rel['r_offset']
                    relocation['r_info'] = rel['r_info']
                    relocation['r_info_type'] = describe_reloc_type(rel['r_info_type'], self._elf)

                    if rel['r_info_sym'] == 0:
                        continue

                    symbol = symtable.get_symbol(rel['r_info_sym'])
                    # Some symbols have zero 'st_name', so instead what's used is
                    # the name of the section they point at
                    if symbol['st_name'] == 0:
                        symsec = self._elf.get_section(symbol['st_shndx'])
                        relocation['symbol_name'] = symbol_name = symsec.name
                    else:
                        symbol_name = symbol.name
                        relocation['st_value'] = symbol['st_value']
                        relocation['symbol_name'] = symbol_name
                    if section.is_RELA():
                        relocation['r_addend'] = rel['r_addend']
                    result['relocation'].append(relocation)



            #Symbol Section
            if isinstance(section, SymbolTableSection):
                self._init_versioninfo()

                if section['sh_entsize'] == 0:
                    continue
                result['special_type'] = 'symbol'
                result['symbol'] = []
                for nsym, symbol in enumerate(section.iter_symbols()):
                    sym_dic = {}
                    version_info = ''
                    # readelf doesn't display version info for Solaris versioning
                    if (section['sh_type'] == 'SHT_DYNSYM' and
                            self._versioninfo['type'] == 'GNU'):
                        version = self._symbol_version(nsym)
                        if (version['name'] != symbol.name and
                            version['index'] not in ('VER_NDX_LOCAL',
                                                     'VER_NDX_GLOBAL')):
                            if version['filename']:
                                # external symbol
                                version_info = '@%(name)s (%(index)i)' % version
                            else:
                                # internal symbol
                                if version['hidden']:
                                    version_info = '@%(name)s' % version
                                else:
                                    version_info = '@@%(name)s' % version

                        # symbol names are truncated to 25 chars, similarly to readelf
                        sym_dic['nsym'] = nsym
                        sym_dic['st_value'] = symbol['st_value']
                        sym_dic['st_size'] = symbol['st_size']
                        sym_dic['type'] = describe_symbol_type(symbol['st_info']['type'])
                        sym_dic['bind'] = describe_symbol_bind(symbol['st_info']['bind'])
                        sym_dic['vis'] = describe_symbol_visibility(symbol['st_other']['visibility'])
                        sym_dic['ndx'] = describe_symbol_shndx(symbol['st_shndx'])
                        sym_dic['name'] = symbol.name
                        sym_dic['version'] = version_info
                        result['symbol'].append(sym_dic)
            sections.append(result)
        return sections


    def get_program_header(self):
        header = []
        if self._elf.num_segments() == 0:
            return []

        for segment in self._elf.iter_segments():
            result = {}
            result['p_type'] = describe_p_type(segment['p_type'])

            if self._elf.elfclass == 32:
                result['p_offset'] = segment['p_offset']
                result['p_vaddr'] = segment['p_vaddr']
                result['p_paddr'] = segment['p_paddr']
                result['p_filesz'] = segment['p_filesz']
                result['p_memsz'] = segment['p_memsz']
                result['p_flags'] = describe_p_flags(segment['p_flags'])
                result['p_align'] = segment['p_align']
            else: # 64
                result['p_offset'] = segment['p_offset']
                result['p_vaddr'] = segment['p_vaddr']
                result['p_paddr'] = segment['p_paddr']
                result['p_filesz'] = segment['p_filesz']
                result['p_memsz'] = segment['p_memsz']
                result['p_flags'] = describe_p_flags(segment['p_flags'])
                result['p_align'] = segment['p_align']
            if isinstance(segment, InterpSegment):
                result['interp_name'] = segment.get_interp_name()
            result['include_section'] = []
            for section in self._elf.iter_sections():
                if (    not section.is_null() and
                        segment.section_in_segment(section)):
                    result['include_section'].append(section.name)
            
            #NoteSegment
            if isinstance(segment, NoteSegment):
                result['special_type'] = 'note'
                result['note'] = []
                for note in segment.iter_notes():
                    note_dic = {}
                    note_dic['n_offset'] = note['n_offset']
                    note_dic['n_size'] = note['n_size']
                    note_dic['n_name'] = note['n_name']
                    note_dic['n_descsz'] = note['n_descsz']
                    note_dic['note'] = describe_note(note)
                    result['note'].append(note_dic)

            header.append(result)

        return header




    def _init_versioninfo(self):
        """ Search and initialize informations about version related sections
            and the kind of versioning used (GNU or Solaris).
        """
        if self._versioninfo is not None:
            return

        self._versioninfo = {'versym': None, 'verdef': None,
                             'verneed': None, 'type': None}

        for section in self._elf.iter_sections():
            if isinstance(section, GNUVerSymSection):
                self._versioninfo['versym'] = section
            elif isinstance(section, GNUVerDefSection):
                self._versioninfo['verdef'] = section
            elif isinstance(section, GNUVerNeedSection):
                self._versioninfo['verneed'] = section
            elif isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    if tag['d_tag'] == 'DT_VERSYM':
                        self._versioninfo['type'] = 'GNU'
                        break

        if not self._versioninfo['type'] and (
                self._versioninfo['verneed'] or self._versioninfo['verdef']):
            self._versioninfo['type'] = 'Solaris'


    def _symbol_version(self, nsym):
        """ Return a dict containing information on the
                   or None if no version information is available
        """
        self._init_versioninfo()

        symbol_version = dict.fromkeys(('index', 'name', 'filename', 'hidden'))

        if (not self._versioninfo['versym'] or
                nsym >= self._versioninfo['versym'].num_symbols()):
            return None

        symbol = self._versioninfo['versym'].get_symbol(nsym)
        index = symbol.entry['ndx']
        if not index in ('VER_NDX_LOCAL', 'VER_NDX_GLOBAL'):
            index = int(index)

            if self._versioninfo['type'] == 'GNU':
                # In GNU versioning mode, the highest bit is used to
                # store wether the symbol is hidden or not
                if index & 0x8000:
                    index &= ~0x8000
                    symbol_version['hidden'] = True

            if (self._versioninfo['verdef'] and
                    index <= self._versioninfo['verdef'].num_versions()):
                _, verdaux_iter = \
                        self._versioninfo['verdef'].get_version(index)
                symbol_version['name'] = next(verdaux_iter).name
            else:
                verneed, vernaux = \
                        self._versioninfo['verneed'].get_version(index)
                symbol_version['name'] = vernaux.name
                symbol_version['filename'] = verneed.name

        symbol_version['index'] = index
        return symbol_version








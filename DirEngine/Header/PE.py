# -*- coding: utf-8 -*-
try:
    import pefile
except ImportError:
    pefile = None
import hashlib

from ..error import Error
from ._header import _header
from .Archinfo.ArchSelector import ArchSelector

ASLR = 0x40


def none(string):
    if string == None:
        string = 0
    return string

class PE(_header):
    _backend = None
    _pe = None
    _iat = {}
    iat_symbols = {}
    def __init__(self,path,filetype,stream=None,backend=None):
        self._iat = {}
        self.iat_symbols = {}
        if pefile is None:
            raise CLEError("Install the pefile module to use the PE backend!")      
        super(PE, self).__init__(path,filetype)
        self._backend = backend
        if stream is None:
            f = open(path,'rb')
            self.bin_data = f.read()
            f.close()
            self._pe = pefile.PE(path)
        else:
            stream.seek(0)
            self.bin_data = stream.read()
            stream.seek(0)
            self._pe = pefile.PE(data=stream.read())
        
        stream.seek(0)
        self.fileMd5 = hashlib.md5(self.bin_data).hexdigest()
        self.fileSha1 = hashlib.sha1(self.bin_data).hexdigest()
        self.fileSha256 = hashlib.sha256(self.bin_data).hexdigest()
        self.fileSha512 = hashlib.sha512(self.bin_data).hexdigest()

        self.arch_str = pefile.MACHINE_TYPE[self._pe.FILE_HEADER.Machine]
        self.base_addr = self._pe.OPTIONAL_HEADER.ImageBase
        self._entry = self._pe.OPTIONAL_HEADER.AddressOfEntryPoint

        self.set_arch(ArchSelector().search(self.arch_str))

        if (self._pe.OPTIONAL_HEADER.DllCharacteristics | ASLR) == self._pe.OPTIONAL_HEADER.DllCharacteristics:
            self.set_aslr(True)
        else:
            self.set_aslr(False)

        for i in self._pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            if(i.name == "IMAGE_DIRECTORY_ENTRY_IAT"): 
                self._iat = i.__field_offsets__

        self.iat_symbols = self.get_symbols()

    def get_symbols(self):
        result = {}
        IMPORT = self._pe.DIRECTORY_ENTRY_IMPORT
        for imports in IMPORT:
            for imp in imports.imports:
                result[str(imp.address)] = imp.name
        return result


    def read_rva_to_addr(self,rva):
        for section in self._pe.sections:
            if section.contains_rva(rva-self.base_addr): 
                return ((rva-self.base_addr) - section.VirtualAddress + section.PointerToRawData)


    def read_addr(self,addr):
        for section in self._pe.sections:
            if section.contains_rva(addr): 
                return (addr - section.VirtualAddress + section.PointerToRawData)


    def is_section(self,addr):
        for section in self._pe.sections:
            if section.contains_rva(addr-self.base_addr):
                return section

    def is_iat(self,addr):
        if self._iat != {}:
            return False
        if (int(self.base_addr) + int(self._iat['VirtualAddress']) + int(self._iat['Size'])) <= int(addr):
            if (int(self.base_addr) + int(self._iat['VirtualAddress']) + int(self._iat['Size'])) >= int(addr):
                return True
        return False

    def iat_symbol(self,addr):
        if not self.is_iat(addr):
            return False
        if str(addr) in iat_symbols.keys():
            return iat_symbols[str(addr)]
        return False



    def get_dos_header(self):
        result = {}
        DOS = self._pe.DOS_HEADER
        if(hasattr(DOS,'e_magic')):             
            result['signature'] = DOS.e_magic
        if(hasattr(DOS,'e_lfanew')):                            
            result['nt_offset'] = DOS.e_lfanew
        return result

    def get_pe_sections(self):
        result = []
        for section in self._pe.sections:
            r = {}
            if(hasattr(section,'Name')):        
                r['name'] = section.Name.replace('\x00','')
            if(hasattr(section,'Misc_VirtualSize')):        
                r['virtualsize'] = (none(section.Misc_VirtualSize))
            if(hasattr(section,'VirtualAddress')):      
                r['virtualaddress'] = (none(section.VirtualAddress))
            if(hasattr(section,'PointerToRawData')):        
                r['pointer_raw_data'] = (none(section.PointerToRawData))
            if(hasattr(section,'SizeOfRawData')):                       
                r['size_raw_data'] = (none(section.SizeOfRawData))
            if(hasattr(section,'Characteristics')):                     
                r['character'] = (none(section.Characteristics))
            r['sha512'] = (none(section.get_hash_sha512()))
            r['sha256'] = (none(section.get_hash_sha256()))
            r['sha1'] = (none(section.get_hash_sha1()))
            r['md5'] = (none(section.get_hash_md5()))
            r['entropy'] = section.get_entropy()
            result.append(r)
        return result

    def get_nt_file_header(self):
        result = {}
        FILE = self._pe.FILE_HEADER
        if(hasattr(FILE,'Machine')):        
            result['machine'] = (none(FILE.Machine))
        if(hasattr(FILE,'NumberOfSections')):       
            result['num_sections'] = (none(FILE.NumberOfSections))
        if(hasattr(FILE,'TimeDateStamp')):                  
            result['timedate'] = (none(FILE.TimeDateStamp))
        if(hasattr(FILE,'Characteristics')):                    
            result['character'] = (none(FILE.Characteristics))
        return result
    def get_nt_optional_header(self):
        result = {}
        OPTIONAL = self._pe.OPTIONAL_HEADER
        if(hasattr(OPTIONAL,'Magic')):
            result['magic'] = (none(OPTIONAL.Magic))
        if(hasattr(OPTIONAL,'MajorLinkerVersion') and hasattr(OPTIONAL,'MinorLinkerVersion')):
            result['linkerversion'] = str((none(OPTIONAL.MajorLinkerVersion))) + str((none(OPTIONAL.MinorLinkerVersion)))
        if(hasattr(OPTIONAL,'SizeOfCode')):
            result['size_code'] = (none(OPTIONAL.SizeOfCode))
        if(hasattr(OPTIONAL,'SizeOfInitializedData')):
            result['size_init_data'] = (none(OPTIONAL.SizeOfInitializedData))
        if(hasattr(OPTIONAL,'SizeOfUninitializedData')):
            result['size_uninit_data'] = (none(OPTIONAL.SizeOfUninitializedData))
        if(hasattr(OPTIONAL,'AddressOfEntryPoint')):
            result['entry_point'] = (none(OPTIONAL.AddressOfEntryPoint))
        if(hasattr(OPTIONAL,'BaseOfCode')):
            result['base_code'] = (none(OPTIONAL.BaseOfCode))
        if(hasattr(OPTIONAL,'BaseOfData')):
            result['base_data'] = (none(OPTIONAL.BaseOfData))
        if(hasattr(OPTIONAL,'ImageBase')):
            result['imagebase'] = (none(OPTIONAL.ImageBase))
        if(hasattr(OPTIONAL,'SectionAlignment')):
            result['section_alignment'] = (none(OPTIONAL.SectionAlignment))
        if(hasattr(OPTIONAL,'FileAlignment')):
            result['file_alignment'] = (none(OPTIONAL.FileAlignment))
        if(hasattr(OPTIONAL,'SizeOfImage')):
            result['size_image'] = (none(OPTIONAL.SizeOfImage))
        if(hasattr(OPTIONAL,'SizeOfHeaders')):
            result['size_headers'] = (none(OPTIONAL.SizeOfHeaders))
        if(hasattr(OPTIONAL,'CheckSum')):
            result['checksum'] = (none(OPTIONAL.CheckSum))
        if(hasattr(OPTIONAL,'Subsystem')):
            result['subsystem'] = (none(OPTIONAL.Subsystem))
        if(hasattr(OPTIONAL,'DllCharacteristics')):     
            result['dll_character'] = (none(OPTIONAL.DllCharacteristics))
        if(hasattr(OPTIONAL,'MajorOperatingSystemVersion')):        
            result['majorversion'] = (none(OPTIONAL.MajorOperatingSystemVersion))
        if(hasattr(OPTIONAL,'MinorOperatingSystemVersion')):        
            result['minorversion']= (none(OPTIONAL.MinorOperatingSystemVersion))
        if(hasattr(OPTIONAL,'SizeOfStackReserve')):             
            result['size_stack_reserve'] = (none(OPTIONAL.SizeOfStackReserve))
        if(hasattr(OPTIONAL,'SizeOfStackCommit')):              
            result['size_stack_commit'] = (none(OPTIONAL.SizeOfStackCommit))
        if(hasattr(OPTIONAL,'SizeOfHeapReserve')):              
            result['size_heap_reserve'] = (none(OPTIONAL.SizeOfHeapReserve))
        if(hasattr(OPTIONAL,'SizeOfHeapCommit')):               
            result['size_heap_commit'] = (none(OPTIONAL.SizeOfHeapCommit))
        if(hasattr(OPTIONAL,'NumberOfRvaAndSizes')):                
            result['num_data_direct'] = (none(OPTIONAL.NumberOfRvaAndSizes))

        for i in OPTIONAL.DATA_DIRECTORY:
            result[i.name] = i.__field_offsets__


        return result

    def get_data_directory_table(self):
        result = []
        data_directory = self._pe.OPTIONAL_HEADER.DATA_DIRECTORY
        for data in data_directory:
            r = {}
            r['structure'] = data.name
            r['virtualaddress'] = data.VirtualAddress
            r['size'] = data.Size
            result.append(r)
        return result

    def get_iat_header(self):
        result = []
        IMPORT = self._pe.DIRECTORY_ENTRY_IMPORT
        for imports in IMPORT:
            dll = {}
            dll['dll'] = imports.dll
            dll['iat_rva'] = (none(imports.struct.FirstThunk))
            dll['import'] = []
            for imp in imports.imports:
                iat = {}
                iat['name'] = imp.name
                iat['ordinal'] = (none(imp.ordinal))
                iat['ordinal_bit'] = imp.import_by_ordinal
                dll['import'].append(iat)
            result.append(dll)
        return result

    def get_meta_data(self):
        result = {}
        if not hasattr(self._pe,'FileInfo'):
            return result
            
        for fileinfo in self._pe.FileInfo:
            if fileinfo.Key == 'StringFileInfo':
                for st in fileinfo.StringTable:
                    for entry in st.entries.items():
                            result.update({entry[0] : entry[1]})

            if fileinfo.Key == 'VarFileInfo':
                for var in fileinfo.Var:
                    result.update({var.entry.items()[0][0] : var.entry.items()[0][1]})

        return result


    def Header(self):
        header = {}

        header['dos'] = self.get_dos_header()
        header['sections'] = self.get_pe_sections()
        header['nt_file'] = self.get_nt_file_header()
        header['nt_optional'] = self.get_nt_optional_header()
        header['data_directory'] = self.get_data_directory_table()
        header['iat'] = self.get_iat_header()
        header['meta'] = self.get_meta_data()
        return header
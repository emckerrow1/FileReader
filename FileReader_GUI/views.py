from django.shortcuts import render

from forms import UploadFileForm

import pefile
import os
import hashlib

# Create your views here.
def home(request):
    if request.method == "POST":
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            file_information = handle_uploaded_file(request.FILES['file_upload'])
            return render(request, 'home.html', {'form':form, 'file_information':file_information})
    else:
        form = UploadFileForm()

    return render(request, 'home.html', {'form':form})

def handle_uploaded_file(f):
    if f.readline()[:2] == 'MZ':
    	file_information = {
                'file_type':'PE',
                'file_name':f.name
        }
        if not os.path.exists('uploads/'+f.name):
            with open('uploads/'+f.name, 'wb+') as dest:
                for chunk in f.chunks():
                    dest.write(chunk)
                file_information['sha256'] = hashlib.sha256('uploads/'+f.name).hexdigest()
        pe = pefile.PE('uploads/'+f.name)
        if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE:   file_information['pe_type'] = '32-bit'
        else:   file_information['pe_type'] = '32-bit'
        file_information['e_magic'] = hex(pe.DOS_HEADER.e_magic)
        file_information['signature'] = hex(pe.NT_HEADERS.Signature)
        file_information['entry_point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        imports = [x for x in pe.DIRECTORY_ENTRY_IMPORT]
        for import_ in imports:
            file_information['imports_'+repr(import_.dll)] = [x.name for x in import_.imports]
        
        file_information['all_info'] = pe.dump_info()
        file_information['pe_dir'] = dir(pe)
        return file_information
from django.shortcuts import render

from forms import UploadFileForm

import pefile
import os

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
    	file_information = {'file_type':'PE'}
        if not os.path.exists('uploads/'+f.name):
            with open('uploads/'+f.name, 'wb+') as dest:
                for chunk in f.chunks():
                    dest.write(chunk)
        pe = pefile.PE('uploads/'+f.name)
        file_information['e_magic'] = hex(pe.DOS_HEADER.e_magic)
        file_information['signature'] = hex(pe.NT_HEADERS.Signature)
        return file_information
from django import forms

class UploadFileForm(forms.Form):
    file_upload = forms.FileField()
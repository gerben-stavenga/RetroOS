"""Link the Wine probes without a C runtime; it exercises Wine APIs directly."""
from pathlib import Path
import subprocess
import sys
import tempfile
source,header,output=map(lambda p:Path(p).resolve(),sys.argv[1:])
imports={
 'USER32':{'RegisterClassA':4,'CreateWindowExA':48,'DefWindowProcA':16,'SetForegroundWindow':4,'SetActiveWindow':4,'SetFocus':4,'PeekMessageA':20,'GetMessageA':16,'GetKeyState':4,'GetAsyncKeyState':4,'TranslateMessage':4,'PostQuitMessage':4,'GetClassLongA':8,'GetDC':4,'ReleaseDC':8,'DestroyWindow':4,'SetCapture':4,'ReleaseCapture':0,'GetCursorPos':4,'DispatchMessageA':4,'ShowWindow':8,'BeginPaint':8,'EndPaint':8,'GetWindow':8,'GetParent':4},
 'GDI32':{'SetPixel':16,'GetPixel':12,'GetClipBox':8},
 'KERNEL32':{'GetModuleHandleA':4,'GetLastError':0,'lstrlenA':4,'ExitProcess':4,'GetWindowsDirectoryA':8,'GetSystemDirectoryA':8,'lstrcmpiA':8,'LoadLibraryA':4,'FreeLibrary':4},
 'RETROOS':{'RetroWriteFile':20},
}
imports['KERNEL32'].update({'GlobalMemoryStatusEx':4,'GlobalMemoryStatus':4})
with tempfile.TemporaryDirectory() as d:
 w=Path(d);obj=w/'test.o';libs=[]
 subprocess.run(['clang-19','-target','i686-windows','-O2','-ffreestanding','-fno-stack-protector','-D__WINE_PE_BUILD','-D_UCRT','-I'+str(header.parent),'-I'+str(header.parent/'msvcrt'),'-c',str(source),'-o',str(obj)],check=True)
 for dll,functions in imports.items():
  definition=w/(dll+'.def');lib=w/(dll+'.lib');libs.append(str(lib))
  definition.write_text('LIBRARY '+dll+'.DLL\nEXPORTS\n'+''.join(f'{name}@{size}\n' for name,size in functions.items()))
  subprocess.run(['llvm-dlltool','-m','i386','-k','-d',str(definition),'-l',str(lib)],check=True)
 subprocess.run(['ld.lld','-m','i386pe','--entry','_start','--subsystem','console','--image-base','0x400000','--stack','262144',str(obj),*libs,'-o',str(output)],check=True)

"""Build FreeType as PE code and adapt Wine's font file I/O to NT mappings."""
from pathlib import Path
import tarfile


def replace_body(text, signature, body):
    start = text.index('{', text.index(signature))
    depth, end = 1, start + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[:start] + '{\n' + body + '\n}' + text[end:]


def prepare_fonts(source, archive, work):
    with tarfile.open(archive) as tar:
        tar.extractall(work, filter='data')
    ft = work / 'freetype-2.13.3'
    path = source / 'dlls/win32u/freetype.c'
    text = path.read_text()
    text = '#define HAVE_FT2BUILD_H 1\n#define SONAME_LIBFREETYPE "static"\n' + text
    text = text.replace('static void *ft_handle = NULL;', '')
    start = text.index('    ft_handle = dlopen(')
    end = text.index('    LOAD_FUNCPTR(FT_Done_Face)', start)
    text = text[:start] + '#define LOAD_FUNCPTR(f) p##f = f;\n\n' + text[end:]
    text = text.replace('dlclose(ft_handle);', '').replace('ft_handle = NULL;', '')
    start = text.index('\nsym_not_found:')
    end = text.index('\n}', start)
    text = text[:start] + text[end:]
    text = text.replace('    dev_t       dev;\n    ino_t       ino;', '    WCHAR      *name;')
    # No host paths: mappings are identified by their NT path and owned until
    # the last live font releases them. FreeType only sees memory faces.
    map_start = text.index('static struct font_mapping *map_font_file(')
    map_end = text.index('\nstatic int load_VDMX', map_start)
    mapping = (Path(__file__).with_name('font_mapping.c')).read_text()
    text = text[:map_start] + mapping + '\n' + text[map_end:]
    pos = text.index('static struct list mappings_list')
    text = text[:pos] + 'static struct font_mapping *map_font_file(const WCHAR *name);\nstatic void unmap_font_file(struct font_mapping *mapping);\n' + text[pos:]
    text = text.replace('    struct stat st;\n', '').replace('    int fd, length;', '    int length;')
    start = text.index('    if (unix_name)\n    {', text.index('static struct unix_face *unix_face_create'))
    end = text.index('\n    if (!(This = calloc', start)
    text = text[:start] + '    assert(!unix_name);\n' + text[end:]
    text = text.replace('    if (unix_name) munmap( data_ptr, data_size );', '')
    text = text.replace('file, data_ptr, data_size, face_index, unix_face->fs,', 'file, file ? NULL : data_ptr, file ? 0 : data_size, face_index, unix_face->fs,')
    text = text.replace('assert(unix_name || !(flags & ADDFONT_EXTERNAL_FONT));','assert(dos_name || !(flags & ADDFONT_EXTERNAL_FONT));')
    start = text.index('    if (!dos_name && unix_name && !ntdll_get_dos_file_name')
    end = text.index('\n    do', start)
    text = text[:start] + '    assert(!unix_name);\n' + text[end:]
    text = replace_body(text, 'static INT freetype_add_font(', '''    struct font_mapping *mapping = map_font_file(file);
    int ret;
    if (!mapping) return 0;
    ret = AddFontToList(file, NULL, mapping->data, mapping->size, flags);
    unmap_font_file(mapping);
    return ret;''')
    start = text.index('        char *filename;', text.index('static BOOL freetype_load_font'))
    end = text.index('        if (!data->mapping)', start)
    text = text[:start] + '        data->mapping = map_font_file(font->file);\n' + text[end:]
    # unix_face_create already has mapped bytes, so never invoke CRT file I/O.
    start = text.index('    if (file)\n', text.index('static FT_Face new_ft_face'))
    end = text.index('\n    if (err != 0)', start)
    text = text[:start] + '    err = pFT_New_Memory_Face(library, font_data_ptr, font_data_size, face_index, &ft_face);\n' + text[end:]
    path.write_text(text)
    return ft


def build_fonts(ft, source, build, work, env, log, run):
    modules = ['autofit', 'bdf', 'cff', 'cid/type1cid', 'pcf', 'pfr', 'psaux',
               'pshinter', 'psnames', 'raster', 'sdf', 'sfnt', 'smooth', 'svg',
               'truetype', 'type1', 'type42', 'winfonts/winfnt',
               'gzip/ftgzip', 'bzip2/ftbzip2', 'lzw/ftlzw']
    bases = ['ftbase', 'ftinit', 'ftsystem', 'ftdebug', 'ftbbox', 'ftbitmap',
             'ftglyph', 'ftmm', 'ftfstype', 'ftlcdfil', 'ftstroke', 'fttype1',
             'ftwinfnt', 'ftgasp', 'ftotval', 'ftgxval', 'ftpatent', 'ftpfr', 'ftsynth']
    sources = [ft / 'src' / (m + '.c' if '/' in m else m + '/' + m + '.c') for m in modules]
    sources += [ft / 'src/base' / (m + '.c') for m in bases]
    objects = []
    for i, src in enumerate(sources):
        obj = work / f'ft-{i}.o'
        run(['clang-19', '-target', 'i686-windows', '-O2', '-c', '-D_UCRT',
             '-D__WINE_PE_BUILD', '-DFT2_BUILD_LIBRARY',
             '-I' + str(ft / 'include'), '-I' + str(source / 'include/msvcrt'),
             '-I' + str(source / 'include'), '-I' + str(build / 'include'),
             str(src), '-o', str(obj)], build, env, log)
        objects.append(str(obj))
    library = work / 'freetype.lib'
    run(['llvm-ar', 'rcs', str(library), *objects], build, env, log)
    return library

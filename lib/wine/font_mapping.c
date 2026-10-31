/* NT file mappings for Wine's userspace FreeType backend. */
static struct font_mapping *map_font_file(const WCHAR *name)
{
    struct font_mapping *mapping;
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK io;
    FILE_STANDARD_INFORMATION info;
    HANDLE file, section;
    SIZE_T size = 0;
    void *data = NULL;
    NTSTATUS status;

    LIST_FOR_EACH_ENTRY(mapping, &mappings_list, struct font_mapping, entry)
        if (!wcsicmp(mapping->name, name))
        {
            mapping->refcount++;
            return mapping;
        }
    RtlInitUnicodeString(&path, name);
    InitializeObjectAttributes(&attr, &path, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (NtOpenFile(&file, GENERIC_READ | SYNCHRONIZE, &attr, &io,
                   FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT)) return NULL;
    status = NtQueryInformationFile(file, &io, &info, sizeof(info), FileStandardInformation);
    if (!status && (!info.EndOfFile.QuadPart || info.EndOfFile.QuadPart > 0xffffffff))
        status = STATUS_INVALID_PARAMETER;
    if (!status) status = NtCreateSection(&section, SECTION_MAP_READ, NULL, NULL,
                                          PAGE_READONLY, SEC_COMMIT, file);
    NtClose(file);
    if (status) return NULL;
    status = NtMapViewOfSection(section, GetCurrentProcess(), &data, 0, 0, NULL,
                                &size, ViewShare, 0, PAGE_READONLY);
    NtClose(section);
    if (status) return NULL;
    mapping = calloc(1, sizeof(*mapping));
    if (mapping) mapping->name = wcsdup(name);
    if (!mapping || !mapping->name)
    {
        free(mapping);
        NtUnmapViewOfSection(GetCurrentProcess(), data);
        return NULL;
    }
    mapping->data = data;
    mapping->size = info.EndOfFile.QuadPart;
    mapping->refcount = 1;
    list_add_tail(&mappings_list, &mapping->entry);
    return mapping;
}

static void unmap_font_file(struct font_mapping *mapping)
{
    if (!--mapping->refcount)
    {
        list_remove(&mapping->entry);
        NtUnmapViewOfSection(GetCurrentProcess(), mapping->data);
        free(mapping->name);
        free(mapping);
    }
}

#define _GNU_SOURCE

#include <assert.h>
#include <clang-c/CXDiagnostic.h>
#include <clang-c/CXFile.h>
#include <clang-c/CXSourceLocation.h>
#include <clang-c/CXString.h>
#include <clang-c/Index.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "str_list.h"
#include "util.h"

typedef struct {
    CXCursor* cursors;
    size_t len;
    size_t capacity;
} CursorVec;

static void cursor_vec_free(CursorVec* vec) {
    assert(vec);

    if (vec->cursors) {
        free(vec->cursors);
        vec->cursors = NULL;
        vec->capacity = 0;
        vec->len = 0;
    }
}

static void cursor_vec_push(CursorVec* vec, CXCursor cursor) {
    assert(vec);

    if (!vec->cursors) {
        const size_t default_capacity = 4;
        vec->cursors = malloc(default_capacity * sizeof(CXCursor));
        if (!vec->cursors) {
            perror_exit("cursor vec malloc");
        }
        vec->capacity = default_capacity;
        vec->len = 0;
    }

    if (vec->len == vec->capacity) {
        vec->capacity *= 2;
        CXCursor* tmp = realloc(vec->cursors, vec->capacity * sizeof(CXCursor));
        if (!tmp) {
            perror_exit("cursor vec realloc");
        }

        vec->cursors = tmp;
    }

    vec->cursors[vec->len++] = cursor;
}

typedef struct {
    const char* path;
    CursorVec fns;
} FnCollector;

static enum CXChildVisitResult
fn_collect_visitor(CXCursor cursor, CXCursor parent, CXClientData data) {
    assert(data);
    (void)parent;

    FnCollector* collector = data;
    assert(collector && collector->path);

    if (clang_getCursorKind(cursor) != CXCursor_FunctionDecl ||
        clang_Cursor_getStorageClass(cursor) == CX_SC_Static ||
        !clang_Cursor_isNull(clang_getCursorDefinition(cursor)) ||
        !clang_equalCursors(cursor, clang_getCanonicalCursor(cursor))) {
        return CXChildVisit_Continue;
    }

    CXFile file;
    clang_getExpansionLocation(clang_getCursorLocation(cursor), &file, NULL, NULL, NULL);
    if (!file) {
        return CXChildVisit_Continue;
    }

    CXString cx_file_name = clang_getFileName(file);
    const char* file_name = clang_getCString(cx_file_name);
    if (strcmp(file_name, collector->path) == 0) {
        cursor_vec_push(&collector->fns, cursor);
    }

    clang_disposeString(cx_file_name);
    return CXChildVisit_Continue;
}

static CXTranslationUnit parse_translation_unit(
    CXIndex index, const char* header_path, const char* target, CursorVec* fns_out
) {
    assert(header_path && target && fns_out);

    const char* args[] = {"-target", target, "-ffreestanding", "-xc-header"};
    CXTranslationUnit translation_unit = clang_parseTranslationUnit(
        index, header_path, args, sizeof(args) / sizeof(args[0]), NULL, 0, CXTranslationUnit_None
    );

    if (!translation_unit) {
        pmsg_exit("%s (%s): failed to parse tu", header_path, target);
    }

    unsigned int num_diagnostics = clang_getNumDiagnostics(translation_unit);
    for (unsigned int diag_idx = 0; diag_idx < num_diagnostics; diag_idx++) {
        CXDiagnostic diag = clang_getDiagnostic(translation_unit, diag_idx);
        CXString cxstr = clang_formatDiagnostic(diag, clang_defaultDiagnosticDisplayOptions());

        const char* msg = clang_getCString(cxstr);
        fprintf(stderr, "    %s\n", msg);

        clang_disposeString(cxstr);
        clang_disposeDiagnostic(diag);
    }

    if (num_diagnostics) {
        pmsg_exit("%s (%s): %u diagnostics", header_path, target, num_diagnostics);
    }

    FnCollector collector = {.path = header_path};
    clang_visitChildren(
        clang_getTranslationUnitCursor(translation_unit), fn_collect_visitor, &collector
    );
    *fns_out = collector.fns;

    return translation_unit;
}

static enum CXVisitorResult field_collect_visitor(CXCursor cursor, CXClientData data) {
    assert(data);
    cursor_vec_push(data, cursor);
    return CXVisit_Continue;
}

static _Bool type_layout_matches(CXType type32, CXType type64) {
    CXType canon32 = clang_getCanonicalType(type32);
    CXType canon64 = clang_getCanonicalType(type64);

    if (canon32.kind == CXType_Void) {
        if (canon64.kind != CXType_Void) {
            fprintf(stderr, "type mismatch (32-bit == void)\n");
            return false;
        } else {
            return true;
        }
    }

    // Check size and alignment
    long long size = clang_Type_getSizeOf(canon32);
    if (size < 0) {
        // Incomplete records are opaque
        if (canon32.kind == CXType_Record && canon64.kind == CXType_Record &&
            clang_Type_getSizeOf(canon64) < 0) {
            return true;
        }

        fprintf(stderr, "type has no size\n");
        return false;
    }

    if (size != clang_Type_getSizeOf(canon64) ||
        clang_Type_getAlignOf(canon32) != clang_Type_getAlignOf(canon64)) {
        fprintf(stderr, "different size or alignment\n");
        return false;
    }

    // Check fields
    if (canon32.kind == CXType_Record) {
        if (canon64.kind != CXType_Record) {
            fprintf(stderr, "type mismatch (32-bit == record)\n");
            return false;
        }

        CursorVec fields32 = {0};
        CursorVec fields64 = {0};
        clang_Type_visitFields(canon32, field_collect_visitor, &fields32);
        clang_Type_visitFields(canon64, field_collect_visitor, &fields64);

        _Bool ok = fields32.len == fields64.len;
        if (!ok) {
            fprintf(stderr, "record field count different\n");
        }

        for (size_t idx = 0; ok && idx < fields32.len; idx++) {
            ok = clang_Cursor_getOffsetOfField(fields32.cursors[idx]) ==
                 clang_Cursor_getOffsetOfField(fields64.cursors[idx]);
            if (!ok) {
                fprintf(stderr, "offset of record field %zu differs\n", idx);
                break;
            }

            ok = type_layout_matches(
                clang_getCursorType(fields32.cursors[idx]),
                clang_getCursorType(fields64.cursors[idx])
            );
            if (!ok) {
                fprintf(stderr, "type layout of record field %zu differs\n", idx);
            }
        }

        cursor_vec_free(&fields32);
        cursor_vec_free(&fields64);
        return ok;
    }

    if (canon32.kind == CXType_ConstantArray) {
        if (canon64.kind != CXType_ConstantArray) {
            fprintf(stderr, "type mismatch (32-bit == constant array)\n");
            return false;
        }

        if (type_layout_matches(clang_getElementType(canon32), clang_getElementType(canon64))) {
            return true;
        } else {
            fprintf(stderr, "constant array element type mismatch\n");
            return false;
        }
    }

    return true;
}

static bool is_int_kind(enum CXTypeKind kind) {
    switch (kind) {
        case CXType_Bool:
        case CXType_Char_U:
        case CXType_UChar:
        case CXType_UShort:
        case CXType_UInt:
        case CXType_ULong:
        case CXType_ULongLong:
        case CXType_Char_S:
        case CXType_SChar:
        case CXType_WChar:
        case CXType_Short:
        case CXType_Int:
        case CXType_Long:
        case CXType_LongLong:
        case CXType_Char16:
        case CXType_Char32:
        case CXType_Enum:
            return true;
        default:
            return false;
    }
}

static bool is_bytes_kind(enum CXTypeKind kind) {
    return kind == CXType_Float || kind == CXType_Double || kind == CXType_Record;
}

static _Bool valid_type(CXType type32, CXType type64) {
    CXType canon32 = clang_getCanonicalType(type32);
    CXType canon64 = clang_getCanonicalType(type64);

    if (canon32.kind == CXType_Pointer) {
        CXType pointee32 = clang_getPointeeType(canon32);
        CXType pointee64 = clang_getPointeeType(canon64);

        enum CXTypeKind pointee_kind = clang_getCanonicalType(pointee32).kind;
        if (pointee_kind == CXType_FunctionProto || pointee_kind == CXType_FunctionNoProto) {
            fprintf(stderr, "function pointers unsupported\n");
            return false;
        }

        if (!type_layout_matches(pointee32, pointee64)) {
            fprintf(stderr, "pointee layout differs on 32 and 64-bit\n");
            return false;
        }

        return true;
    }

    if (!type_layout_matches(canon32, canon64)) {
        fprintf(stderr, "layout differs between 32 and 64-bit\n");
        return false;
    }

    if (is_int_kind(canon32.kind) && is_int_kind(canon64.kind)) {
        return true;
    }

    long long size = clang_Type_getSizeOf(canon32);
    if (is_bytes_kind(canon32.kind) && is_bytes_kind(canon64.kind) && size >= 0 && size <= 8) {
        return true;
    }

    fprintf(stderr, "unsupported type\n");
    return false;
}

typedef struct {
    _Bool is_stdcall;
    int num_args;
    _Bool has_return;
} Signature;

static void check_fn(
    CXCursor fn32, CXCursor fn64, const char* header_path, const char* fn_name, Signature* sig
) {
    assert(header_path && fn_name && sig);

    CXType fn_type32 = clang_getCursorType(fn32);
    CXType fn_type64 = clang_getCursorType(fn64);

    if (clang_isFunctionTypeVariadic(fn_type32) || clang_isFunctionTypeVariadic(fn_type64)) {
        pmsg_exit("%s:%s: variadic functions unsupported", header_path, fn_name);
    }

    if (clang_getFunctionTypeCallingConv(fn_type64) != CXCallingConv_X86_64Win64) {
        pmsg_exit("%s:%s: missing WINAPI/WINAPIV (64-bit not ms_abi)", header_path, fn_name);
    }

    enum CXCallingConv calling_conv32 = clang_getFunctionTypeCallingConv(fn_type32);
    if (calling_conv32 != CXCallingConv_C && calling_conv32 != CXCallingConv_X86StdCall) {
        pmsg_exit(
            "%s:%s: missing WINAPI/WINAPIV (32-bit not stdcall or cdecl)", header_path, fn_name
        );
    }

    sig->is_stdcall = calling_conv32 == CXCallingConv_X86StdCall;
    sig->num_args = clang_Cursor_getNumArguments(fn32);
    if (sig->num_args != clang_Cursor_getNumArguments(fn64)) {
        pmsg_exit("%s:%s: argument count mismatch", header_path, fn_name);
    }

    for (int idx = 0; idx < sig->num_args; idx++) {
        CXType arg32 = clang_getCursorType(clang_Cursor_getArgument(fn32, idx));
        CXType arg64 = clang_getCursorType(clang_Cursor_getArgument(fn64, idx));

        if (!valid_type(arg32, arg64)) {
            pmsg_exit("%s:%s: invalid type for argument %d", header_path, fn_name, idx);
        }
    }

    CXType result_type32 = clang_getResultType(fn_type32);
    CXType result_type64 = clang_getResultType(fn_type64);
    sig->has_return = clang_getCanonicalType(result_type32).kind != CXType_Void;

    if (sig->has_return && !valid_type(result_type32, result_type64)) {
        pmsg_exit("%s:%s: invalid return type", header_path, fn_name);
    }
}

static void
write_thunk32(FILE* file, CXCursor fn, Signature sig, const char* fn_name, size_t global_fn_idx) {
    assert(file && fn_name);

    CXType fn_type = clang_getCursorType(fn);
    CXType result_type = clang_getResultType(fn_type);
    CXString result_type_cxstr = clang_getTypeSpelling(result_type);
    const char* result_type_str = clang_getCString(result_type_cxstr);

    fprintf(
        file, "%s __attribute__((%s)) %s(", result_type_str, sig.is_stdcall ? "stdcall" : "cdecl",
        fn_name
    );

    for (int arg_idx = 0; arg_idx < sig.num_args; arg_idx++) {
        CXCursor arg = clang_Cursor_getArgument(fn, arg_idx);
        CXString arg_cxstr = clang_getTypeSpelling(clang_getCursorType(arg));
        fprintf(
            file, "%s p%d%s", clang_getCString(arg_cxstr), arg_idx,
            arg_idx + 1 == sig.num_args ? "" : ", "
        );

        clang_disposeString(arg_cxstr);
    }

    fprintf(file, ") {\n");

    fprintf(file, "    uint64_t args[%d] = {0};\n", sig.num_args > 1 ? sig.num_args : 1);

    for (int arg_idx = 0; arg_idx < sig.num_args; arg_idx++) {
        CXType arg_ty =
            clang_getCanonicalType(clang_getCursorType(clang_Cursor_getArgument(fn, arg_idx)));
        if (arg_ty.kind == CXType_Pointer) {
            fprintf(file, "    args[%d] = (uint64_t)(uintptr_t)p%d;\n", arg_idx, arg_idx);
        } else if (is_int_kind(arg_ty.kind)) {
            fprintf(file, "    args[%d] = (uint64_t)p%d;\n", arg_idx, arg_idx);
        } else if (is_bytes_kind(arg_ty.kind)) {
            fprintf(
                file, "    __builtin_memcpy(&args[%d], &p%d, sizeof(p%d));\n", arg_idx, arg_idx,
                arg_idx
            );
        }
    }

    fprintf(file, "    uint64_t result = 0;\n");
    fprintf(file, "    elfinator_call64(%zu, args, &result);\n", global_fn_idx);

    CXType canon_result_type = clang_getCanonicalType(result_type);
    if (canon_result_type.kind == CXType_Pointer) {
        fprintf(file, "    return (%s)(uintptr_t)result;\n", result_type_str);
    } else if (is_int_kind(canon_result_type.kind)) {
        fprintf(file, "    return (%s)result;\n", result_type_str);
    } else if (is_bytes_kind(canon_result_type.kind)) {
        fprintf(file, "    %s result_val;\n", result_type_str);
        fprintf(file, "    __builtin_memcpy(&result_val, &result, sizeof(result_val));\n");
        fprintf(file, "    return result_val;\n");
    } else if (sig.has_return) {
        pmsg_exit("unimplemented return type");
    }

    fprintf(file, "}\n\n");

    clang_disposeString(result_type_cxstr);
}

static void
write_thunk64(FILE* file, CXCursor fn, Signature sig, const char* fn_name, size_t global_fn_idx) {
    assert(file);

    fprintf(
        file, "static void thunk%zu(const uint64_t* args, uint64_t* result) {\n", global_fn_idx
    );
    fprintf(file, "    (void)args;\n");
    fprintf(file, "    (void)result;\n");

    for (int arg_idx = 0; arg_idx < sig.num_args; arg_idx++) {
        CXType arg_ty_written = clang_getCursorType(clang_Cursor_getArgument(fn, arg_idx));
        CXType arg_ty = clang_getCanonicalType(arg_ty_written);
        CXString arg_ty_cxstr = clang_getTypeSpelling(arg_ty_written);
        const char* arg_ty_str = clang_getCString(arg_ty_cxstr);

        if (arg_ty.kind == CXType_Pointer) {
            fprintf(
                file, "    %s param%d = (%s)(uintptr_t)args[%d];\n", arg_ty_str, arg_idx,
                arg_ty_str, arg_idx
            );
        } else if (is_int_kind(arg_ty.kind)) {
            fprintf(
                file, "    %s param%d = (%s)args[%d];\n", arg_ty_str, arg_idx, arg_ty_str, arg_idx
            );
        } else if (is_bytes_kind(arg_ty.kind)) {
            fprintf(file, "    %s param%d;\n", arg_ty_str, arg_idx);
            fprintf(
                file, "    __builtin_memcpy(&param%d, &args[%d], sizeof(param%d));\n", arg_idx,
                arg_idx, arg_idx
            );
        }

        clang_disposeString(arg_ty_cxstr);
    }

    CXType fn_type = clang_getCursorType(fn);
    CXType result_type_written = clang_getResultType(fn_type);
    CXType result_type = clang_getCanonicalType(result_type_written);
    if (result_type.kind == CXType_Pointer) {
        fprintf(file, "    *result = (uint64_t)(uintptr_t)");
    } else if (is_int_kind(result_type.kind)) {
        fprintf(file, "    *result = (uint64_t)");
    } else if (is_bytes_kind(result_type.kind)) {
        CXString result_ty_cxstr = clang_getTypeSpelling(result_type_written);
        const char* result_ty_str = clang_getCString(result_ty_cxstr);
        fprintf(file, "    %s result_val = ", result_ty_str);
        clang_disposeString(result_ty_cxstr);
    } else if (sig.has_return) {
        pmsg_exit("unimplemented return type");
    } else {
        fprintf(file, "    ");
    }

    fprintf(file, "%s(", fn_name);
    for (int idx = 0; idx < sig.num_args; idx++) {
        if (idx + 1 == sig.num_args) {
            fprintf(file, "param%d", idx);
        } else {
            fprintf(file, "param%d, ", idx);
        }
    }
    fprintf(file, ");\n");

    if (result_type.kind == CXType_Pointer) {
        fprintf(file, "    assert(*result >> 32 == 0);\n");
    } else if (is_bytes_kind(result_type.kind)) {
        fprintf(file, "    __builtin_memcpy(result, &result_val, sizeof(result_val));\n");
    }

    fprintf(file, "}\n\n");
}

#define OUT_DIR32 "build/builtins-out/32"
#define OUT_DIR64 "build/builtins-out/64"
#define ROOT_FROM_OUT "../../../"

static void write_include(FILE* file, const char* path) {
    fprintf(file, "#include \"%s%s\"\n", path[0] == '/' ? "" : ROOT_FROM_OUT, path);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <header1> <header2>...\n", argv[0]);
        return 1;
    }

    mkdir_recursive(OUT_DIR32);
    mkdir_recursive(OUT_DIR64);

    CXIndex index = clang_createIndex(0, 0);

    size_t num_headers = argc - 1;
    char** headers = argv + 1;

    FILE* host_thunk_file = open_output_file("", OUT_DIR64, "builtins_thunk.c");
    fprintf(host_thunk_file, "// Generated by gen-builtins, do not modify\n");
    fprintf(host_thunk_file, "#include <assert.h>\n");
    fprintf(host_thunk_file, "#include <stdint.h>\n");
    fprintf(host_thunk_file, "#include <stdio.h>\n");
    fprintf(host_thunk_file, "#include <stdlib.h>\n\n");
    write_include(host_thunk_file, "src/builtin_dlls.h");
    fprintf(host_thunk_file, "\n");
    for (size_t header_idx = 0; header_idx < num_headers; header_idx++) {
        write_include(host_thunk_file, headers[header_idx]);
    }
    fprintf(host_thunk_file, "\n#ifdef ELFINATOR_COMPAT\n\n");

    size_t global_fn_idx = 0;
    StrListList dlls = str_list_list_init();

    for (size_t header_idx = 0; header_idx < num_headers; header_idx++) {
        const char* header = headers[header_idx];
        printf("%s:\n", header);

        StrList function_names = str_list_init();

        char dll_name[512];
        if (make_output_path(dll_name, sizeof(dll_name), header, "", ".dll") != 0) {
            pmsg_exit("path too long");
        }

        FILE* def_file = open_output_file(header, OUT_DIR32, ".def");
        fprintf(def_file, "; Generated by gen-builtins, do not modify\n");
        fprintf(def_file, "LIBRARY %s\n", dll_name);
        fprintf(def_file, "EXPORTS\n");

        FILE* thunk32_file = open_output_file(header, OUT_DIR32, ".c");
        fprintf(thunk32_file, "// Generated by gen-builtins, do not modify\n");
        write_include(thunk32_file, header);
        fprintf(thunk32_file, "#include <stdint.h>\n");
        fprintf(
            thunk32_file, "__declspec(dllimport) void elfinator_call64(uint32_t idx, const "
                          "uint64_t* args, uint64_t* ret);\n\n\n"
        );

        CursorVec fns32 = {0};
        CursorVec fns64 = {0};
        CXTranslationUnit tu32 =
            parse_translation_unit(index, header, "i686-w64-windows-gnu", &fns32);
        CXTranslationUnit tu64 = parse_translation_unit(index, header, "x86_64-linux-gnu", &fns64);

        if (fns32.len != fns64.len) {
            pmsg_exit("%s: 32 and 64-bit versions have different function counts", header);
        }

        for (size_t fn_idx = 0; fn_idx < fns32.len; fn_idx++) {
            CXCursor fn32 = fns32.cursors[fn_idx];
            CXCursor fn64 = fns64.cursors[fn_idx];

            CXString cxname32 = clang_getCursorSpelling(fn32);
            CXString cxname64 = clang_getCursorSpelling(fn64);
            const char* name32 = clang_getCString(cxname32);
            const char* name64 = clang_getCString(cxname64);
            str_list_push(&function_names, name32);

            if (strcmp(name32, name64) != 0) {
                pmsg_exit("%s: 32 and 64-bit versions disagree on function order", header);
            }

            printf("  found fn `%s`\n", name64);
            Signature sig;
            check_fn(fn32, fn64, header, name64, &sig);

            if (sig.is_stdcall) {
                long long int arg_bytes = 0ll;
                for (int arg_idx = 0; arg_idx < sig.num_args; arg_idx++) {
                    CXType arg = clang_getCursorType(clang_Cursor_getArgument(fn32, arg_idx));
                    arg_bytes += (clang_Type_getSizeOf(arg) + 3ll) & ~3ll;
                }

                fprintf(def_file, "    %s@%lld\n", name32, arg_bytes);
            } else {
                fprintf(def_file, "    %s\n", name32);
            }

            write_thunk32(thunk32_file, fn32, sig, name32, global_fn_idx);
            write_thunk64(host_thunk_file, fn64, sig, name64, global_fn_idx);

            clang_disposeString(cxname32);
            clang_disposeString(cxname64);

            global_fn_idx++;
        }

        cursor_vec_free(&fns32);
        cursor_vec_free(&fns64);
        clang_disposeTranslationUnit(tu32);
        clang_disposeTranslationUnit(tu64);

        fclose(def_file);
        fclose(thunk32_file);
        str_list_sort(&function_names);
        str_list_list_push(&dlls, function_names);
    }

    fprintf(host_thunk_file, "static void (*const thunks[])(const uint64_t*, uint64_t*) = {\n");
    for (size_t idx = 0; idx < global_fn_idx; idx++) {
        fprintf(host_thunk_file, "    thunk%zu,\n", idx);
    }
    fprintf(host_thunk_file, "};\n\n");

    fprintf(
        host_thunk_file,
        "void builtins_dispatch(uint32_t idx, const uint64_t* args, uint64_t* result) {\n"
    );
    fprintf(host_thunk_file, "    if (idx >= sizeof(thunks) / sizeof(thunks[0])) {\n");
    fprintf(
        host_thunk_file,
        "        fprintf(stderr, \"bad builtin thunk index %%lu\\n\", (unsigned long)idx);\n"
    );
    fprintf(host_thunk_file, "        exit(1);\n");
    fprintf(host_thunk_file, "    }\n");
    fprintf(host_thunk_file, "    thunks[idx](args, result);\n");
    fprintf(host_thunk_file, "}\n\n");
    fprintf(host_thunk_file, "#endif // ELFINATOR_COMPAT\n\n");

    for (size_t header_idx = 0; header_idx < num_headers; header_idx++) {
        fprintf(host_thunk_file, "static const BuiltinExport exports%zu[] = {\n", header_idx);
        for (size_t fn_idx = 0; fn_idx < dlls.list[header_idx].len; fn_idx++) {
            const char* name = dlls.list[header_idx].strs[fn_idx];
            fprintf(host_thunk_file, "    { .name = \"%s\", .fn = (void*)%s },\n", name, name);
        }
        fprintf(host_thunk_file, "};\n\n");
    }

    fprintf(host_thunk_file, "const size_t builtin_dll_count = %zu;\n\n", num_headers);

    fprintf(host_thunk_file, "const BuiltinDll builtin_dlls[] = {\n");
    for (size_t header_idx = 0; header_idx < num_headers; header_idx++) {
        char dll_name[512];
        if (make_output_path(dll_name, sizeof(dll_name), headers[header_idx], "", ".dll") != 0) {
            pmsg_exit("path too long");
        }

        fprintf(
            host_thunk_file,
            "    { .name = \"%s\", .exports = exports%zu, .export_count = %zu },\n", dll_name,
            header_idx, dlls.list[header_idx].len
        );
    }
    fprintf(host_thunk_file, "};\n");

    fclose(host_thunk_file);
    str_list_list_free(&dlls);

    return 0;
}

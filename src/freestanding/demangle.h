/* Defs for interface to demanglers.
   Copyright (C) 1992-2025 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License
   as published by the Free Software Foundation; either version 2, or
   (at your option) any later version.

   In addition to the permissions in the GNU Library General Public
   License, the Free Software Foundation gives you unlimited
   permission to link the compiled version of this file into
   combinations with other programs, and to distribute those
   combinations without any restriction coming from the use of this
   file.  (The Library Public License restrictions do apply in other
   respects; for example, they cover modification of the file, and
   distribution when not linked into a combined executable.)

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.
*/


#if !defined (DEMANGLE_H)
#define DEMANGLE_H

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Options passed to cplus_demangle (in 2nd parameter). */

#define DMGL_NO_OPTS	 0		/* For readability... */
#define DMGL_PARAMS	 (1 << 0)	/* Include function args */
#define DMGL_ANSI	 (1 << 1)	/* Include const, volatile, etc */
#define DMGL_JAVA	 (1 << 2)	/* Demangle as Java rather than C++. */
#define DMGL_VERBOSE	 (1 << 3)	/* Include implementation details.  */
#define DMGL_TYPES	 (1 << 4)	/* Also try to demangle type encodings.  */
#define DMGL_RET_POSTFIX (1 << 5)       /* Print function return types (when present) after function signature. It applies only to the toplevel function type.  */
#define DMGL_RET_DROP	 (1 << 6)       
/* Suppress printing function return
                        types, even if present.  It applies
                        only to the toplevel function type.
                        */

#define DMGL_AUTO	 (1 << 8)
#define DMGL_GNU_V3	 (1 << 14)
#define DMGL_GNAT	 (1 << 15)
#define DMGL_DLANG	 (1 << 16)
#define DMGL_RUST	 (1 << 17)	/* Rust wraps GNU_V3 style mangling.  */

/* If none of these are set, use 'current_demangling_style' as the default. */
#define DMGL_STYLE_MASK (DMGL_AUTO|DMGL_GNU_V3|DMGL_JAVA|DMGL_GNAT|DMGL_DLANG|DMGL_RUST)

/* Disable a limit on the depth of recursion in mangled strings.
    Note if this limit is disabled then stack exhaustion is possible when
    demangling pathologically complicated strings.  Bug reports about stack
    exhaustion when the option is enabled will be rejected.  */
#define DMGL_NO_RECURSE_LIMIT (1 << 18)

/* If DMGL_NO_RECURSE_LIMIT is not enabled, then this is the value used as
    the maximum depth of recursion allowed.  It should be enough for any
    real-world mangled name.  */
#define DEMANGLE_RECURSION_LIMIT 2048

/* Enumeration of possible demangling styles.

    Lucid and ARM styles are still kept logically distinct, even though
    they now both behave identically.  The resulting style is actual the
    union of both.  I.E. either style recognizes both "__pt__" and "__rf__"
    for operator "->", even though the first is lucid style and the second
    is ARM style. (FIXME?) */

extern enum demangling_styles
{
    no_demangling = -1,
    unknown_demangling = 0,
    auto_demangling = DMGL_AUTO,
    gnu_v3_demangling = DMGL_GNU_V3,
    java_demangling = DMGL_JAVA,
    gnat_demangling = DMGL_GNAT,
    dlang_demangling = DMGL_DLANG,
    rust_demangling = DMGL_RUST
} current_demangling_style;

/* Define string names for the various demangling styles. */

#define NO_DEMANGLING_STYLE_STRING            "none"
#define AUTO_DEMANGLING_STYLE_STRING	      "auto"
#define GNU_V3_DEMANGLING_STYLE_STRING        "gnu-v3"
#define JAVA_DEMANGLING_STYLE_STRING          "java"
#define GNAT_DEMANGLING_STYLE_STRING          "gnat"
#define DLANG_DEMANGLING_STYLE_STRING         "dlang"
#define RUST_DEMANGLING_STYLE_STRING          "rust"

/* Some macros to test what demangling style is active. */

#define CURRENT_DEMANGLING_STYLE current_demangling_style
#define AUTO_DEMANGLING (((int) CURRENT_DEMANGLING_STYLE) & DMGL_AUTO)
#define GNU_V3_DEMANGLING (((int) CURRENT_DEMANGLING_STYLE) & DMGL_GNU_V3)
#define JAVA_DEMANGLING (((int) CURRENT_DEMANGLING_STYLE) & DMGL_JAVA)
#define GNAT_DEMANGLING (((int) CURRENT_DEMANGLING_STYLE) & DMGL_GNAT)
#define DLANG_DEMANGLING (((int) CURRENT_DEMANGLING_STYLE) & DMGL_DLANG)
#define RUST_DEMANGLING (((int) CURRENT_DEMANGLING_STYLE) & DMGL_RUST)

/* Provide information about the available demangle styles. This code is
    pulled from gdb into libiberty because it is useful to binutils also.  */

extern const struct demangler_engine
{
    const char *const demangling_style_name;
    const enum demangling_styles demangling_style;
    const char *const demangling_style_doc;
} libiberty_demanglers[];

extern char *
cplus_demangle (const char *mangled, int options);

/* Note: This sets global state.  FIXME if you care about multi-threading. */

extern enum demangling_styles
cplus_demangle_set_style (enum demangling_styles style);

extern enum demangling_styles
cplus_demangle_name_to_style (const char *name);

/* Callback typedef for allocation-less demangler interfaces. */
typedef void (*demangle_callbackref) (const char *, std::size_t, void *);

/* V3 ABI demangling entry points, defined in cp-demangle.c.  Callback
    variants return non-zero on success, zero on error.  char* variants
    return a string allocated by malloc on success, NULL on error.  */
extern int
cplus_demangle_v3_callback (const char *mangled, int options,
                            demangle_callbackref callback, void *opaque);

extern char*
cplus_demangle_v3 (const char *mangled, int options);

extern int
java_demangle_v3_callback (const char *mangled,
                            demangle_callbackref callback, void *opaque);

extern char*
java_demangle_v3 (const char *mangled);

char *
ada_demangle (const char *mangled, int options);

extern char *
dlang_demangle (const char *mangled, int options);

extern int
rust_demangle_callback (const char *mangled, int options,
                        demangle_callbackref callback, void *opaque);


extern char *
rust_demangle (const char *mangled, int options);

enum gnu_v3_ctor_kinds {
    gnu_v3_complete_object_ctor = 1,
    gnu_v3_base_object_ctor,
    gnu_v3_complete_object_allocating_ctor,
    /* These are not part of the V3 ABI.  Unified constructors are generated
    as a speed-for-space optimization when the -fdeclone-ctor-dtor option
    is used, and are always internal symbols.  */
    gnu_v3_unified_ctor,
    gnu_v3_object_ctor_group
};

/* Return non-zero iff NAME is the mangled form of a constructor name
    in the G++ V3 ABI demangling style.  Specifically, return an `enum
    gnu_v3_ctor_kinds' value indicating what kind of constructor
    it is.  */
extern enum gnu_v3_ctor_kinds
    is_gnu_v3_mangled_ctor (const char *name);


enum gnu_v3_dtor_kinds {
    gnu_v3_deleting_dtor = 1,
    gnu_v3_complete_object_dtor,
    gnu_v3_base_object_dtor,
    /* These are not part of the V3 ABI.  Unified destructors are generated
    as a speed-for-space optimization when the -fdeclone-ctor-dtor option
    is used, and are always internal symbols.  */
    gnu_v3_unified_dtor,
    gnu_v3_object_dtor_group
};

/* Return non-zero iff NAME is the mangled form of a destructor name
    in the G++ V3 ABI demangling style.  Specifically, return an `enum
    gnu_v3_dtor_kinds' value, indicating what kind of destructor
    it is.  */
extern enum gnu_v3_dtor_kinds
    is_gnu_v3_mangled_dtor (const char *name);

/* The V3 demangler works in two passes.  The first pass builds a tree
    representation of the mangled name, and the second pass turns the
    tree representation into a demangled string.  Here we define an
    interface to permit a caller to build their own tree
    representation, which they can pass to the demangler to get a
    demangled string.  This can be used to canonicalize user input into
    something which the demangler might output.  It could also be used
    by other demanglers in the future.  */

/* These are the component types which may be found in the tree.  Many
    component types have one or two subtrees, referred to as left and
    right (a component type with only one subtree puts it in the left
    subtree).  */

enum demangle_component_type
{
    /* A name, with a length and a pointer to a string.  */
    DEMANGLE_COMPONENT_NAME,
    /* A qualified name.  The left subtree is a class or namespace or
    some such thing, and the right subtree is a name qualified by
    that class.  */
    DEMANGLE_COMPONENT_QUAL_NAME,
    /* A local name.  The left subtree describes a function, and the
    right subtree is a name which is local to that function.  */
    DEMANGLE_COMPONENT_LOCAL_NAME,
    /* A typed name.  The left subtree is a name, and the right subtree
    describes that name as a function.  */
    DEMANGLE_COMPONENT_TYPED_NAME,
    /* A template.  The left subtree is a template name, and the right
    subtree is a template argument list.  */
    DEMANGLE_COMPONENT_TEMPLATE,
    /* A template parameter.  This holds a number, which is the template
    parameter index.  */
    DEMANGLE_COMPONENT_TEMPLATE_PARAM,
    /* A function parameter.  This holds a number, which is the index.  */
    DEMANGLE_COMPONENT_FUNCTION_PARAM,
    /* A constructor.  This holds a name and the kind of
    constructor.  */
    DEMANGLE_COMPONENT_CTOR,
    /* A destructor.  This holds a name and the kind of destructor.  */
    DEMANGLE_COMPONENT_DTOR,
    /* A vtable.  This has one subtree, the type for which this is a
    vtable.  */
    DEMANGLE_COMPONENT_VTABLE,
    /* A VTT structure.  This has one subtree, the type for which this
    is a VTT.  */
    DEMANGLE_COMPONENT_VTT,
    /* A construction vtable.  The left subtree is the type for which
    this is a vtable, and the right subtree is the derived type for
    which this vtable is built.  */
    DEMANGLE_COMPONENT_CONSTRUCTION_VTABLE,
    /* A typeinfo structure.  This has one subtree, the type for which
    this is the tpeinfo structure.  */
    DEMANGLE_COMPONENT_TYPEINFO,
    /* A typeinfo name.  This has one subtree, the type for which this
    is the typeinfo name.  */
    DEMANGLE_COMPONENT_TYPEINFO_NAME,
    /* A typeinfo function.  This has one subtree, the type for which
    this is the tpyeinfo function.  */
    DEMANGLE_COMPONENT_TYPEINFO_FN,
    /* A thunk.  This has one subtree, the name for which this is a
    thunk.  */
    DEMANGLE_COMPONENT_THUNK,
    /* A virtual thunk.  This has one subtree, the name for which this
    is a virtual thunk.  */
    DEMANGLE_COMPONENT_VIRTUAL_THUNK,
    /* A covariant thunk.  This has one subtree, the name for which this
    is a covariant thunk.  */
    DEMANGLE_COMPONENT_COVARIANT_THUNK,
    /* A Java class.  This has one subtree, the type.  */
    DEMANGLE_COMPONENT_JAVA_CLASS,
    /* A guard variable.  This has one subtree, the name for which this
    is a guard variable.  */
    DEMANGLE_COMPONENT_GUARD,
    /* The init and wrapper functions for C++11 thread_local variables.  */
    DEMANGLE_COMPONENT_TLS_INIT,
    DEMANGLE_COMPONENT_TLS_WRAPPER,
    /* A reference temporary.  This has one subtree, the name for which
    this is a temporary.  */
    DEMANGLE_COMPONENT_REFTEMP,
    /* A hidden alias.  This has one subtree, the encoding for which it
    is providing alternative linkage.  */
    DEMANGLE_COMPONENT_HIDDEN_ALIAS,
    /* A standard substitution.  This holds the name of the
    substitution.  */
    DEMANGLE_COMPONENT_SUB_STD,
    /* The restrict qualifier.  The one subtree is the type which is
    being qualified.  */
    DEMANGLE_COMPONENT_RESTRICT,
    /* The volatile qualifier.  The one subtree is the type which is
    being qualified.  */
    DEMANGLE_COMPONENT_VOLATILE,
    /* The const qualifier.  The one subtree is the type which is being
    qualified.  */
    DEMANGLE_COMPONENT_CONST,
    /* The restrict qualifier modifying a member function.  The one
    subtree is the type which is being qualified.  */
    DEMANGLE_COMPONENT_RESTRICT_THIS,
    /* The volatile qualifier modifying a member function.  The one
    subtree is the type which is being qualified.  */
    DEMANGLE_COMPONENT_VOLATILE_THIS,
    /* The const qualifier modifying a member function.  The one subtree
    is the type which is being qualified.  */
    DEMANGLE_COMPONENT_CONST_THIS,
    /* C++11 A reference modifying a member function.  The one subtree is the
    type which is being referenced.  */
    DEMANGLE_COMPONENT_REFERENCE_THIS,
    /* C++11: An rvalue reference modifying a member function.  The one
    subtree is the type which is being referenced.  */
    DEMANGLE_COMPONENT_RVALUE_REFERENCE_THIS,
    /* C++23: A member function with explict object parameter.  */
    DEMANGLE_COMPONENT_XOBJ_MEMBER_FUNCTION,
    /* A vendor qualifier.  The left subtree is the type which is being
    qualified, and the right subtree is the name of the
    qualifier.  */
    DEMANGLE_COMPONENT_VENDOR_TYPE_QUAL,
    /* A pointer.  The one subtree is the type which is being pointed
    to.  */
    DEMANGLE_COMPONENT_POINTER,
    /* A reference.  The one subtree is the type which is being
    referenced.  */
    DEMANGLE_COMPONENT_REFERENCE,
    /* C++0x: An rvalue reference.  The one subtree is the type which is
    being referenced.  */
    DEMANGLE_COMPONENT_RVALUE_REFERENCE,
    /* A complex type.  The one subtree is the base type.  */
    DEMANGLE_COMPONENT_COMPLEX,
    /* An imaginary type.  The one subtree is the base type.  */
    DEMANGLE_COMPONENT_IMAGINARY,
    /* A builtin type.  This holds the builtin type information.  */
    DEMANGLE_COMPONENT_BUILTIN_TYPE,
    /* A vendor's builtin type.  This holds the name of the type.  */
    DEMANGLE_COMPONENT_VENDOR_TYPE,
    /* A function type.  The left subtree is the return type.  The right
    subtree is a list of ARGLIST nodes.  Either or both may be
    NULL.  */
    DEMANGLE_COMPONENT_FUNCTION_TYPE,
    /* An array type.  The left subtree is the dimension, which may be
    NULL, or a string (represented as DEMANGLE_COMPONENT_NAME), or an
    expression.  The right subtree is the element type.  */
    DEMANGLE_COMPONENT_ARRAY_TYPE,
    /* A pointer to member type.  The left subtree is the class type,
    and the right subtree is the member type.  CV-qualifiers appear
    on the latter.  */
    DEMANGLE_COMPONENT_PTRMEM_TYPE,
    /* A fixed-point type.  */
    DEMANGLE_COMPONENT_FIXED_TYPE,
    /* A vector type.  The left subtree is the number of elements,
    the right subtree is the element type.  */
    DEMANGLE_COMPONENT_VECTOR_TYPE,
    /* An argument list.  The left subtree is the current argument, and
    the right subtree is either NULL or another ARGLIST node.  */
    DEMANGLE_COMPONENT_ARGLIST,
    /* A template argument list.  The left subtree is the current
    template argument, and the right subtree is either NULL or
    another TEMPLATE_ARGLIST node.  */
    DEMANGLE_COMPONENT_TEMPLATE_ARGLIST,
    /* A template parameter object (C++20).  The left subtree is the
    corresponding template argument.  */
    DEMANGLE_COMPONENT_TPARM_OBJ,
    /* An initializer list.  The left subtree is either an explicit type or
    NULL, and the right subtree is a DEMANGLE_COMPONENT_ARGLIST.  */
    DEMANGLE_COMPONENT_INITIALIZER_LIST,
    /* An operator.  This holds information about a standard
    operator.  */
    DEMANGLE_COMPONENT_OPERATOR,
    /* An extended operator.  This holds the number of arguments, and
    the name of the extended operator.  */
    DEMANGLE_COMPONENT_EXTENDED_OPERATOR,
    /* A typecast, represented as a unary operator.  The one subtree is
    the type to which the argument should be cast.  */
    DEMANGLE_COMPONENT_CAST,
    /* A conversion operator, represented as a unary operator.  The one
    subtree is the type to which the argument should be converted
    to.  */
    DEMANGLE_COMPONENT_CONVERSION,
    /* A nullary expression.  The left subtree is the operator.  */
    DEMANGLE_COMPONENT_NULLARY,
    /* A unary expression.  The left subtree is the operator, and the
    right subtree is the single argument.  */
    DEMANGLE_COMPONENT_UNARY,
    /* A binary expression.  The left subtree is the operator, and the
    right subtree is a BINARY_ARGS.  */
    DEMANGLE_COMPONENT_BINARY,
    /* Arguments to a binary expression.  The left subtree is the first
    argument, and the right subtree is the second argument.  */
    DEMANGLE_COMPONENT_BINARY_ARGS,
    /* A trinary expression.  The left subtree is the operator, and the
    right subtree is a TRINARY_ARG1.  */
    DEMANGLE_COMPONENT_TRINARY,
    /* Arguments to a trinary expression.  The left subtree is the first
    argument, and the right subtree is a TRINARY_ARG2.  */
    DEMANGLE_COMPONENT_TRINARY_ARG1,
    /* More arguments to a trinary expression.  The left subtree is the
    second argument, and the right subtree is the third argument.  */
    DEMANGLE_COMPONENT_TRINARY_ARG2,
    /* A literal.  The left subtree is the type, and the right subtree
    is the value, represented as a DEMANGLE_COMPONENT_NAME.  */
    DEMANGLE_COMPONENT_LITERAL,
    /* A negative literal.  Like LITERAL, but the value is negated.
    This is a minor hack: the NAME used for LITERAL points directly
    to the mangled string, but since negative numbers are mangled
    using 'n' instead of '-', we want a way to indicate a negative
    number which involves neither modifying the mangled string nor
    allocating a new copy of the literal in memory.  */
    DEMANGLE_COMPONENT_LITERAL_NEG,
    /* A vendor's builtin expression.  The left subtree holds the
    expression's name, and the right subtree is a argument list.  */
    DEMANGLE_COMPONENT_VENDOR_EXPR,
    /* A libgcj compiled resource.  The left subtree is the name of the
    resource.  */
    DEMANGLE_COMPONENT_JAVA_RESOURCE,
    /* A name formed by the concatenation of two parts.  The left
    subtree is the first part and the right subtree the second.  */
    DEMANGLE_COMPONENT_COMPOUND_NAME,
    /* A name formed by a single character.  */
    DEMANGLE_COMPONENT_CHARACTER,
    /* A number.  */
    DEMANGLE_COMPONENT_NUMBER,
    /* A decltype type.  */
    DEMANGLE_COMPONENT_DECLTYPE,
    /* Global constructors keyed to name.  */
    DEMANGLE_COMPONENT_GLOBAL_CONSTRUCTORS,
    /* Global destructors keyed to name.  */
    DEMANGLE_COMPONENT_GLOBAL_DESTRUCTORS,
    /* A lambda closure type.  */
    DEMANGLE_COMPONENT_LAMBDA,
    /* A default argument scope.  */
    DEMANGLE_COMPONENT_DEFAULT_ARG,
    /* An unnamed type.  */
    DEMANGLE_COMPONENT_UNNAMED_TYPE,
    /* A transactional clone.  This has one subtree, the encoding for
    which it is providing alternative linkage.  */
    DEMANGLE_COMPONENT_TRANSACTION_CLONE,
    /* A non-transactional clone entry point.  In the i386/x86_64 abi,
    the unmangled symbol of a tm_callable becomes a thunk and the
    non-transactional function version is mangled thus.  */
    DEMANGLE_COMPONENT_NONTRANSACTION_CLONE,
    /* A pack expansion.  */
    DEMANGLE_COMPONENT_PACK_EXPANSION,
    /* A name with an ABI tag.  */
    DEMANGLE_COMPONENT_TAGGED_NAME,
    /* A transaction-safe function type.  */
    DEMANGLE_COMPONENT_TRANSACTION_SAFE,
    /* A cloned function.  */
    DEMANGLE_COMPONENT_CLONE,
    /* A member-like friend function.  */
    DEMANGLE_COMPONENT_FRIEND,
    DEMANGLE_COMPONENT_NOEXCEPT,
    DEMANGLE_COMPONENT_THROW_SPEC,

    DEMANGLE_COMPONENT_STRUCTURED_BINDING,

    DEMANGLE_COMPONENT_MODULE_NAME,
    DEMANGLE_COMPONENT_MODULE_PARTITION,
    DEMANGLE_COMPONENT_MODULE_ENTITY,
    DEMANGLE_COMPONENT_MODULE_INIT,

    DEMANGLE_COMPONENT_TEMPLATE_HEAD,
    DEMANGLE_COMPONENT_TEMPLATE_TYPE_PARM,
    DEMANGLE_COMPONENT_TEMPLATE_NON_TYPE_PARM,
    DEMANGLE_COMPONENT_TEMPLATE_TEMPLATE_PARM,
    DEMANGLE_COMPONENT_TEMPLATE_PACK_PARM,

    DEMANGLE_COMPONENT_CONSTRAINTS,

    /* A builtin type with argument.  This holds the builtin type
    information.  */
    DEMANGLE_COMPONENT_EXTENDED_BUILTIN_TYPE

};

/* Types which are only used internally.  */

struct demangle_operator_info;
struct demangle_builtin_type_info;

/* A node in the tree representation is an instance of a struct
    demangle_component.  Note that the field names of the struct are
    not well protected against macros defined by the file including
    this one.  We can fix this if it ever becomes a problem.  */

struct demangle_component
{
    /* The type of this component.  */
    enum demangle_component_type type;

    /* Guard against recursive component printing.
    Initialize to zero.  Private to d_print_comp.
    All other fields are final after initialization.  */
    int d_printing;
    int d_counting;

    union
    {
    /* For DEMANGLE_COMPONENT_NAME.  */
    struct
    {
        /* A pointer to the name (which need not NULL terminated) and
    its length.  */
        const char *s;
        int len;
    } s_name;

    /* For DEMANGLE_COMPONENT_OPERATOR.  */
    struct
    {
        /* Operator.  */
        const struct demangle_operator_info *op;
    } s_operator;

    /* For DEMANGLE_COMPONENT_EXTENDED_OPERATOR.  */
    struct
    {
        /* Number of arguments.  */
        int args;
        /* Name.  */
        struct demangle_component *name;
    } s_extended_operator;

    /* For DEMANGLE_COMPONENT_FIXED_TYPE.  */
    struct
    {
        /* The length, indicated by a C integer type name.  */
        struct demangle_component *length;
        /* _Accum or _Fract?  */
        short accum;
        /* Saturating or not?  */
        short sat;
    } s_fixed;

    /* For DEMANGLE_COMPONENT_CTOR.  */
    struct
    {
        /* Kind of constructor.  */
        enum gnu_v3_ctor_kinds kind;
        /* Name.  */
        struct demangle_component *name;
    } s_ctor;

    /* For DEMANGLE_COMPONENT_DTOR.  */
    struct
    {
        /* Kind of destructor.  */
        enum gnu_v3_dtor_kinds kind;
        /* Name.  */
        struct demangle_component *name;
    } s_dtor;

    /* For DEMANGLE_COMPONENT_BUILTIN_TYPE.  */
    struct
    {
        /* Builtin type.  */
        const struct demangle_builtin_type_info *type;
    } s_builtin;

    /* For DEMANGLE_COMPONENT_EXTENDED_BUILTIN_TYPE.  */
    struct
    {
        /* Builtin type.  */
        const struct demangle_builtin_type_info *type;
        short arg;
        char suffix;
    } s_extended_builtin;

    /* For DEMANGLE_COMPONENT_SUB_STD.  */
    struct
    {
        /* Standard substitution string.  */
        const char* string;
        /* Length of string.  */
        int len;
    } s_string;

    /* For DEMANGLE_COMPONENT_*_PARAM.  */
    struct
    {
        /* Parameter index.  */
        long number;
    } s_number;

    /* For DEMANGLE_COMPONENT_CHARACTER.  */
    struct
    {
        int character;
    } s_character;

    /* For other types.  */
    struct
    {
        /* Left (or only) subtree.  */
        struct demangle_component *left;
        /* Right subtree.  */
        struct demangle_component *right;
    } s_binary;

    struct
    {
        /* subtree, same place as d_left.  */
        struct demangle_component *sub;
        /* integer.  */
        int num;
    } s_unary_num;

    } u;
};


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif	/* DEMANGLE_H */

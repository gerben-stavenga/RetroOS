/* Demangler for g++ V3 ABI.
   Copyright (C) 2003-2025 Free Software Foundation, Inc.
   Written by Ian Lance Taylor <ian@wasabisystems.com>.

   This file is part of the libiberty library, which is part of GCC.

   This file is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   In addition to the permissions in the GNU General Public License, the
   Free Software Foundation gives you unlimited permission to link the
   compiled version of this file into combinations with other programs,
   and to distribute those combinations without any restriction coming
   from the use of this file.  (The General Public License restrictions
   do apply in other respects; for example, they cover modification of
   the file, and distribution when not linked into a combined
   executable.)

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA. 
*/

/* This code implements a demangler for the g++ V3 ABI.  The ABI is
   described on this web page:
       https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling

   This code was written while looking at the demangler written by
   Alex Samuel <samuel@codesourcery.com>.

   This code first pulls the mangled name apart into a list of
   components, and then walks the list generating the demangled
   name.

   This file will normally define the following functions, q.v.:
      char *cplus_demangle_v3(const char *mangled, int options)
      char *java_demangle_v3(const char *mangled)
      int cplus_demangle_v3_callback(const char *mangled, int options,
                                     demangle_callbackref callback)
      int java_demangle_v3_callback(const char *mangled,
                                    demangle_callbackref callback)
      enum gnu_v3_ctor_kinds is_gnu_v3_mangled_ctor (const char *name)
      enum gnu_v3_dtor_kinds is_gnu_v3_mangled_dtor (const char *name)

   Also, the interface to the component list is public, and defined in
   demangle.h.  The interface consists of these types, which are
   defined in demangle.h:
      enum demangle_component_type
      struct demangle_component
      demangle_callbackref
   and these functions defined in this file:
      cplus_demangle_fill_name
      cplus_demangle_fill_extended_operator
      cplus_demangle_fill_ctor
      cplus_demangle_fill_dtor
      cplus_demangle_print
      cplus_demangle_print_callback
   and other functions defined in the file cp-demint.c.

   This file also defines some other functions and variables which are
   only to be used by the file cp-demint.c.

   Preprocessor macros you can define while compiling this file:

   IN_LIBGCC2
      If defined, this file defines the following functions, q.v.:
         char *__cxa_demangle (const char *mangled, char *buf, size_t *len,
                               int *status)
         int __gcclibcxx_demangle_callback (const char *,
                                            void (*)
                                              (const char *, size_t, void *),
                                            void *)
      instead of cplus_demangle_v3[_callback]() and
      java_demangle_v3[_callback]().

   IN_GLIBCPP_V3
      If defined, this file defines only __cxa_demangle() and
      __gcclibcxx_demangle_callback(), and no other publically visible
      functions or variables.

   STANDALONE_DEMANGLER
      If defined, this file defines a main() function which demangles
      any arguments, or, if none, demangles stdin.

   CP_DEMANGLE_DEBUG
      If defined, turns on debugging mode, which prints information on
      stdout about the mangled string.  This is not generally useful.

   CHECK_DEMANGLER
      If defined, additional sanity checks will be performed.  It will
      cause some slowdown, but will allow to catch out-of-bound access
      errors earlier.  This macro is intended for testing and debugging.  */

#include <limits.h>

#include "demangle.h"
#include "cp-demangle.h"

#include "utils.h"

/* See if the compiler supports dynamic arrays.  */

/* We avoid pulling in the ctype tables, to prevent pulling in
additional unresolved symbols when this code is used in a library.
FIXME: Is this really a valid reason?  This comes from the original
V3 demangler code.

As of this writing this file has the following undefined references
when compiled with -DIN_GLIBCPP_V3: realloc, free, memcpy, strcpy,
strcat, strlen.  */

#define IS_DIGIT(c) ((c) >= '0' && (c) <= '9')
#define IS_UPPER(c) ((c) >= 'A' && (c) <= 'Z')
#define IS_LOWER(c) ((c) >= 'a' && (c) <= 'z')

/* The prefix prepended by GCC to an identifier represnting the
anonymous namespace.  */
#define ANONYMOUS_NAMESPACE_PREFIX "_GLOBAL_"
#define ANONYMOUS_NAMESPACE_PREFIX_LEN \
(sizeof (ANONYMOUS_NAMESPACE_PREFIX) - 1)

/* Information we keep for the standard substitutions.  */

struct d_standard_sub_info
{
/* The code for this substitution.  */
char code;
/* The simple string it expands to.  */
const char *simple_expansion;
/* The length of the simple expansion.  */
int simple_len;
/* The results of a full, verbose, expansion.  This is used when
    qualifying a constructor/destructor, or when in verbose mode.  */
const char *full_expansion;
/* The length of the full expansion.  */
int full_len;
/* What to set the last_name field of d_info to; nullptr if we should
    not set it.  This is only relevant when qualifying a
    constructor/destructor.  */
const char *set_last_name;
/* The length of set_last_name.  */
int set_last_name_len;
};

/* Accessors for subtrees of struct demangle_component.  */

#define d_left(dc) ((dc)->u.s_binary.left)
#define d_right(dc) ((dc)->u.s_binary.right)

/* A list of templates.  This is used while printing.  */

struct d_print_template
{
/* Next template on the list.  */
struct d_print_template *next;
/* This template.  */
const struct demangle_component *template_decl;
};

/* A list of type modifiers.  This is used while printing.  */

struct d_print_mod
{
/* Next modifier on the list.  These are in the reverse of the order
    in which they appeared in the mangled string.  */
struct d_print_mod *next;
/* The modifier.  */
struct demangle_component *mod;
/* Whether this modifier was printed.  */
int printed;
/* The list of templates which applies to this modifier.  */
struct d_print_template *templates;
};

/* We use these structures to hold information during printing.  */

struct d_growable_string
{
/* Buffer holding the result.  */
char *buf;
/* Current length of data in buffer.  */
size_t len;
/* Allocated size of buffer.  */
size_t alc;
/* Set to 1 if we had a memory allocation failure.  */
int allocation_failure;
};

/* Stack of components, innermost first, used to avoid loops.  */

struct d_component_stack
{
/* This component.  */
const struct demangle_component *dc;
/* This component's parent.  */
const struct d_component_stack *parent;
};

/* A demangle component and some scope captured when it was first
traversed.  */

struct d_saved_scope
{
/* The component whose scope this is.  */
const struct demangle_component *container;
/* The list of templates, if any, that was current when this
    scope was captured.  */
struct d_print_template *templates;
};

/* Checkpoint structure to allow backtracking.  This holds copies
of the fields of struct d_info that need to be restored
if a trial parse needs to be backtracked over.  */

struct d_info_checkpoint
{
const char *n;
int next_comp;
int next_sub;
int expansion;
};

/* Maximum number of times d_print_comp may be called recursively.  */
#define MAX_RECURSION_COUNT 1024

enum { D_PRINT_BUFFER_LENGTH = 256 };
struct d_print_info
{
/* Fixed-length allocated buffer for demangled data, flushed to the
    callback with a NUL termination once full.  */
char buf[D_PRINT_BUFFER_LENGTH];
/* Current length of data in buffer.  */
size_t len;
/* The last character printed, saved individually so that it survives
    any buffer flush.  */
char last_char;
/* Callback function to handle demangled buffer flush.  */
demangle_callbackref callback;
/* Opaque callback argument.  */
void *opaque;
/* The current list of templates, if any.  */
struct d_print_template *templates;
/* The current list of modifiers (e.g., pointer, reference, etc.),
    if any.  */
struct d_print_mod *modifiers;
/* Set to 1 if we saw a demangling error.  */
int demangle_failure;
/* Number of times d_print_comp was recursively called.  Should not
    be bigger than MAX_RECURSION_COUNT.  */
int recursion;
/* 1 more than the number of explicit template parms of a lambda.  Template
    parm references >= are actually 'auto'.  */
int lambda_tpl_parms;
/* The current index into any template argument packs we are using
    for printing, or -1 to print the whole pack.  */
int pack_index;
/* Number of d_print_flush calls so far.  */
unsigned long int flush_count;
/* Stack of components, innermost first, used to avoid loops.  */
const struct d_component_stack *component_stack;
/* Array of saved scopes for evaluating substitutions.  */
struct d_saved_scope *saved_scopes;
/* Index of the next unused saved scope in the above array.  */
int next_saved_scope;
/* Number of saved scopes in the above array.  */
int num_saved_scopes;
/* Array of templates for saving into scopes.  */
struct d_print_template *copy_templates;
/* Index of the next unused copy template in the above array.  */
int next_copy_template;
/* Number of copy templates in the above array.  */
int num_copy_templates;
/* The nearest enclosing template, if any.  */
const struct demangle_component *current_template;
};

#ifdef CP_DEMANGLE_DEBUG
static void d_dump (struct demangle_component *, int);
#endif

static struct demangle_component *
d_make_empty (struct d_info *);

static struct demangle_component *
d_make_comp (struct d_info *, enum demangle_component_type,
            struct demangle_component *,
            struct demangle_component *);

static struct demangle_component *
d_make_name (struct d_info *, const char *, int);

static struct demangle_component *
d_make_demangle_mangled_name (struct d_info *, const char *);

static struct demangle_component *
d_make_builtin_type (struct d_info *,
                    const struct demangle_builtin_type_info *);

static struct demangle_component *
d_make_operator (struct d_info *,
                const struct demangle_operator_info *);

static struct demangle_component *
d_make_extended_operator (struct d_info *, int,
                        struct demangle_component *);

static struct demangle_component *
d_make_ctor (struct d_info *, enum gnu_v3_ctor_kinds,
            struct demangle_component *);

static struct demangle_component *
d_make_dtor (struct d_info *, enum gnu_v3_dtor_kinds,
            struct demangle_component *);

static struct demangle_component *
d_make_template_param (struct d_info *, int);

static struct demangle_component *
d_make_sub (struct d_info *, const char *, int);

static int
has_return_type (struct demangle_component *);

static int
is_ctor_dtor_or_conversion (struct demangle_component *);

static struct demangle_component *d_encoding (struct d_info *, int);

static struct demangle_component *d_name (struct d_info *, int substable);

static struct demangle_component *d_nested_name (struct d_info *);

static int d_maybe_module_name (struct d_info *, struct demangle_component **);

static struct demangle_component *d_prefix (struct d_info *, int);

static struct demangle_component *d_unqualified_name (struct d_info *,
    struct demangle_component *scope, struct demangle_component *module);

static struct demangle_component *d_source_name (struct d_info *);

static int d_number (struct d_info *);

static struct demangle_component *d_identifier (struct d_info *, int);

static struct demangle_component *d_operator_name (struct d_info *);

static struct demangle_component *d_special_name (struct d_info *);

static struct demangle_component *d_parmlist (struct d_info *);

static int d_call_offset (struct d_info *, int);

static struct demangle_component *d_ctor_dtor_name (struct d_info *);

static struct demangle_component **
d_cv_qualifiers (struct d_info *, struct demangle_component **, int);

static struct demangle_component *
d_ref_qualifier (struct d_info *, struct demangle_component *);

static struct demangle_component *
d_function_type (struct d_info *);

static struct demangle_component *
d_bare_function_type (struct d_info *, int);

static struct demangle_component *
d_class_enum_type (struct d_info *, int);

static struct demangle_component *d_array_type (struct d_info *);

static struct demangle_component *d_vector_type (struct d_info *);

static struct demangle_component *
d_pointer_to_member_type (struct d_info *);

static struct demangle_component *
d_template_param (struct d_info *);

static struct demangle_component *d_template_args (struct d_info *);
static struct demangle_component *d_template_args_1 (struct d_info *);

static struct demangle_component *
d_template_arg (struct d_info *);

static struct demangle_component *d_expression (struct d_info *);

static struct demangle_component *d_expr_primary (struct d_info *);

static struct demangle_component *d_local_name (struct d_info *);

static int d_discriminator (struct d_info *);

static struct demangle_component *d_template_parm (struct d_info *, int *bad);

static struct demangle_component *d_template_head (struct d_info *, int *bad);

static struct demangle_component *d_lambda (struct d_info *);

static struct demangle_component *d_unnamed_type (struct d_info *);

static struct demangle_component *
d_clone_suffix (struct d_info *, struct demangle_component *);

static int
d_add_substitution (struct d_info *, struct demangle_component *);

static struct demangle_component *d_substitution (struct d_info *, int);

static void d_checkpoint (struct d_info *, struct d_info_checkpoint *);

static void d_backtrack (struct d_info *, struct d_info_checkpoint *);

static void d_growable_string_init (struct d_growable_string *, size_t);

static inline void
d_growable_string_resize (struct d_growable_string *, size_t);

static inline void
d_growable_string_append_buffer (struct d_growable_string *,
                                const char *, size_t);
static void
d_growable_string_callback_adapter (const char *, size_t, void *);

static void
d_print_init (struct d_print_info *, demangle_callbackref, void *,
        struct demangle_component *);

static inline void d_print_error (struct d_print_info *);

static inline int d_print_saw_error (struct d_print_info *);

static inline void d_print_flush (struct d_print_info *);

static inline void d_append_char (struct d_print_info *, char);

static inline void d_append_buffer (struct d_print_info *,
                                    const char *, size_t);

static inline void d_append_string (struct d_print_info *, const char *);

static inline char d_last_char (struct d_print_info *);

static void
d_print_comp (struct d_print_info *, int, struct demangle_component *);

static void
d_print_java_identifier (struct d_print_info *, const char *, int);

static void
d_print_mod_list (struct d_print_info *, int, struct d_print_mod *, int);

static void
d_print_mod (struct d_print_info *, int, struct demangle_component *);

static void
d_print_function_type (struct d_print_info *, int,
                    struct demangle_component *,
                    struct d_print_mod *);

static void
d_print_array_type (struct d_print_info *, int,
                    struct demangle_component *,
                    struct d_print_mod *);

static void
d_print_expr_op (struct d_print_info *, int, struct demangle_component *);

static void d_print_cast (struct d_print_info *, int,
            struct demangle_component *);
static void d_print_conversion (struct d_print_info *, int,
                struct demangle_component *);

static int d_demangle_callback (const char *, int,
                                demangle_callbackref, void *);
static char *d_demangle (const char *, int, size_t *);

#define FNQUAL_COMPONENT_CASE				\
    case DEMANGLE_COMPONENT_RESTRICT_THIS:		\
    case DEMANGLE_COMPONENT_VOLATILE_THIS:		\
    case DEMANGLE_COMPONENT_CONST_THIS:			\
    case DEMANGLE_COMPONENT_REFERENCE_THIS:		\
    case DEMANGLE_COMPONENT_RVALUE_REFERENCE_THIS:	\
    case DEMANGLE_COMPONENT_XOBJ_MEMBER_FUNCTION:	\
    case DEMANGLE_COMPONENT_TRANSACTION_SAFE:		\
    case DEMANGLE_COMPONENT_NOEXCEPT:			\
    case DEMANGLE_COMPONENT_THROW_SPEC

/* True iff TYPE is a demangling component representing a
function-type-qualifier.  */

static int
is_fnqual_component_type (enum demangle_component_type type)
{
switch (type)
    {
    FNQUAL_COMPONENT_CASE:
    return 1;
    default:
    break;
    }
return 0;
}


/* Fill in a DEMANGLE_COMPONENT_NAME.  */

static
int
cplus_demangle_fill_name (struct demangle_component *p, const char *s, int len)
{
if (p == nullptr || s == nullptr || len <= 0)
    return 0;
p->d_printing = 0;
p->d_counting = 0;
p->type = DEMANGLE_COMPONENT_NAME;
p->u.s_name.s = s;
p->u.s_name.len = len;
return 1;
}

/* Fill in a DEMANGLE_COMPONENT_EXTENDED_OPERATOR.  */

static
int
cplus_demangle_fill_extended_operator (struct demangle_component *p, int args,
                                    struct demangle_component *name)
{
if (p == nullptr || args < 0 || name == nullptr)
    return 0;
p->d_printing = 0;
p->d_counting = 0;
p->type = DEMANGLE_COMPONENT_EXTENDED_OPERATOR;
p->u.s_extended_operator.args = args;
p->u.s_extended_operator.name = name;
return 1;
}

/* Fill in a DEMANGLE_COMPONENT_CTOR.  */

static
int
cplus_demangle_fill_ctor (struct demangle_component *p,
                        enum gnu_v3_ctor_kinds kind,
                        struct demangle_component *name)
{
if (p == nullptr
    || name == nullptr
    || (int) kind < gnu_v3_complete_object_ctor
    || (int) kind > gnu_v3_object_ctor_group)
    return 0;
p->d_printing = 0;
p->d_counting = 0;
p->type = DEMANGLE_COMPONENT_CTOR;
p->u.s_ctor.kind = kind;
p->u.s_ctor.name = name;
return 1;
}

/* Fill in a DEMANGLE_COMPONENT_DTOR.  */

static
int
cplus_demangle_fill_dtor (struct demangle_component *p,
                        enum gnu_v3_dtor_kinds kind,
                        struct demangle_component *name)
{
if (p == nullptr
    || name == nullptr
    || (int) kind < gnu_v3_deleting_dtor
    || (int) kind > gnu_v3_object_dtor_group)
    return 0;
p->d_printing = 0;
p->d_counting = 0;
p->type = DEMANGLE_COMPONENT_DTOR;
p->u.s_dtor.kind = kind;
p->u.s_dtor.name = name;
return 1;
}

/* Add a new component.  */

static struct demangle_component *
d_make_empty (struct d_info *di)
{
struct demangle_component *p;

if (di->next_comp >= di->num_comps)
    return nullptr;
p = &di->comps[di->next_comp];
p->d_printing = 0;
p->d_counting = 0;
++di->next_comp;
return p;
}

/* Add a new generic component.  */

static struct demangle_component *
d_make_comp (struct d_info *di, enum demangle_component_type type,
            struct demangle_component *left,
            struct demangle_component *right)
{
struct demangle_component *p;

/* We check for errors here.  A typical error would be a nullptr return
    from a subroutine.  We catch those here, and return nullptr
    upward.  */
switch (type)
    {
    /* These types require two parameters.  */
    case DEMANGLE_COMPONENT_QUAL_NAME:
    case DEMANGLE_COMPONENT_LOCAL_NAME:
    case DEMANGLE_COMPONENT_TYPED_NAME:
    case DEMANGLE_COMPONENT_TAGGED_NAME:
    case DEMANGLE_COMPONENT_TEMPLATE:
    case DEMANGLE_COMPONENT_CONSTRUCTION_VTABLE:
    case DEMANGLE_COMPONENT_VENDOR_TYPE_QUAL:
    case DEMANGLE_COMPONENT_PTRMEM_TYPE:
    case DEMANGLE_COMPONENT_UNARY:
    case DEMANGLE_COMPONENT_BINARY:
    case DEMANGLE_COMPONENT_BINARY_ARGS:
    case DEMANGLE_COMPONENT_TRINARY:
    case DEMANGLE_COMPONENT_TRINARY_ARG1:
    case DEMANGLE_COMPONENT_LITERAL:
    case DEMANGLE_COMPONENT_LITERAL_NEG:
    case DEMANGLE_COMPONENT_VENDOR_EXPR:
    case DEMANGLE_COMPONENT_COMPOUND_NAME:
    case DEMANGLE_COMPONENT_VECTOR_TYPE:
    case DEMANGLE_COMPONENT_CLONE:
    case DEMANGLE_COMPONENT_MODULE_ENTITY:
    case DEMANGLE_COMPONENT_CONSTRAINTS:
    if (left == nullptr || right == nullptr)
    return nullptr;
    break;

    /* These types only require one parameter.  */
    case DEMANGLE_COMPONENT_VTABLE:
    case DEMANGLE_COMPONENT_VTT:
    case DEMANGLE_COMPONENT_TYPEINFO:
    case DEMANGLE_COMPONENT_TYPEINFO_NAME:
    case DEMANGLE_COMPONENT_TYPEINFO_FN:
    case DEMANGLE_COMPONENT_THUNK:
    case DEMANGLE_COMPONENT_VIRTUAL_THUNK:
    case DEMANGLE_COMPONENT_COVARIANT_THUNK:
    case DEMANGLE_COMPONENT_JAVA_CLASS:
    case DEMANGLE_COMPONENT_GUARD:
    case DEMANGLE_COMPONENT_TLS_INIT:
    case DEMANGLE_COMPONENT_TLS_WRAPPER:
    case DEMANGLE_COMPONENT_REFTEMP:
    case DEMANGLE_COMPONENT_HIDDEN_ALIAS:
    case DEMANGLE_COMPONENT_TRANSACTION_CLONE:
    case DEMANGLE_COMPONENT_NONTRANSACTION_CLONE:
    case DEMANGLE_COMPONENT_POINTER:
    case DEMANGLE_COMPONENT_REFERENCE:
    case DEMANGLE_COMPONENT_RVALUE_REFERENCE:
    case DEMANGLE_COMPONENT_COMPLEX:
    case DEMANGLE_COMPONENT_IMAGINARY:
    case DEMANGLE_COMPONENT_VENDOR_TYPE:
    case DEMANGLE_COMPONENT_CAST:
    case DEMANGLE_COMPONENT_CONVERSION:
    case DEMANGLE_COMPONENT_JAVA_RESOURCE:
    case DEMANGLE_COMPONENT_DECLTYPE:
    case DEMANGLE_COMPONENT_PACK_EXPANSION:
    case DEMANGLE_COMPONENT_GLOBAL_CONSTRUCTORS:
    case DEMANGLE_COMPONENT_GLOBAL_DESTRUCTORS:
    case DEMANGLE_COMPONENT_NULLARY:
    case DEMANGLE_COMPONENT_TRINARY_ARG2:
    case DEMANGLE_COMPONENT_TPARM_OBJ:
    case DEMANGLE_COMPONENT_STRUCTURED_BINDING:
    case DEMANGLE_COMPONENT_MODULE_INIT:
    case DEMANGLE_COMPONENT_TEMPLATE_HEAD:
    case DEMANGLE_COMPONENT_TEMPLATE_NON_TYPE_PARM:
    case DEMANGLE_COMPONENT_TEMPLATE_TEMPLATE_PARM:
    case DEMANGLE_COMPONENT_TEMPLATE_PACK_PARM:
    case DEMANGLE_COMPONENT_FRIEND:
    if (left == nullptr)
    return nullptr;
    break;

    /* This needs a right parameter, but the left parameter can be
    empty.  */
    case DEMANGLE_COMPONENT_ARRAY_TYPE:
    case DEMANGLE_COMPONENT_INITIALIZER_LIST:
    case DEMANGLE_COMPONENT_MODULE_NAME:
    case DEMANGLE_COMPONENT_MODULE_PARTITION:
    if (right == nullptr)
    return nullptr;
    break;

    /* These are allowed to have no parameters--in some cases they
    will be filled in later.  */
    case DEMANGLE_COMPONENT_FUNCTION_TYPE:
    case DEMANGLE_COMPONENT_RESTRICT:
    case DEMANGLE_COMPONENT_VOLATILE:
    case DEMANGLE_COMPONENT_CONST:
    case DEMANGLE_COMPONENT_ARGLIST:
    case DEMANGLE_COMPONENT_TEMPLATE_ARGLIST:
    case DEMANGLE_COMPONENT_TEMPLATE_TYPE_PARM:
    FNQUAL_COMPONENT_CASE:
    break;

    /* Other types should not be seen here.  */
    default:
    return nullptr;
    }

p = d_make_empty (di);
if (p != nullptr)
    {
    p->type = type;
    p->u.s_binary.left = left;
    p->u.s_binary.right = right;
    }
return p;
}

/* Add a new demangle mangled name component.  */

static struct demangle_component *
d_make_demangle_mangled_name (struct d_info *di, const char *s)
{
if (d_peek_char (di) != '_' || d_peek_next_char (di) != 'Z')
    return d_make_name (di, s, std::strlen (s));
d_advance (di, 2);
return d_encoding (di, 0);
}

/* Add a new name component.  */

static struct demangle_component *
d_make_name (struct d_info *di, const char *s, int len)
{
struct demangle_component *p;

p = d_make_empty (di);
if (! cplus_demangle_fill_name (p, s, len))
    return nullptr;
return p;
}

/* Add a new builtin type component.  */

static struct demangle_component *
d_make_builtin_type (struct d_info *di,
                    const struct demangle_builtin_type_info *type)
{
struct demangle_component *p;

if (type == nullptr)
    return nullptr;
p = d_make_empty (di);
if (p != nullptr)
    {
    p->type = DEMANGLE_COMPONENT_BUILTIN_TYPE;
    p->u.s_builtin.type = type;
    }
return p;
}

/* Add a new extended builtin type component.  */

static struct demangle_component *
d_make_extended_builtin_type (struct d_info *di,
                const struct demangle_builtin_type_info *type,
                short arg, char suffix)
{
struct demangle_component *p;

if (type == nullptr)
    return nullptr;
p = d_make_empty (di);
if (p != nullptr)
    {
    p->type = DEMANGLE_COMPONENT_EXTENDED_BUILTIN_TYPE;
    p->u.s_extended_builtin.type = type;
    p->u.s_extended_builtin.arg = arg;
    p->u.s_extended_builtin.suffix = suffix;
    }
return p;
}

/* Add a new operator component.  */

static struct demangle_component *
d_make_operator (struct d_info *di, const struct demangle_operator_info *op)
{
struct demangle_component *p;

p = d_make_empty (di);
if (p != nullptr)
    {
    p->type = DEMANGLE_COMPONENT_OPERATOR;
    p->u.s_operator.op = op;
    }
return p;
}

/* Add a new extended operator component.  */

static struct demangle_component *
d_make_extended_operator (struct d_info *di, int args,
                        struct demangle_component *name)
{
struct demangle_component *p;

p = d_make_empty (di);
if (! cplus_demangle_fill_extended_operator (p, args, name))
    return nullptr;
return p;
}

static struct demangle_component *
d_make_default_arg (struct d_info *di, int num,
            struct demangle_component *sub)
{
struct demangle_component *p = d_make_empty (di);
if (p)
    {
    p->type = DEMANGLE_COMPONENT_DEFAULT_ARG;
    p->u.s_unary_num.num = num;
    p->u.s_unary_num.sub = sub;
    }
return p;
}

/* Add a new constructor component.  */

static struct demangle_component *
d_make_ctor (struct d_info *di, enum gnu_v3_ctor_kinds kind,
            struct demangle_component *name)
{
struct demangle_component *p;

p = d_make_empty (di);
if (! cplus_demangle_fill_ctor (p, kind, name))
    return nullptr;
return p;
}

/* Add a new destructor component.  */

static struct demangle_component *
d_make_dtor (struct d_info *di, enum gnu_v3_dtor_kinds kind,
            struct demangle_component *name)
{
struct demangle_component *p;

p = d_make_empty (di);
if (! cplus_demangle_fill_dtor (p, kind, name))
    return nullptr;
return p;
}

/* Add a new template parameter.  */

static struct demangle_component *
d_make_template_param (struct d_info *di, int i)
{
struct demangle_component *p;

p = d_make_empty (di);
if (p != nullptr)
    {
    p->type = DEMANGLE_COMPONENT_TEMPLATE_PARAM;
    p->u.s_number.number = i;
    }
return p;
}

/* Add a new function parameter.  */

static struct demangle_component *
d_make_function_param (struct d_info *di, int i)
{
struct demangle_component *p;

p = d_make_empty (di);
if (p != nullptr)
    {
    p->type = DEMANGLE_COMPONENT_FUNCTION_PARAM;
    p->u.s_number.number = i;
    }
return p;
}

/* Add a new standard substitution component.  */

static struct demangle_component *
d_make_sub (struct d_info *di, const char *name, int len)
{
struct demangle_component *p;

p = d_make_empty (di);
if (p != nullptr)
    {
    p->type = DEMANGLE_COMPONENT_SUB_STD;
    p->u.s_string.string = name;
    p->u.s_string.len = len;
    }
return p;
}

/* <mangled-name> ::= _Z <encoding> [<clone-suffix>]*

TOP_LEVEL is non-zero when called at the top level.  */

static
struct demangle_component *
cplus_demangle_mangled_name (struct d_info *di, int top_level)
{
struct demangle_component *p;

if (! d_check_char (di, '_')
    /* Allow missing _ if not at toplevel to work around a
    bug in G++ abi-version=2 mangling; see the comment in
    write_template_arg.  */
    && top_level)
    return nullptr;
if (! d_check_char (di, 'Z'))
    return nullptr;
p = d_encoding (di, top_level);

/* If at top level and parsing parameters, check for a clone
    suffix.  */
if (top_level && (di->options & DMGL_PARAMS) != 0)
    while (d_peek_char (di) == '.'
    && (IS_LOWER (d_peek_next_char (di))
        || d_peek_next_char (di) == '_'
        || IS_DIGIT (d_peek_next_char (di))))
    p = d_clone_suffix (di, p);

return p;
}

/* Return whether a function should have a return type.  The argument
is the function name, which may be qualified in various ways.  The
rules are that template functions have return types with some
exceptions, function types which are not part of a function name
mangling have return types with some exceptions, and non-template
function names do not have return types.  The exceptions are that
constructors, destructors, and conversion operators do not have
return types.  */

static int
has_return_type (struct demangle_component *dc)
{
if (dc == nullptr)
    return 0;
switch (dc->type)
    {
    default:
    return 0;
    case DEMANGLE_COMPONENT_LOCAL_NAME:
    return has_return_type (d_right (dc));
    case DEMANGLE_COMPONENT_TEMPLATE:
    return ! is_ctor_dtor_or_conversion (d_left (dc));
    FNQUAL_COMPONENT_CASE:
    return has_return_type (d_left (dc));
    }
}

/* Return whether a name is a constructor, a destructor, or a
conversion operator.  */

static int
is_ctor_dtor_or_conversion (struct demangle_component *dc)
{
if (dc == nullptr)
    return 0;
switch (dc->type)
    {
    default:
    return 0;
    case DEMANGLE_COMPONENT_QUAL_NAME:
    case DEMANGLE_COMPONENT_LOCAL_NAME:
    return is_ctor_dtor_or_conversion (d_right (dc));
    case DEMANGLE_COMPONENT_CTOR:
    case DEMANGLE_COMPONENT_DTOR:
    case DEMANGLE_COMPONENT_CONVERSION:
    return 1;
    }
}

/* [ Q <constraint-expression> ] */

static struct demangle_component *
d_maybe_constraints (struct d_info *di, struct demangle_component *dc)
{
if (d_peek_char (di) == 'Q')
    {
    d_advance (di, 1);
    struct demangle_component *expr = d_expression (di);
    if (expr == nullptr)
    return nullptr;
    dc = d_make_comp (di, DEMANGLE_COMPONENT_CONSTRAINTS, dc, expr);
    }
return dc;
}

/* <encoding> ::= <(function) name> <bare-function-type>
            ::= <(data) name>
            ::= <special-name>

TOP_LEVEL is non-zero when called at the top level, in which case
if DMGL_PARAMS is not set we do not demangle the function
parameters.  We only set this at the top level, because otherwise
we would not correctly demangle names in local scopes.  */

static struct demangle_component *
d_encoding (struct d_info *di, int top_level)
{
char peek = d_peek_char (di);
struct demangle_component *dc;

if (peek == 'G' || peek == 'T')
    dc = d_special_name (di);
else
    {
    dc = d_name (di, 0);

    if (!dc)
    /* Failed already.  */;
    else if (top_level && (di->options & DMGL_PARAMS) == 0)
    {
    /* Strip off any initial CV-qualifiers, as they really apply
        to the `this' parameter, and they were not output by the
        v2 demangler without DMGL_PARAMS.  */
    while (is_fnqual_component_type (dc->type))
        dc = d_left (dc);

    /* If the top level is a DEMANGLE_COMPONENT_LOCAL_NAME, then
        there may be function-qualifiers on its right argument which
        really apply here; this happens when parsing a class
        which is local to a function.  */
    if (dc->type == DEMANGLE_COMPONENT_LOCAL_NAME)
        {
        while (d_right (dc) != nullptr
            && is_fnqual_component_type (d_right (dc)->type))
        d_right (dc) = d_left (d_right (dc));

        if (d_right (dc) == nullptr)
        dc = nullptr;
        }
    }
    else
    {
    peek = d_peek_char (di);
    if (peek != '\0' && peek != 'E')
        {
        struct demangle_component *ftype;

        ftype = d_bare_function_type (di, has_return_type (dc));
        if (!ftype)
        return nullptr;

        /* If this is a non-top-level local-name, clear the
        return type, so it doesn't confuse the user by
        being confused with the return type of whaever
        this is nested within.  */
        if (!top_level && dc->type == DEMANGLE_COMPONENT_LOCAL_NAME
        && ftype->type == DEMANGLE_COMPONENT_FUNCTION_TYPE)
        d_left (ftype) = nullptr;

        ftype = d_maybe_constraints (di, ftype);

        dc = d_make_comp (di, DEMANGLE_COMPONENT_TYPED_NAME,
                dc, ftype);
        }
    }
    }

return dc;
}

/* <tagged-name> ::= <name> B <source-name> */

static struct demangle_component *
d_abi_tags (struct d_info *di, struct demangle_component *dc)
{
struct demangle_component *hold_last_name;
char peek;

/* Preserve the last name, so the ABI tag doesn't clobber it.  */
hold_last_name = di->last_name;

while (peek = d_peek_char (di),
    peek == 'B')
    {
    struct demangle_component *tag;
    d_advance (di, 1);
    tag = d_source_name (di);
    dc = d_make_comp (di, DEMANGLE_COMPONENT_TAGGED_NAME, dc, tag);
    }

di->last_name = hold_last_name;

return dc;
}

/* <name> ::= <nested-name>
        ::= <unscoped-name>
        ::= <unscoped-template-name> <template-args>
        ::= <local-name>

<unscoped-name> ::= <unqualified-name>
                ::= St <unqualified-name>

<unscoped-template-name> ::= <unscoped-name>
                            ::= <substitution>
*/

static struct demangle_component *
d_name (struct d_info *di, int substable)
{
char peek = d_peek_char (di);
struct demangle_component *dc = nullptr;
struct demangle_component *module = nullptr;
int subst = 0;

switch (peek)
    {
    case 'N':
    dc = d_nested_name (di);
    break;

    case 'Z':
    dc = d_local_name (di);
    break;

    case 'U':
    dc = d_unqualified_name (di, nullptr, nullptr);
    break;

    case 'S':
    {
    if (d_peek_next_char (di) == 't')
    {
        d_advance (di, 2);
        dc = d_make_name (di, "std", 3);
        di->expansion += 3;
    }

    if (d_peek_char (di) == 'S')
    {
        module = d_substitution (di, 0);
        if (!module)
        return nullptr;
        if (!(module->type == DEMANGLE_COMPONENT_MODULE_NAME
        || module->type == DEMANGLE_COMPONENT_MODULE_PARTITION))
        {
        if (dc)
        return nullptr;
        subst = 1;
        dc = module;
        module = nullptr;
        }
    }
    }
    /* FALLTHROUGH */

    case 'L':
    default:
    if (!subst)
    dc = d_unqualified_name (di, dc, module);
    if (d_peek_char (di) == 'I')
    {
    /* This is <template-args>, which means that we just saw
        <unscoped-template-name>, which is a substitution
        candidate.  */
    if (!subst && !d_add_substitution (di, dc))
        return nullptr;
    dc = d_make_comp (di, DEMANGLE_COMPONENT_TEMPLATE, dc,
                d_template_args (di));
    subst = 0;
    }
    break;
    }
if (substable && !subst && !d_add_substitution (di, dc))
    return nullptr;
return dc;
}

/* <nested-name> ::= N [<CV-qualifiers>] [<ref-qualifier>] <prefix> <unqualified-name> E
                ::= N [<CV-qualifiers>] [<ref-qualifier>] <template-prefix> <template-args> E
                ::= N H <prefix> <unqualified-name> E
                ::= N H <template-prefix> <template-args> E
*/

static struct demangle_component *
d_nested_name (struct d_info *di)
{
struct demangle_component *ret;
struct demangle_component **pret;
struct demangle_component *rqual;

if (! d_check_char (di, 'N'))
    return nullptr;

if (d_peek_char (di) == 'H')
    {
    d_advance (di, 1);
    di->expansion += sizeof "this";
    pret = &ret;
    rqual = d_make_comp (di, DEMANGLE_COMPONENT_XOBJ_MEMBER_FUNCTION,
            nullptr, nullptr);
    }
else
    {
    pret = d_cv_qualifiers (di, &ret, 1);
    if (pret == nullptr)
    return nullptr;

    /* Parse the ref-qualifier now and then attach it
    once we have something to attach it to.  */
    rqual = d_ref_qualifier (di, nullptr);
    }

*pret = d_prefix (di, 1);
if (*pret == nullptr)
    return nullptr;

if (rqual)
    {
    d_left (rqual) = ret;
    ret = rqual;
    }

if (! d_check_char (di, 'E'))
    return nullptr;

return ret;
}

/* <prefix> ::= <prefix> <unqualified-name>
            ::= <template-prefix> <template-args>
            ::= <template-param>
            ::= <decltype>
            ::=
            ::= <substitution>

<template-prefix> ::= <prefix> <(template) unqualified-name>
                    ::= <template-param>
                    ::= <substitution>

SUBST is true if we should add substitutions (as normal), false
if not (in an unresolved-name).  */

static struct demangle_component *
d_prefix (struct d_info *di, int substable)
{
struct demangle_component *ret = nullptr;

for (;;)
    {
    char peek = d_peek_char (di);

    /* The older code accepts a <local-name> here, but I don't see
    that in the grammar.  The older code does not accept a
    <template-param> here.  */

    if (peek == 'D'
    && (d_peek_next_char (di) == 'T'
        || d_peek_next_char (di) == 't'))
    {
    /* Decltype.  */
    if (ret)
        return nullptr;
    ret = cplus_demangle_type (di);
    }
    else if (peek == 'I')
    {
    if (ret == nullptr)
        return nullptr;
    struct demangle_component *dc = d_template_args (di);
    if (!dc)
        return nullptr;
    ret = d_make_comp (di, DEMANGLE_COMPONENT_TEMPLATE, ret, dc);
    }
    else if (peek == 'T')
    {
    if (ret)
        return nullptr;
    ret = d_template_param (di);
    }
    else if (peek == 'M')
    {
    /* Initializer scope for a lambda.  We already added it as a
        substitution candidate, don't do that again.  */
    d_advance (di, 1);
    continue;
    }
    else
    {
    struct demangle_component *module = nullptr;
    if (peek == 'S')
        {
        module = d_substitution (di, 1);
        if (!module)
        return nullptr;
        if (!(module->type == DEMANGLE_COMPONENT_MODULE_NAME
            || module->type == DEMANGLE_COMPONENT_MODULE_PARTITION))
        {
        if (ret)
            return nullptr;
        ret = module;
        continue;
        }
        }
    ret = d_unqualified_name (di, ret, module);
    }

    if (!ret)
    break;

    if (d_peek_char (di) == 'E')
    break;

    if (substable && !d_add_substitution (di, ret))
    return nullptr;
    }

return ret;
}

static int
d_maybe_module_name (struct d_info *di, struct demangle_component **name)
{
while (d_peek_char (di) == 'W')
    {
    d_advance (di, 1);
    enum demangle_component_type code = DEMANGLE_COMPONENT_MODULE_NAME;
    if (d_peek_char (di) == 'P')
    {
    code = DEMANGLE_COMPONENT_MODULE_PARTITION;
    d_advance (di, 1);
    }

    *name = d_make_comp (di, code, *name, d_source_name (di));
    if (!*name)
    return 0;
    if (!d_add_substitution (di, *name))
    return 0;
    }
return 1;
}

/* <unqualified-name> ::= [<module-name>] <operator-name> [<abi-tags>]
                    ::= [<module-name>] <ctor-dtor-name> [<abi-tags>]
                    ::= [<module-name>] <source-name> [<abi-tags>]
            ::= [<module-name>] F <source-name> [<abi-tags>]
            ::= [<module-name>] <local-source-name>  [<abi-tags>]
                    ::= [<module-name>] DC <source-name>+ E [<abi-tags>]
    <local-source-name>	::= L <source-name> <discriminator> [<abi-tags>]
*/

static struct demangle_component *
d_unqualified_name (struct d_info *di, struct demangle_component *scope,
            struct demangle_component *module)
{
struct demangle_component *ret;
char peek;
int member_like_friend = 0;

if (!d_maybe_module_name (di, &module))
    return nullptr;

peek = d_peek_char (di);
if (peek == 'F')
    {
    member_like_friend = 1;
    d_advance (di, 1);
    peek = d_peek_char (di);
    }
if (IS_DIGIT (peek))
    ret = d_source_name (di);
else if (IS_LOWER (peek))
    {
    int was_expr = di->is_expression;
    if (peek == 'o' && d_peek_next_char (di) == 'n')
    {
    d_advance (di, 2);
    /* Treat cv as naming a conversion operator.  */
    di->is_expression = 0;
    }
    ret = d_operator_name (di);
    di->is_expression = was_expr;
    if (ret != nullptr && ret->type == DEMANGLE_COMPONENT_OPERATOR)
    {
    di->expansion += sizeof "operator" + ret->u.s_operator.op->len - 2;
    if (!std::strcmp (ret->u.s_operator.op->code, "li"))
        ret = d_make_comp (di, DEMANGLE_COMPONENT_UNARY, ret,
                d_source_name (di));
    }
    }
else if (peek == 'D' && d_peek_next_char (di) == 'C')
    {
    // structured binding
    d_advance (di, 2);
    struct demangle_component *prev = nullptr;
    do
    {
    struct demangle_component *next = 
        d_make_comp (di, DEMANGLE_COMPONENT_STRUCTURED_BINDING,
            d_source_name (di), nullptr);
    if (prev)
        d_right (prev) = next;
    else
        ret = next;
    prev = next;
    }
    while (prev && d_peek_char (di) != 'E');
    if (prev)
    d_advance (di, 1);
    else
    ret = nullptr;
    }
else if (peek == 'C' || peek == 'D')
    ret = d_ctor_dtor_name (di);
else if (peek == 'L')
    {
    d_advance (di, 1);

    ret = d_source_name (di);
    if (ret == nullptr)
    return nullptr;
    if (! d_discriminator (di))
    return nullptr;
    }
else if (peek == 'U')
    {
    switch (d_peek_next_char (di))
    {
    case 'l':
    ret = d_lambda (di);
    break;
    case 't':
    ret = d_unnamed_type (di);
    break;
    default:
    return nullptr;
    }
    }
else
    return nullptr;

if (module)
    ret = d_make_comp (di, DEMANGLE_COMPONENT_MODULE_ENTITY, ret, module);
if (d_peek_char (di) == 'B')
    ret = d_abi_tags (di, ret);
if (member_like_friend)
    ret = d_make_comp (di, DEMANGLE_COMPONENT_FRIEND, ret, nullptr);
if (scope)
    ret = d_make_comp (di, DEMANGLE_COMPONENT_QUAL_NAME, scope, ret);

return ret;
}

/* <source-name> ::= <(positive length) number> <identifier>  */

static struct demangle_component *
d_source_name (struct d_info *di)
{
int len;
struct demangle_component *ret;

len = d_number (di);
if (len <= 0)
    return nullptr;
ret = d_identifier (di, len);
di->last_name = ret;
return ret;
}

/* number ::= [n] <(non-negative decimal integer)>  */

static int
d_number (struct d_info *di)
{
int negative;
char peek;
int ret;

negative = 0;
peek = d_peek_char (di);
if (peek == 'n')
    {
    negative = 1;
    d_advance (di, 1);
    peek = d_peek_char (di);
    }

ret = 0;
while (1)
    {
    if (! IS_DIGIT (peek))
    {
    if (negative)
        ret = - ret;
    return ret;
    }
    if (ret > ((INT_MAX - (peek - '0')) / 10))
        return -1;
    ret = ret * 10 + (peek - '0');
    d_advance (di, 1);
    peek = d_peek_char (di);
    }
}

/* Like d_number, but returns a demangle_component.  */

static struct demangle_component *
d_number_component (struct d_info *di)
{
struct demangle_component *ret = d_make_empty (di);
if (ret)
    {
    ret->type = DEMANGLE_COMPONENT_NUMBER;
    ret->u.s_number.number = d_number (di);
    }
return ret;
}

/* identifier ::= <(unqualified source code identifier)>  */

static struct demangle_component *
d_identifier (struct d_info *di, int len)
{
const char *name;

name = d_str (di);

if (di->send - name < len)
    return nullptr;

d_advance (di, len);

/* A Java mangled name may have a trailing '$' if it is a C++
    keyword.  This '$' is not included in the length count.  We just
    ignore the '$'.  */
if ((di->options & DMGL_JAVA) != 0
    && d_peek_char (di) == '$')
    d_advance (di, 1);

/* Look for something which looks like a gcc encoding of an
    anonymous namespace, and replace it with a more user friendly
    name.  */
if (len >= (int) ANONYMOUS_NAMESPACE_PREFIX_LEN + 2
    && std::memcmp (name, ANONYMOUS_NAMESPACE_PREFIX,
        ANONYMOUS_NAMESPACE_PREFIX_LEN) == 0)
    {
    const char *s;

    s = name + ANONYMOUS_NAMESPACE_PREFIX_LEN;
    if ((*s == '.' || *s == '_' || *s == '$')
    && s[1] == 'N')
    {
    di->expansion -= len - sizeof "(anonymous namespace)";
    return d_make_name (di, "(anonymous namespace)",
                sizeof "(anonymous namespace)" - 1);
    }
    }

return d_make_name (di, name, len);
}

/* operator_name ::= many different two character encodings.
                ::= cv <type>
                ::= v <digit> <source-name>

This list is sorted for binary search.  */

#define NL(s) s, (sizeof s) - 1

static
const struct demangle_operator_info cplus_demangle_operators[] =
{
{ "aN", NL ("&="),        2 },
{ "aS", NL ("="),         2 },
{ "aa", NL ("&&"),        2 },
{ "ad", NL ("&"),         1 },
{ "an", NL ("&"),         2 },
{ "at", NL ("alignof "),   1 },
{ "aw", NL ("co_await "), 1 },
{ "az", NL ("alignof "),   1 },
{ "cc", NL ("const_cast"), 2 },
{ "cl", NL ("()"),        2 },
{ "cm", NL (","),         2 },
{ "co", NL ("~"),         1 },
{ "dV", NL ("/="),        2 },
{ "dX", NL ("[...]="),     3 }, /* [expr...expr] = expr */
{ "da", NL ("delete[] "), 1 },
{ "dc", NL ("dynamic_cast"), 2 },
{ "de", NL ("*"),         1 },
{ "di", NL ("="),         2 }, /* .name = expr */
{ "dl", NL ("delete "),   1 },
{ "ds", NL (".*"),        2 },
{ "dt", NL ("."),         2 },
{ "dv", NL ("/"),         2 },
{ "dx", NL ("]="),        2 }, /* [expr] = expr */
{ "eO", NL ("^="),        2 },
{ "eo", NL ("^"),         2 },
{ "eq", NL ("=="),        2 },
{ "fL", NL ("..."),       3 },
{ "fR", NL ("..."),       3 },
{ "fl", NL ("..."),       2 },
{ "fr", NL ("..."),       2 },
{ "ge", NL (">="),        2 },
{ "gs", NL ("::"),	    1 },
{ "gt", NL (">"),         2 },
{ "ix", NL ("[]"),        2 },
{ "lS", NL ("<<="),       2 },
{ "le", NL ("<="),        2 },
{ "li", NL ("operator\"\" "), 1 },
{ "ls", NL ("<<"),        2 },
{ "lt", NL ("<"),         2 },
{ "mI", NL ("-="),        2 },
{ "mL", NL ("*="),        2 },
{ "mi", NL ("-"),         2 },
{ "ml", NL ("*"),         2 },
{ "mm", NL ("--"),        1 },
{ "na", NL ("new[]"),     3 },
{ "ne", NL ("!="),        2 },
{ "ng", NL ("-"),         1 },
{ "nt", NL ("!"),         1 },
{ "nw", NL ("new"),       3 },
{ "nx", NL ("noexcept"),  1 },
{ "oR", NL ("|="),        2 },
{ "oo", NL ("||"),        2 },
{ "or", NL ("|"),         2 },
{ "pL", NL ("+="),        2 },
{ "pl", NL ("+"),         2 },
{ "pm", NL ("->*"),       2 },
{ "pp", NL ("++"),        1 },
{ "ps", NL ("+"),         1 },
{ "pt", NL ("->"),        2 },
{ "qu", NL ("?"),         3 },
{ "rM", NL ("%="),        2 },
{ "rS", NL (">>="),       2 },
{ "rc", NL ("reinterpret_cast"), 2 },
{ "rm", NL ("%"),         2 },
{ "rs", NL (">>"),        2 },
{ "sP", NL ("sizeof..."), 1 },
{ "sZ", NL ("sizeof..."), 1 },
{ "sc", NL ("static_cast"), 2 },
{ "ss", NL ("<=>"),       2 },
{ "st", NL ("sizeof "),   1 },
{ "sz", NL ("sizeof "),   1 },
{ "tr", NL ("throw"),     0 },
{ "tw", NL ("throw "),    1 },
{ nullptr, nullptr, 0,          0 }
};

static struct demangle_component *
d_operator_name (struct d_info *di)
{
char c1;
char c2;

c1 = d_next_char (di);
c2 = d_next_char (di);
if (c1 == 'v' && IS_DIGIT (c2))
    return d_make_extended_operator (di, c2 - '0', d_source_name (di));
else if (c1 == 'c' && c2 == 'v')
    {
    struct demangle_component *type;
    int was_conversion = di->is_conversion;
    struct demangle_component *res;

    di->is_conversion = ! di->is_expression;
    type = cplus_demangle_type (di);
    if (di->is_conversion)
    res = d_make_comp (di, DEMANGLE_COMPONENT_CONVERSION, type, nullptr);
    else
    res = d_make_comp (di, DEMANGLE_COMPONENT_CAST, type, nullptr);
    di->is_conversion = was_conversion;
    return res;
    }
else
    {
    /* LOW is the inclusive lower bound.  */
    int low = 0;
    /* HIGH is the exclusive upper bound.  We subtract one to ignore
    the sentinel at the end of the array.  */
    int high = ((sizeof (cplus_demangle_operators)
        / sizeof (cplus_demangle_operators[0]))
        - 1);

    while (1)
    {
    int i;
    const struct demangle_operator_info *p;

    i = low + (high - low) / 2;
    p = cplus_demangle_operators + i;

    if (c1 == p->code[0] && c2 == p->code[1])
        return d_make_operator (di, p);

    if (c1 < p->code[0] || (c1 == p->code[0] && c2 < p->code[1]))
        high = i;
    else
        low = i + 1;
    if (low == high)
        return nullptr;
    }
    }
}

static struct demangle_component *
d_make_character (struct d_info *di, int c)
{
struct demangle_component *p;
p = d_make_empty (di);
if (p != nullptr)
    {
    p->type = DEMANGLE_COMPONENT_CHARACTER;
    p->u.s_character.character = c;
    }
return p;
}

static struct demangle_component *
d_java_resource (struct d_info *di)
{
struct demangle_component *p = nullptr;
struct demangle_component *next = nullptr;
int len, i;
char c;
const char *str;

len = d_number (di);
if (len <= 1)
    return nullptr;

/* Eat the leading '_'.  */
if (d_next_char (di) != '_')
    return nullptr;
len--;

str = d_str (di);
i = 0;

while (len > 0)
    {
    c = str[i];
    if (!c)
    return nullptr;

    /* Each chunk is either a '$' escape...  */
    if (c == '$')
    {
    i++;
    switch (str[i++])
        {
        case 'S':
        c = '/';
        break;
        case '_':
        c = '.';
        break;
        case '$':
        c = '$';
        break;
        default:
        return nullptr;
        }
    next = d_make_character (di, c);
    d_advance (di, i);
    str = d_str (di);
    len -= i;
    i = 0;
    if (next == nullptr)
        return nullptr;
    }
    /* ... or a sequence of characters.  */
    else
    {
    while (i < len && str[i] && str[i] != '$')
        i++;

    next = d_make_name (di, str, i);
    d_advance (di, i);
    str = d_str (di);
    len -= i;
    i = 0;
    if (next == nullptr)
        return nullptr;
    }

    if (p == nullptr)
    p = next;
    else
    {
    p = d_make_comp (di, DEMANGLE_COMPONENT_COMPOUND_NAME, p, next);
    if (p == nullptr)
        return nullptr;
    }
    }

p = d_make_comp (di, DEMANGLE_COMPONENT_JAVA_RESOURCE, p, nullptr);

return p;
}

/* <special-name> ::= TV <type>
                ::= TT <type>
                ::= TI <type>
                ::= TS <type>
        ::= TA <template-arg>
                ::= GV <(object) name>
                ::= T <call-offset> <(base) encoding>
                ::= Tc <call-offset> <call-offset> <(base) encoding>
Also g++ extensions:
                ::= TC <type> <(offset) number> _ <(base) type>
                ::= TF <type>
                ::= TJ <type>
                ::= GR <name>
        ::= GA <encoding>
        ::= Gr <resource name>
        ::= GTt <encoding>
        ::= GTn <encoding>
*/

static struct demangle_component *
d_special_name (struct d_info *di)
{
di->expansion += 20;
if (d_check_char (di, 'T'))
    {
    switch (d_next_char (di))
    {
    case 'V':
    di->expansion -= 5;
    return d_make_comp (di, DEMANGLE_COMPONENT_VTABLE,
                cplus_demangle_type (di), nullptr);
    case 'T':
    di->expansion -= 10;
    return d_make_comp (di, DEMANGLE_COMPONENT_VTT,
                cplus_demangle_type (di), nullptr);
    case 'I':
    return d_make_comp (di, DEMANGLE_COMPONENT_TYPEINFO,
                cplus_demangle_type (di), nullptr);
    case 'S':
    return d_make_comp (di, DEMANGLE_COMPONENT_TYPEINFO_NAME,
                cplus_demangle_type (di), nullptr);

    case 'h':
    if (! d_call_offset (di, 'h'))
        return nullptr;
    return d_make_comp (di, DEMANGLE_COMPONENT_THUNK,
                d_encoding (di, 0), nullptr);

    case 'v':
    if (! d_call_offset (di, 'v'))
        return nullptr;
    return d_make_comp (di, DEMANGLE_COMPONENT_VIRTUAL_THUNK,
                d_encoding (di, 0), nullptr);

    case 'c':
    if (! d_call_offset (di, '\0'))
        return nullptr;
    if (! d_call_offset (di, '\0'))
        return nullptr;
    return d_make_comp (di, DEMANGLE_COMPONENT_COVARIANT_THUNK,
                d_encoding (di, 0), nullptr);

    case 'C':
    {
        struct demangle_component *derived_type;
        int offset;
        struct demangle_component *base_type;

        derived_type = cplus_demangle_type (di);
        offset = d_number (di);
        if (offset < 0)
        return nullptr;
        if (! d_check_char (di, '_'))
        return nullptr;
        base_type = cplus_demangle_type (di);
        /* We don't display the offset.  FIXME: We should display
        it in verbose mode.  */
        di->expansion += 5;
        return d_make_comp (di, DEMANGLE_COMPONENT_CONSTRUCTION_VTABLE,
                base_type, derived_type);
    }

    case 'F':
    return d_make_comp (di, DEMANGLE_COMPONENT_TYPEINFO_FN,
                cplus_demangle_type (di), nullptr);
    case 'J':
    return d_make_comp (di, DEMANGLE_COMPONENT_JAVA_CLASS,
                cplus_demangle_type (di), nullptr);

    case 'H':
    return d_make_comp (di, DEMANGLE_COMPONENT_TLS_INIT,
                d_name (di, 0), nullptr);

    case 'W':
    return d_make_comp (di, DEMANGLE_COMPONENT_TLS_WRAPPER,
                d_name (di, 0), nullptr);

    case 'A':
    return d_make_comp (di, DEMANGLE_COMPONENT_TPARM_OBJ,
                d_template_arg (di), nullptr);

    default:
    return nullptr;
    }
    }
else if (d_check_char (di, 'G'))
    {
    switch (d_next_char (di))
    {
    case 'V':
    return d_make_comp (di, DEMANGLE_COMPONENT_GUARD,
                d_name (di, 0), nullptr);

    case 'R':
    {
        struct demangle_component *name = d_name (di, 0);
        return d_make_comp (di, DEMANGLE_COMPONENT_REFTEMP, name,
                d_number_component (di));
    }

    case 'A':
    return d_make_comp (di, DEMANGLE_COMPONENT_HIDDEN_ALIAS,
                d_encoding (di, 0), nullptr);

    case 'I':
    {
        struct demangle_component *module = nullptr;
        if (!d_maybe_module_name (di, &module) || !module)
        return nullptr;
        return d_make_comp (di, DEMANGLE_COMPONENT_MODULE_INIT,
                module, nullptr);
    }
    case 'T':
    switch (d_next_char (di))
        {
        case 'n':
        return d_make_comp (di, DEMANGLE_COMPONENT_NONTRANSACTION_CLONE,
                d_encoding (di, 0), nullptr);
        default:
        /* ??? The proposal is that other letters (such as 'h') stand
        for different variants of transaction cloning, such as
        compiling directly for hardware transaction support.  But
        they still should all be transactional clones of some sort
        so go ahead and call them that.  */
        case 't':
        return d_make_comp (di, DEMANGLE_COMPONENT_TRANSACTION_CLONE,
                d_encoding (di, 0), nullptr);
        }

    case 'r':
    return d_java_resource (di);

    default:
    return nullptr;
    }
    }
else
    return nullptr;
}

/* <call-offset> ::= h <nv-offset> _
                ::= v <v-offset> _

<nv-offset> ::= <(offset) number>

<v-offset> ::= <(offset) number> _ <(virtual offset) number>

The C parameter, if not '\0', is a character we just read which is
the start of the <call-offset>.

We don't display the offset information anywhere.  FIXME: We should
display it in verbose mode.  */

static int
d_call_offset (struct d_info *di, int c)
{
if (c == '\0')
    c = d_next_char (di);

if (c == 'h')
    d_number (di);
else if (c == 'v')
    {
    d_number (di);
    if (! d_check_char (di, '_'))
    return 0;
    d_number (di);
    }
else
    return 0;

if (! d_check_char (di, '_'))
    return 0;

return 1;
}

/* <ctor-dtor-name> ::= C1
                    ::= C2
                    ::= C3
                    ::= D0
                    ::= D1
                    ::= D2
*/

static struct demangle_component *
d_ctor_dtor_name (struct d_info *di)
{
if (di->last_name != nullptr)
    {
    if (di->last_name->type == DEMANGLE_COMPONENT_NAME)
    di->expansion += di->last_name->u.s_name.len;
    else if (di->last_name->type == DEMANGLE_COMPONENT_SUB_STD)
    di->expansion += di->last_name->u.s_string.len;
    }
switch (d_peek_char (di))
    {
    case 'C':
    {
    enum gnu_v3_ctor_kinds kind;
    int inheriting = 0;

    if (d_peek_next_char (di) == 'I')
    {
        inheriting = 1;
        d_advance (di, 1);
    }

    switch (d_peek_next_char (di))
    {
    case '1':
        kind = gnu_v3_complete_object_ctor;
        break;
    case '2':
        kind = gnu_v3_base_object_ctor;
        break;
    case '3':
        kind = gnu_v3_complete_object_allocating_ctor;
        break;
        case '4':
        kind = gnu_v3_unified_ctor;
        break;
    case '5':
        kind = gnu_v3_object_ctor_group;
        break;
    default:
        return nullptr;
    }

    d_advance (di, 2);

    if (inheriting)
    cplus_demangle_type (di);

    return d_make_ctor (di, kind, di->last_name);
    }

    case 'D':
    {
    enum gnu_v3_dtor_kinds kind;

    switch (d_peek_next_char (di))
    {
    case '0':
        kind = gnu_v3_deleting_dtor;
        break;
    case '1':
        kind = gnu_v3_complete_object_dtor;
        break;
    case '2':
        kind = gnu_v3_base_object_dtor;
        break;
        /*  digit '3' is not used */
    case '4':
        kind = gnu_v3_unified_dtor;
        break;
    case '5':
        kind = gnu_v3_object_dtor_group;
        break;
    default:
        return nullptr;
    }
    d_advance (di, 2);
    return d_make_dtor (di, kind, di->last_name);
    }

    default:
    return nullptr;
    }
}

/* True iff we're looking at an order-insensitive type-qualifier, including
function-type-qualifiers.  */

static int
next_is_type_qual (struct d_info *di)
{
char peek = d_peek_char (di);
if (peek == 'r' || peek == 'V' || peek == 'K')
    return 1;
if (peek == 'D')
    {
    peek = d_peek_next_char (di);
    if (peek == 'x' || peek == 'o' || peek == 'O' || peek == 'w')
    return 1;
    }
return 0;
}

/* <type> ::= <builtin-type>
        ::= <function-type>
        ::= <class-enum-type>
        ::= <array-type>
        ::= <pointer-to-member-type>
        ::= <template-param>
        ::= <template-template-param> <template-args>
        ::= <substitution>
        ::= <CV-qualifiers> <type>
        ::= P <type>
        ::= R <type>
        ::= O <type> (C++0x)
        ::= C <type>
        ::= G <type>
        ::= U <source-name> <type>

<builtin-type> ::= various one letter codes
                ::= u <source-name>
*/

static
const struct demangle_builtin_type_info
cplus_demangle_builtin_types[D_BUILTIN_TYPE_COUNT] =
{
/* a */ { NL ("signed char"),	NL ("signed char"),	D_PRINT_DEFAULT },
/* b */ { NL ("bool"),	NL ("boolean"),		D_PRINT_BOOL },
/* c */ { NL ("char"),	NL ("byte"),		D_PRINT_DEFAULT },
/* d */ { NL ("double"),	NL ("double"),		D_PRINT_FLOAT },
/* e */ { NL ("long double"),	NL ("long double"),	D_PRINT_FLOAT },
/* f */ { NL ("float"),	NL ("float"),		D_PRINT_FLOAT },
/* g */ { NL ("__float128"),	NL ("__float128"),	D_PRINT_FLOAT },
/* h */ { NL ("unsigned char"), NL ("unsigned char"),	D_PRINT_DEFAULT },
/* i */ { NL ("int"),		NL ("int"),		D_PRINT_INT },
/* j */ { NL ("unsigned int"), NL ("unsigned"),	D_PRINT_UNSIGNED },
/* k */ { nullptr, 0,		nullptr, 0,		D_PRINT_DEFAULT },
/* l */ { NL ("long"),	NL ("long"),		D_PRINT_LONG },
/* m */ { NL ("unsigned long"), NL ("unsigned long"),	D_PRINT_UNSIGNED_LONG },
/* n */ { NL ("__int128"),	NL ("__int128"),	D_PRINT_DEFAULT },
/* o */ { NL ("unsigned __int128"), NL ("unsigned __int128"),
        D_PRINT_DEFAULT },
/* p */ { nullptr, 0,		nullptr, 0,		D_PRINT_DEFAULT },
/* q */ { nullptr, 0,		nullptr, 0,		D_PRINT_DEFAULT },
/* r */ { nullptr, 0,		nullptr, 0,		D_PRINT_DEFAULT },
/* s */ { NL ("short"),	NL ("short"),		D_PRINT_DEFAULT },
/* t */ { NL ("unsigned short"), NL ("unsigned short"), D_PRINT_DEFAULT },
/* u */ { nullptr, 0,		nullptr, 0,		D_PRINT_DEFAULT },
/* v */ { NL ("void"),	NL ("void"),		D_PRINT_VOID },
/* w */ { NL ("wchar_t"),	NL ("char"),		D_PRINT_DEFAULT },
/* x */ { NL ("long long"),	NL ("long"),		D_PRINT_LONG_LONG },
/* y */ { NL ("unsigned long long"), NL ("unsigned long long"),
        D_PRINT_UNSIGNED_LONG_LONG },
/* z */ { NL ("..."),		NL ("..."),		D_PRINT_DEFAULT },
/* 26 */ { NL ("decimal32"),	NL ("decimal32"),	D_PRINT_DEFAULT },
/* 27 */ { NL ("decimal64"),	NL ("decimal64"),	D_PRINT_DEFAULT },
/* 28 */ { NL ("decimal128"),	NL ("decimal128"),	D_PRINT_DEFAULT },
/* 29 */ { NL ("half"),	NL ("half"),		D_PRINT_FLOAT },
/* 30 */ { NL ("char8_t"),	NL ("char8_t"),		D_PRINT_DEFAULT },
/* 31 */ { NL ("char16_t"),	NL ("char16_t"),	D_PRINT_DEFAULT },
/* 32 */ { NL ("char32_t"),	NL ("char32_t"),	D_PRINT_DEFAULT },
/* 33 */ { NL ("decltype(nullptr)"),	NL ("decltype(nullptr)"),
        D_PRINT_DEFAULT },
/* 34 */ { NL ("_Float"),	NL ("_Float"),		D_PRINT_FLOAT },
/* 35 */ { NL ("std::bfloat16_t"), NL ("std::bfloat16_t"), D_PRINT_FLOAT },
};

static
struct demangle_component *
cplus_demangle_type (struct d_info *di)
{
char peek;
struct demangle_component *ret;
int can_subst;

/* The ABI specifies that when CV-qualifiers are used, the base type
    is substitutable, and the fully qualified type is substitutable,
    but the base type with a strict subset of the CV-qualifiers is
    not substitutable.  The natural recursive implementation of the
    CV-qualifiers would cause subsets to be substitutable, so instead
    we pull them all off now.

    FIXME: The ABI says that order-insensitive vendor qualifiers
    should be handled in the same way, but we have no way to tell
    which vendor qualifiers are order-insensitive and which are
    order-sensitive.  So we just assume that they are all
    order-sensitive.  g++ 3.4 supports only one vendor qualifier,
    __vector, and it treats it as order-sensitive when mangling
    names.  */

if (next_is_type_qual (di))
    {
    struct demangle_component **pret;

    pret = d_cv_qualifiers (di, &ret, 0);
    if (pret == nullptr)
    return nullptr;
    if (d_peek_char (di) == 'F')
    {
    /* cv-qualifiers before a function type apply to 'this',
        so avoid adding the unqualified function type to
        the substitution list.  */
    *pret = d_function_type (di);
    }
    else
    *pret = cplus_demangle_type (di);
    if (!*pret)
    return nullptr;
    if ((*pret)->type == DEMANGLE_COMPONENT_RVALUE_REFERENCE_THIS
    || (*pret)->type == DEMANGLE_COMPONENT_REFERENCE_THIS)
    {
    /* Move the ref-qualifier outside the cv-qualifiers so that
        they are printed in the right order.  */
    struct demangle_component *fn = d_left (*pret);
    d_left (*pret) = ret;
    ret = *pret;
    *pret = fn;
    }
    if (! d_add_substitution (di, ret))
    return nullptr;
    return ret;
    }

can_subst = 1;

peek = d_peek_char (di);
switch (peek)
    {
    case 'a': case 'b': case 'c': case 'd': case 'e': case 'f': case 'g':
    case 'h': case 'i': case 'j':           case 'l': case 'm': case 'n':
    case 'o':                               case 's': case 't':
    case 'v': case 'w': case 'x': case 'y': case 'z':
    ret = d_make_builtin_type (di,
                &cplus_demangle_builtin_types[peek - 'a']);
    di->expansion += ret->u.s_builtin.type->len;
    can_subst = 0;
    d_advance (di, 1);
    break;

    case 'u':
    d_advance (di, 1);
    ret = d_make_comp (di, DEMANGLE_COMPONENT_VENDOR_TYPE,
            d_source_name (di), nullptr);
    break;

    case 'F':
    ret = d_function_type (di);
    break;

    case 'A':
    ret = d_array_type (di);
    break;

    case 'M':
    ret = d_pointer_to_member_type (di);
    break;

    case 'T':
    ret = d_template_param (di);
    if (d_peek_char (di) == 'I')
    {
    /* This may be <template-template-param> <template-args>.
        If this is the type for a conversion operator, we can
        have a <template-template-param> here only by following
        a derivation like this:

        <nested-name>
        -> <template-prefix> <template-args>
        -> <prefix> <template-unqualified-name> <template-args>
        -> <unqualified-name> <template-unqualified-name> <template-args>
        -> <source-name> <template-unqualified-name> <template-args>
        -> <source-name> <operator-name> <template-args>
        -> <source-name> cv <type> <template-args>
        -> <source-name> cv <template-template-param> <template-args> <template-args>

        where the <template-args> is followed by another.
        Otherwise, we must have a derivation like this:

        <nested-name>
        -> <template-prefix> <template-args>
        -> <prefix> <template-unqualified-name> <template-args>
        -> <unqualified-name> <template-unqualified-name> <template-args>
        -> <source-name> <template-unqualified-name> <template-args>
        -> <source-name> <operator-name> <template-args>
        -> <source-name> cv <type> <template-args>
        -> <source-name> cv <template-param> <template-args>

        where we need to leave the <template-args> to be processed
        by d_prefix (following the <template-prefix>).

        The <template-template-param> part is a substitution
        candidate.  */
    if (! di->is_conversion)
        {
        if (! d_add_substitution (di, ret))
        return nullptr;
        ret = d_make_comp (di, DEMANGLE_COMPONENT_TEMPLATE, ret,
                d_template_args (di));
        }
    else
        {
        struct demangle_component *args;
        struct d_info_checkpoint checkpoint;

        d_checkpoint (di, &checkpoint);
        args = d_template_args (di);
        if (d_peek_char (di) == 'I')
        {
        if (! d_add_substitution (di, ret))
            return nullptr;
        ret = d_make_comp (di, DEMANGLE_COMPONENT_TEMPLATE, ret,
                    args);
        }
        else
        d_backtrack (di, &checkpoint);
        }
    }
    break;

    case 'O':
    d_advance (di, 1);
    ret = d_make_comp (di, DEMANGLE_COMPONENT_RVALUE_REFERENCE,
                        cplus_demangle_type (di), nullptr);
    break;

    case 'P':
    d_advance (di, 1);
    ret = d_make_comp (di, DEMANGLE_COMPONENT_POINTER,
            cplus_demangle_type (di), nullptr);
    break;

    case 'R':
    d_advance (di, 1);
    ret = d_make_comp (di, DEMANGLE_COMPONENT_REFERENCE,
                        cplus_demangle_type (di), nullptr);
    break;

    case 'C':
    d_advance (di, 1);
    ret = d_make_comp (di, DEMANGLE_COMPONENT_COMPLEX,
            cplus_demangle_type (di), nullptr);
    break;

    case 'G':
    d_advance (di, 1);
    ret = d_make_comp (di, DEMANGLE_COMPONENT_IMAGINARY,
            cplus_demangle_type (di), nullptr);
    break;

    case 'U':
    d_advance (di, 1);
    ret = d_source_name (di);
    if (d_peek_char (di) == 'I')
    ret = d_make_comp (di, DEMANGLE_COMPONENT_TEMPLATE, ret,
            d_template_args (di));
    ret = d_make_comp (di, DEMANGLE_COMPONENT_VENDOR_TYPE_QUAL,
            cplus_demangle_type (di), ret);
    break;

    case 'D':
    can_subst = 0;
    d_advance (di, 1);
    peek = d_next_char (di);
    switch (peek)
    {
    case 'T':
    case 't':
    /* decltype (expression) */
    ret = d_make_comp (di, DEMANGLE_COMPONENT_DECLTYPE,
                d_expression (di), nullptr);
    if (ret && d_next_char (di) != 'E')
        ret = nullptr;
    can_subst = 1;
    break;
    
    case 'p':
    /* Pack expansion.  */
    ret = d_make_comp (di, DEMANGLE_COMPONENT_PACK_EXPANSION,
                cplus_demangle_type (di), nullptr);
    can_subst = 1;
    break;

    case 'a':
    /* auto */
    ret = d_make_name (di, "auto", 4);
    break;
    case 'c':
    /* decltype(auto) */
    ret = d_make_name (di, "decltype(auto)", 14);
    break;

    case 'f':
    /* 32-bit decimal floating point */
    ret = d_make_builtin_type (di, &cplus_demangle_builtin_types[26]);
    di->expansion += ret->u.s_builtin.type->len;
    break;
    case 'd':
    /* 64-bit DFP */
    ret = d_make_builtin_type (di, &cplus_demangle_builtin_types[27]);
    di->expansion += ret->u.s_builtin.type->len;
    break;
    case 'e':
    /* 128-bit DFP */
    ret = d_make_builtin_type (di, &cplus_demangle_builtin_types[28]);
    di->expansion += ret->u.s_builtin.type->len;
    break;
    case 'h':
    /* 16-bit half-precision FP */
    ret = d_make_builtin_type (di, &cplus_demangle_builtin_types[29]);
    di->expansion += ret->u.s_builtin.type->len;
    break;
    case 'u':
    /* char8_t */
    ret = d_make_builtin_type (di, &cplus_demangle_builtin_types[30]);
    di->expansion += ret->u.s_builtin.type->len;
    break;
    case 's':
    /* char16_t */
    ret = d_make_builtin_type (di, &cplus_demangle_builtin_types[31]);
    di->expansion += ret->u.s_builtin.type->len;
    break;
    case 'i':
    /* char32_t */
    ret = d_make_builtin_type (di, &cplus_demangle_builtin_types[32]);
    di->expansion += ret->u.s_builtin.type->len;
    break;

    case 'F':
    /* DF<number>_ - _Float<number>.
        DF<number>x - _Float<number>x
        DF16b - std::bfloat16_t.  */
    {
        int arg = d_number (di);
        char buf[12];
        char suffix = 0;
        if (d_peek_char (di) == 'b')
        {
        if (arg != 16)
        return nullptr;
        d_advance (di, 1);
        ret = d_make_builtin_type (di,
                    &cplus_demangle_builtin_types[35]);
        di->expansion += ret->u.s_builtin.type->len;
        break;
        }
        if (d_peek_char (di) == 'x')
        suffix = 'x';
        if (!suffix && d_peek_char (di) != '_')
        return nullptr;
        ret
        = d_make_extended_builtin_type (di,
                        &cplus_demangle_builtin_types[34],
                        arg, suffix);
        d_advance (di, 1);
        auto size = sprint (buf, "{}", arg);
        di->expansion += ret->u.s_extended_builtin.type->len
                + size + (suffix != 0);
        break;
    }

    case 'v':
    ret = d_vector_type (di);
    can_subst = 1;
    break;

        case 'n':
        /* decltype(nullptr) */
    ret = d_make_builtin_type (di, &cplus_demangle_builtin_types[33]);
    di->expansion += ret->u.s_builtin.type->len;
    break;

    default:
    return nullptr;
    }
    break;

    default:
    return d_class_enum_type (di, 1);
    }

if (can_subst)
    {
    if (! d_add_substitution (di, ret))
    return nullptr;
    }

return ret;
}

/* <CV-qualifiers> ::= [r] [V] [K] [Dx] */

static struct demangle_component **
d_cv_qualifiers (struct d_info *di,
                struct demangle_component **pret, int member_fn)
{
struct demangle_component **pstart;
char peek;

pstart = pret;
peek = d_peek_char (di);
while (next_is_type_qual (di))
    {
    enum demangle_component_type t;
    struct demangle_component *right = nullptr;

    d_advance (di, 1);
    if (peek == 'r')
    {
    t = (member_fn
        ? DEMANGLE_COMPONENT_RESTRICT_THIS
        : DEMANGLE_COMPONENT_RESTRICT);
    di->expansion += sizeof "restrict";
    }
    else if (peek == 'V')
    {
    t = (member_fn
        ? DEMANGLE_COMPONENT_VOLATILE_THIS
        : DEMANGLE_COMPONENT_VOLATILE);
    di->expansion += sizeof "volatile";
    }
    else if (peek == 'K')
    {
    t = (member_fn
        ? DEMANGLE_COMPONENT_CONST_THIS
        : DEMANGLE_COMPONENT_CONST);
    di->expansion += sizeof "const";
    }
    else
    {
    peek = d_next_char (di);
    if (peek == 'x')
        {
        t = DEMANGLE_COMPONENT_TRANSACTION_SAFE;
        di->expansion += sizeof "transaction_safe";
        }
    else if (peek == 'o'
        || peek == 'O')
        {
        t = DEMANGLE_COMPONENT_NOEXCEPT;
        di->expansion += sizeof "noexcept";
        if (peek == 'O')
        {
        right = d_expression (di);
        if (right == nullptr)
            return nullptr;
        if (! d_check_char (di, 'E'))
            return nullptr;
        }
        }
    else if (peek == 'w')
        {
        t = DEMANGLE_COMPONENT_THROW_SPEC;
        di->expansion += sizeof "throw";
        right = d_parmlist (di);
        if (right == nullptr)
        return nullptr;
        if (! d_check_char (di, 'E'))
        return nullptr;
        }
    else
        return nullptr;
    }

    *pret = d_make_comp (di, t, nullptr, right);
    if (*pret == nullptr)
    return nullptr;
    pret = &d_left (*pret);

    peek = d_peek_char (di);
    }

if (!member_fn && peek == 'F')
    {
    while (pstart != pret)
    {
    switch ((*pstart)->type)
        {
        case DEMANGLE_COMPONENT_RESTRICT:
        (*pstart)->type = DEMANGLE_COMPONENT_RESTRICT_THIS;
        break;
        case DEMANGLE_COMPONENT_VOLATILE:
        (*pstart)->type = DEMANGLE_COMPONENT_VOLATILE_THIS;
        break;
        case DEMANGLE_COMPONENT_CONST:
        (*pstart)->type = DEMANGLE_COMPONENT_CONST_THIS;
        break;
        default:
        break;
        }
    pstart = &d_left (*pstart);
    }
    }

return pret;
}

/* <ref-qualifier> ::= R
                ::= O */

static struct demangle_component *
d_ref_qualifier (struct d_info *di, struct demangle_component *sub)
{
struct demangle_component *ret = sub;
char peek;

peek = d_peek_char (di);
if (peek == 'R' || peek == 'O')
    {
    enum demangle_component_type t;
    if (peek == 'R')
    {
    t = DEMANGLE_COMPONENT_REFERENCE_THIS;
    di->expansion += sizeof "&";
    }
    else
    {
    t = DEMANGLE_COMPONENT_RVALUE_REFERENCE_THIS;
    di->expansion += sizeof "&&";
    }
    d_advance (di, 1);

    ret = d_make_comp (di, t, ret, nullptr);
    }

return ret;
}

/* <function-type> ::= F [Y] <bare-function-type> [<ref-qualifier>] [T] E  */

static struct demangle_component *
d_function_type (struct d_info *di)
{
struct demangle_component *ret = nullptr;

if ((di->options & DMGL_NO_RECURSE_LIMIT) == 0)
    {
    if (di->recursion_level > DEMANGLE_RECURSION_LIMIT)
    /* FIXME: There ought to be a way to report
    that the recursion limit has been reached.  */
    return nullptr;

    di->recursion_level ++;
    }

if (d_check_char (di, 'F'))
    {
    if (d_peek_char (di) == 'Y')
    {
    /* Function has C linkage.  We don't print this information.
        FIXME: We should print it in verbose mode.  */
    d_advance (di, 1);
    }
    ret = d_bare_function_type (di, 1);
    ret = d_ref_qualifier (di, ret);
    
    if (! d_check_char (di, 'E'))
    ret = nullptr;
    }

if ((di->options & DMGL_NO_RECURSE_LIMIT) == 0)
    di->recursion_level --;
return ret;
}

/* <type>+ */

static struct demangle_component *
d_parmlist (struct d_info *di)
{
struct demangle_component *tl;
struct demangle_component **ptl;

tl = nullptr;
ptl = &tl;
while (1)
    {
    struct demangle_component *type;

    char peek = d_peek_char (di);
    if (peek == '\0' || peek == 'E' || peek == '.' || peek == 'Q')
    break;
    if ((peek == 'R' || peek == 'O')
    && d_peek_next_char (di) == 'E')
    /* Function ref-qualifier, not a ref prefix for a parameter type.  */
    break;
    type = cplus_demangle_type (di);
    if (type == nullptr)
    return nullptr;
    *ptl = d_make_comp (di, DEMANGLE_COMPONENT_ARGLIST, type, nullptr);
    if (*ptl == nullptr)
    return nullptr;
    ptl = &d_right (*ptl);
    }

/* There should be at least one parameter type besides the optional
    return type.  A function which takes no arguments will have a
    single parameter type void.  */
if (tl == nullptr)
    return nullptr;

/* If we have a single parameter type void, omit it.  */
if (d_right (tl) == nullptr
    && d_left (tl)->type == DEMANGLE_COMPONENT_BUILTIN_TYPE
    && d_left (tl)->u.s_builtin.type->print == D_PRINT_VOID)
    {
    di->expansion -= d_left (tl)->u.s_builtin.type->len;
    d_left (tl) = nullptr;
    }

return tl;
}

/* <bare-function-type> ::= [J]<type>+  */

static struct demangle_component *
d_bare_function_type (struct d_info *di, int has_return_type)
{
struct demangle_component *return_type;
struct demangle_component *tl;
char peek;

/* Detect special qualifier indicating that the first argument
    is the return type.  */
peek = d_peek_char (di);
if (peek == 'J')
    {
    d_advance (di, 1);
    has_return_type = 1;
    }

if (has_return_type)
    {
    return_type = cplus_demangle_type (di);
    if (return_type == nullptr)
    return nullptr;
    }
else
    return_type = nullptr;

tl = d_parmlist (di);
if (tl == nullptr)
    return nullptr;

return d_make_comp (di, DEMANGLE_COMPONENT_FUNCTION_TYPE,
            return_type, tl);
}

/* <class-enum-type> ::= <name>  */

static struct demangle_component *
d_class_enum_type (struct d_info *di, int substable)
{
return d_name (di, substable);
}

/* <array-type> ::= A <(positive dimension) number> _ <(element) type>
                ::= A [<(dimension) expression>] _ <(element) type>
*/

static struct demangle_component *
d_array_type (struct d_info *di)
{
char peek;
struct demangle_component *dim;

if (! d_check_char (di, 'A'))
    return nullptr;

peek = d_peek_char (di);
if (peek == '_')
    dim = nullptr;
else if (IS_DIGIT (peek))
    {
    const char *s;

    s = d_str (di);
    do
    {
    d_advance (di, 1);
    peek = d_peek_char (di);
    }
    while (IS_DIGIT (peek));
    dim = d_make_name (di, s, d_str (di) - s);
    if (dim == nullptr)
    return nullptr;
    }
else
    {
    dim = d_expression (di);
    if (dim == nullptr)
    return nullptr;
    }

if (! d_check_char (di, '_'))
    return nullptr;

return d_make_comp (di, DEMANGLE_COMPONENT_ARRAY_TYPE, dim,
            cplus_demangle_type (di));
}

/* <vector-type> ::= Dv <number> _ <type>
                ::= Dv _ <expression> _ <type> */

static struct demangle_component *
d_vector_type (struct d_info *di)
{
char peek;
struct demangle_component *dim;

peek = d_peek_char (di);
if (peek == '_')
    {
    d_advance (di, 1);
    dim = d_expression (di);
    }
else
    dim = d_number_component (di);

if (dim == nullptr)
    return nullptr;

if (! d_check_char (di, '_'))
    return nullptr;

return d_make_comp (di, DEMANGLE_COMPONENT_VECTOR_TYPE, dim,
            cplus_demangle_type (di));
}

/* <pointer-to-member-type> ::= M <(class) type> <(member) type>  */

static struct demangle_component *
d_pointer_to_member_type (struct d_info *di)
{
struct demangle_component *cl;
struct demangle_component *mem;

if (! d_check_char (di, 'M'))
    return nullptr;

cl = cplus_demangle_type (di);
if (cl == nullptr)
    return nullptr;

/* The ABI says, "The type of a non-static member function is considered
    to be different, for the purposes of substitution, from the type of a
    namespace-scope or static member function whose type appears
    similar. The types of two non-static member functions are considered
    to be different, for the purposes of substitution, if the functions
    are members of different classes. In other words, for the purposes of
    substitution, the class of which the function is a member is
    considered part of the type of function."

    For a pointer to member function, this call to cplus_demangle_type
    will end up adding a (possibly qualified) non-member function type to
    the substitution table, which is not correct; however, the member
    function type will never be used in a substitution, so putting the
    wrong type in the substitution table is harmless.  */

mem = cplus_demangle_type (di);
if (mem == nullptr)
    return nullptr;

return d_make_comp (di, DEMANGLE_COMPONENT_PTRMEM_TYPE, cl, mem);
}

/* <non-negative number> _ */

static int
d_compact_number (struct d_info *di)
{
int num;
if (d_peek_char (di) == '_')
    num = 0;
else if (d_peek_char (di) == 'n')
    return -1;
else
    num = d_number (di) + 1;

if (num < 0 || ! d_check_char (di, '_'))
    return -1;
return num;
}

/* <template-param> ::= T_
                    ::= T <(parameter-2 non-negative) number> _
*/

static struct demangle_component *
d_template_param (struct d_info *di)
{
int param;

if (! d_check_char (di, 'T'))
    return nullptr;

param = d_compact_number (di);
if (param < 0)
    return nullptr;

return d_make_template_param (di, param);
}

/* <template-args> ::= I <template-arg>+ E  */

static struct demangle_component *
d_template_args (struct d_info *di)
{
if (d_peek_char (di) != 'I'
    && d_peek_char (di) != 'J')
    return nullptr;
d_advance (di, 1);

return d_template_args_1 (di);
}

/* <template-arg>* [Q <constraint-expression>] E  */

static struct demangle_component *
d_template_args_1 (struct d_info *di)
{
struct demangle_component *hold_last_name;
struct demangle_component *al;
struct demangle_component **pal;

/* Preserve the last name we saw--don't let the template arguments
    clobber it, as that would give us the wrong name for a subsequent
    constructor or destructor.  */
hold_last_name = di->last_name;

if (d_peek_char (di) == 'E')
    {
    /* An argument pack can be empty.  */
    d_advance (di, 1);
    return d_make_comp (di, DEMANGLE_COMPONENT_TEMPLATE_ARGLIST, nullptr, nullptr);
    }

al = nullptr;
pal = &al;
while (1)
    {
    struct demangle_component *a;

    a = d_template_arg (di);
    if (a == nullptr)
    return nullptr;

    *pal = d_make_comp (di, DEMANGLE_COMPONENT_TEMPLATE_ARGLIST, a, nullptr);
    if (*pal == nullptr)
    return nullptr;
    pal = &d_right (*pal);

    char peek = d_peek_char (di);
    if (peek == 'E' || peek == 'Q')
    break;
    }

al = d_maybe_constraints (di, al);

if (d_peek_char (di) != 'E')
    return nullptr;
d_advance (di, 1);

di->last_name = hold_last_name;

return al;
}

/* <template-arg> ::= <type>
                ::= X <expression> E
                ::= <expr-primary>
*/

static struct demangle_component *
d_template_arg (struct d_info *di)
{
struct demangle_component *ret;

switch (d_peek_char (di))
    {
    case 'X':
    d_advance (di, 1);
    ret = d_expression (di);
    if (! d_check_char (di, 'E'))
    return nullptr;
    return ret;

    case 'L':
    return d_expr_primary (di);

    case 'I':
    case 'J':
    /* An argument pack.  */
    return d_template_args (di);

    default:
    return cplus_demangle_type (di);
    }
}

/* Parse a sequence of expressions until we hit the terminator
character.  */

static struct demangle_component *
d_exprlist (struct d_info *di, char terminator)
{
struct demangle_component *list = nullptr;
struct demangle_component **p = &list;

if (d_peek_char (di) == terminator)
    {
    d_advance (di, 1);
    return d_make_comp (di, DEMANGLE_COMPONENT_ARGLIST, nullptr, nullptr);
    }

while (1)
    {
    struct demangle_component *arg = d_expression (di);
    if (arg == nullptr)
    return nullptr;

    *p = d_make_comp (di, DEMANGLE_COMPONENT_ARGLIST, arg, nullptr);
    if (*p == nullptr)
    return nullptr;
    p = &d_right (*p);

    if (d_peek_char (di) == terminator)
    {
    d_advance (di, 1);
    break;
    }
    }

return list;
}

/* Returns nonzero iff OP is an operator for a C++ cast: const_cast,
dynamic_cast, static_cast or reinterpret_cast.  */

static int
op_is_new_cast (struct demangle_component *op)
{
const char *code = op->u.s_operator.op->code;
return (code[1] == 'c'
    && (code[0] == 's' || code[0] == 'd'
        || code[0] == 'c' || code[0] == 'r'));
}

/*   <unresolved-name> ::= [gs] <base-unresolved-name> # x or (with "gs") ::x
    ::= sr <unresolved-type> <base-unresolved-name> # T::x / decltype(p)::x
    # T::N::x /decltype(p)::N::x
    ::= srN <unresolved-type> <unresolved-qualifier-level>+ E <base-unresolved-name>
    # A::x, N::y, A<T>::z; "gs" means leading "::"
    ::= [gs] sr <unresolved-qualifier-level>+ E <base-unresolved-name>

    "gs" is handled elsewhere, as a unary operator.  */

static struct demangle_component *
d_unresolved_name (struct d_info *di)
{
struct demangle_component *type;
struct demangle_component *name;
char peek;

/* Consume the "sr".  */
d_advance (di, 2);

peek = d_peek_char (di);
if (di->unresolved_name_state
    && (IS_DIGIT (peek)
    || IS_LOWER (peek)
    || peek == 'C'
    || peek == 'U'
    || peek == 'L'))
    {
    /* The third production is ambiguous with the old unresolved-name syntax
    of <type> <base-unresolved-name>; in the old mangling, A::x was mangled
    as sr1A1x, now sr1AE1x.  So we first try to demangle using the new
    mangling, then with the old if that fails.  */
    di->unresolved_name_state = -1;
    type = d_prefix (di, 0);
    if (d_peek_char (di) == 'E')
    d_advance (di, 1);
    }
else
    type = cplus_demangle_type (di);
name = d_unqualified_name (di, type, nullptr);
if (d_peek_char (di) == 'I')
    name = d_make_comp (di, DEMANGLE_COMPONENT_TEMPLATE, name,
            d_template_args (di));
return name;
}

/* <expression> ::= <(unary) operator-name> <expression>
                ::= <(binary) operator-name> <expression> <expression>
                ::= <(trinary) operator-name> <expression> <expression> <expression>
        ::= cl <expression>+ E
                ::= st <type>
                ::= <template-param>
        ::= u <source-name> <template-arg>* E # vendor extended expression
        ::= <unresolved-name>
                ::= <expr-primary>

<braced-expression> ::= <expression>
            ::= di <field source-name> <braced-expression>	# .name = expr
            ::= dx <index expression> <braced-expression>	# [expr] = expr
            ::= dX <range begin expression> <range end expression> <braced-expression>
                                    # [expr ... expr] = expr
*/

static struct demangle_component *
d_expression_1 (struct d_info *di)
{
char peek;

peek = d_peek_char (di);
if (peek == 'L')
    return d_expr_primary (di);
else if (peek == 'T')
    return d_template_param (di);
else if (peek == 's' && d_peek_next_char (di) == 'r')
    return d_unresolved_name (di);
else if (peek == 's' && d_peek_next_char (di) == 'p')
    {
    d_advance (di, 2);
    return d_make_comp (di, DEMANGLE_COMPONENT_PACK_EXPANSION,
            d_expression_1 (di), nullptr);
    }
else if (peek == 'f' && d_peek_next_char (di) == 'p')
    {
    /* Function parameter used in a late-specified return type.  */
    int index;
    d_advance (di, 2);
    if (d_peek_char (di) == 'T')
    {
    /* 'this' parameter.  */
    d_advance (di, 1);
    index = 0;
    }
    else
    {
    index = d_compact_number (di);
    if (index == INT_MAX || index == -1)
        return nullptr;
    index++;
    }
    return d_make_function_param (di, index);
    }
else if (IS_DIGIT (peek)
    || (peek == 'o' && d_peek_next_char (di) == 'n'))
    {
    /* We can get an unqualified name as an expression in the case of
        a dependent function call, i.e. decltype(f(t)).  */
    struct demangle_component *name;

    if (peek == 'o')
    /* operator-function-id, i.e. operator+(t).  */
    d_advance (di, 2);

    name = d_unqualified_name (di, nullptr, nullptr);
    if (name == nullptr)
    return nullptr;
    if (d_peek_char (di) == 'I')
    return d_make_comp (di, DEMANGLE_COMPONENT_TEMPLATE, name,
                d_template_args (di));
    else
    return name;
    }
else if ((peek == 'i' || peek == 't')
    && d_peek_next_char (di) == 'l')
    {
    /* Brace-enclosed initializer list, untyped or typed.  */
    struct demangle_component *type = nullptr;
    d_advance (di, 2);
    if (peek == 't')
    type = cplus_demangle_type (di);
    if (!d_peek_char (di) || !d_peek_next_char (di))
    return nullptr;
    return d_make_comp (di, DEMANGLE_COMPONENT_INITIALIZER_LIST,
            type, d_exprlist (di, 'E'));
    }
else if (peek == 'u')
    {
    /* A vendor extended expression.  */
    struct demangle_component *name, *args;
    d_advance (di, 1);
    name = d_source_name (di);
    args = d_template_args_1 (di);
    return d_make_comp (di, DEMANGLE_COMPONENT_VENDOR_EXPR, name, args);
    }
else
    {
    struct demangle_component *op;
    const char *code = nullptr;
    int args;

    op = d_operator_name (di);
    if (op == nullptr)
    return nullptr;

    if (op->type == DEMANGLE_COMPONENT_OPERATOR)
    {
    code = op->u.s_operator.op->code;
    di->expansion += op->u.s_operator.op->len - 2;
    if (std::strcmp (code, "st") == 0)
        return d_make_comp (di, DEMANGLE_COMPONENT_UNARY, op,
                cplus_demangle_type (di));
    }

    switch (op->type)
    {
    default:
    return nullptr;
    case DEMANGLE_COMPONENT_OPERATOR:
    args = op->u.s_operator.op->args;
    break;
    case DEMANGLE_COMPONENT_EXTENDED_OPERATOR:
    args = op->u.s_extended_operator.args;
    break;
    case DEMANGLE_COMPONENT_CAST:
    args = 1;
    break;
    }

    switch (args)
    {
    case 0:
    return d_make_comp (di, DEMANGLE_COMPONENT_NULLARY, op, nullptr);

    case 1:
    {
        struct demangle_component *operand;
        int suffix = 0;

        if (code && (code[0] == 'p' || code[0] == 'm')
        && code[1] == code[0])
        /* pp_ and mm_ are the prefix variants.  */
        suffix = !d_check_char (di, '_');

        if (op->type == DEMANGLE_COMPONENT_CAST
        && d_check_char (di, '_'))
        operand = d_exprlist (di, 'E');
        else if (code && !std::strcmp (code, "sP"))
        operand = d_template_args_1 (di);
        else
        operand = d_expression_1 (di);

        if (suffix)
        /* Indicate the suffix variant for d_print_comp.  */
        operand = d_make_comp (di, DEMANGLE_COMPONENT_BINARY_ARGS,
                    operand, operand);

        return d_make_comp (di, DEMANGLE_COMPONENT_UNARY, op, operand);
    }
    case 2:
    {
        struct demangle_component *left;
        struct demangle_component *right;

        if (code == nullptr)
        return nullptr;
        if (op_is_new_cast (op))
        left = cplus_demangle_type (di);
        else if (code[0] == 'f')
        /* fold-expression.  */
        left = d_operator_name (di);
        else if (!std::strcmp (code, "di"))
        left = d_unqualified_name (di, nullptr, nullptr);
        else
        left = d_expression_1 (di);
        if (!std::strcmp (code, "cl"))
        right = d_exprlist (di, 'E');
        else if (!std::strcmp (code, "dt") || !std::strcmp (code, "pt"))
        {
        peek = d_peek_char (di);
        /* These codes start a qualified name.  */
        if ((peek == 'g' && d_peek_next_char (di) == 's')
            || (peek == 's' && d_peek_next_char (di) == 'r'))
        right = d_expression_1 (di);
        else
        {
            /* Otherwise it's an unqualified name.  We use
            d_unqualified_name rather than d_expression_1 here for
            old mangled names that didn't add 'on' before operator
            names.  */
            right = d_unqualified_name (di, nullptr, nullptr);
            if (d_peek_char (di) == 'I')
            right = d_make_comp (di, DEMANGLE_COMPONENT_TEMPLATE,
                    right, d_template_args (di));
        }
        }
        else
        right = d_expression_1 (di);

        return d_make_comp (di, DEMANGLE_COMPONENT_BINARY, op,
                d_make_comp (di,
                        DEMANGLE_COMPONENT_BINARY_ARGS,
                        left, right));
    }
    case 3:
    {
        struct demangle_component *first;
        struct demangle_component *second;
        struct demangle_component *third;

        if (code == nullptr)
        return nullptr;
        else if (!std::strcmp (code, "qu")
            || !std::strcmp (code, "dX"))
        {
        /* ?: expression.  */
        first = d_expression_1 (di);
        second = d_expression_1 (di);
        third = d_expression_1 (di);
        if (third == nullptr)
        return nullptr;
        }
        else if (code[0] == 'f')
        {
        /* fold-expression.  */
        first = d_operator_name (di);
        second = d_expression_1 (di);
        third = d_expression_1 (di);
        if (third == nullptr)
        return nullptr;
        }
        else if (code[0] == 'n')
        {
        /* new-expression.  */
        if (code[1] != 'w' && code[1] != 'a')
        return nullptr;
        first = d_exprlist (di, '_');
        second = cplus_demangle_type (di);
        if (d_peek_char (di) == 'E')
        {
            d_advance (di, 1);
            third = nullptr;
        }
        else if (d_peek_char (di) == 'p'
            && d_peek_next_char (di) == 'i')
        {
            /* Parenthesized initializer.  */
            d_advance (di, 2);
            third = d_exprlist (di, 'E');
        }
        else if (d_peek_char (di) == 'i'
            && d_peek_next_char (di) == 'l')
        /* initializer-list.  */
        third = d_expression_1 (di);
        else
        return nullptr;
        }
        else
        return nullptr;
        return d_make_comp (di, DEMANGLE_COMPONENT_TRINARY, op,
                d_make_comp (di,
                        DEMANGLE_COMPONENT_TRINARY_ARG1,
                        first,
                        d_make_comp (di,
                            DEMANGLE_COMPONENT_TRINARY_ARG2,
                            second, third)));
    }
    default:
    return nullptr;
    }
    }
}

static struct demangle_component *
d_expression (struct d_info *di)
{
struct demangle_component *ret;
int was_expression = di->is_expression;

di->is_expression = 1;
ret = d_expression_1 (di);
di->is_expression = was_expression;
return ret;
}

/* <expr-primary> ::= L <type> <(value) number> E
                ::= L <type> <(value) float> E
                ::= L <mangled-name> E
*/

static struct demangle_component *
d_expr_primary (struct d_info *di)
{
struct demangle_component *ret;

if (! d_check_char (di, 'L'))
    return nullptr;
if (d_peek_char (di) == '_'
    /* Workaround for G++ bug; see comment in write_template_arg.  */
    || d_peek_char (di) == 'Z')
    ret = cplus_demangle_mangled_name (di, 0);
else
    {
    struct demangle_component *type;
    enum demangle_component_type t;
    const char *s;

    type = cplus_demangle_type (di);
    if (type == nullptr)
    return nullptr;

    /* If we have a type we know how to print, we aren't going to
    print the type name itself.  */
    if (type->type == DEMANGLE_COMPONENT_BUILTIN_TYPE
    && type->u.s_builtin.type->print != D_PRINT_DEFAULT)
    di->expansion -= type->u.s_builtin.type->len;

    if (type->type == DEMANGLE_COMPONENT_BUILTIN_TYPE
    && std::strcmp (type->u.s_builtin.type->name,
            cplus_demangle_builtin_types[33].name) == 0)
    {
    if (d_peek_char (di) == 'E')
        {
        d_advance (di, 1);
        return type;
        }
    }

    /* Rather than try to interpret the literal value, we just
    collect it as a string.  Note that it's possible to have a
    floating point literal here.  The ABI specifies that the
    format of such literals is machine independent.  That's fine,
    but what's not fine is that versions of g++ up to 3.2 with
    -fabi-version=1 used upper case letters in the hex constant,
    and dumped out gcc's internal representation.  That makes it
    hard to tell where the constant ends, and hard to dump the
    constant in any readable form anyhow.  We don't attempt to
    handle these cases.  */

    t = DEMANGLE_COMPONENT_LITERAL;
    if (d_peek_char (di) == 'n')
    {
    t = DEMANGLE_COMPONENT_LITERAL_NEG;
    d_advance (di, 1);
    }
    s = d_str (di);
    while (d_peek_char (di) != 'E')
    {
    if (d_peek_char (di) == '\0')
        return nullptr;
    d_advance (di, 1);
    }
    ret = d_make_comp (di, t, type, d_make_name (di, s, d_str (di) - s));
    }
if (! d_check_char (di, 'E'))
    return nullptr;
return ret;
}

/* <local-name> ::= Z <(function) encoding> E <(entity) name> [<discriminator>]
                ::= Z <(function) encoding> E s [<discriminator>]
                ::= Z <(function) encoding> E d [<parameter> number>] _ <entity name>
*/

static struct demangle_component *
d_local_name (struct d_info *di)
{
struct demangle_component *function;
struct demangle_component *name;

if (! d_check_char (di, 'Z'))
    return nullptr;

function = d_encoding (di, 0);
if (!function)
    return nullptr;

if (! d_check_char (di, 'E'))
    return nullptr;

if (d_peek_char (di) == 's')
    {
    d_advance (di, 1);
    if (! d_discriminator (di))
    return nullptr;
    name = d_make_name (di, "string literal", sizeof "string literal" - 1);
    }
else
    {
    int num = -1;

    if (d_peek_char (di) == 'd')
    {
    /* Default argument scope: d <number> _.  */
    d_advance (di, 1);
    num = d_compact_number (di);
    if (num < 0)
        return nullptr;
    }

    name = d_name (di, 0);

    if (name
    /* Lambdas and unnamed types have internal discriminators
        and are not functions.  */
    && name->type != DEMANGLE_COMPONENT_LAMBDA
    && name->type != DEMANGLE_COMPONENT_UNNAMED_TYPE)
    {
    /* Read and ignore an optional discriminator.  */
    if (! d_discriminator (di))
        return nullptr;
    }

    if (num >= 0)
    name = d_make_default_arg (di, num, name);
    }

/* Elide the return type of the containing function so as to not
    confuse the user thinking it is the return type of whatever local
    function we might be containing.  */
if (function->type == DEMANGLE_COMPONENT_TYPED_NAME
    && d_right (function)->type == DEMANGLE_COMPONENT_FUNCTION_TYPE)
    d_left (d_right (function)) = nullptr;

return d_make_comp (di, DEMANGLE_COMPONENT_LOCAL_NAME, function, name);
}

/* <discriminator> ::= _ <number>    # when number < 10
                ::= __ <number> _ # when number >= 10

<discriminator> ::= _ <number>    # when number >=10
is also accepted to support gcc versions that wrongly mangled that way.

We demangle the discriminator, but we don't print it out.  FIXME:
We should print it out in verbose mode.  */

static int
d_discriminator (struct d_info *di)
{
int discrim, num_underscores = 1;

if (d_peek_char (di) != '_')
    return 1;
d_advance (di, 1);
if (d_peek_char (di) == '_')
    {
    ++num_underscores;
    d_advance (di, 1);
    }

discrim = d_number (di);
if (discrim < 0)
    return 0;
if (num_underscores > 1 && discrim >= 10)
    {
    if (d_peek_char (di) == '_')
    d_advance (di, 1);
    else
    return 0;
    }

return 1;
}

/* <template-parm> ::= Ty
                ::= Tn <type>
        ::= Tt <template-head> E
        ::= Tp <template-parm>  */

static struct demangle_component *
d_template_parm (struct d_info *di, int *bad)
{
if (d_peek_char (di) != 'T')
    return nullptr;

struct demangle_component *op;
enum demangle_component_type kind;
switch (d_peek_next_char (di))
    {
    default:
    return nullptr;

    case 'p': /* Pack  */
    d_advance (di, 2);
    op = d_template_parm (di, bad);
    kind = DEMANGLE_COMPONENT_TEMPLATE_PACK_PARM;
    if (!op)
    {
    *bad = 1;
    return nullptr;
    }
    break;

    case 'y': /* Typename  */
    d_advance (di, 2);
    op = nullptr;
    kind = DEMANGLE_COMPONENT_TEMPLATE_TYPE_PARM;
    break;

    case 'n': /* Non-Type  */
    d_advance (di, 2);
    op = cplus_demangle_type (di);
    kind = DEMANGLE_COMPONENT_TEMPLATE_NON_TYPE_PARM;
    if (!op)
    {
    *bad = 1;
    return nullptr;
    }
    break;

    case 't': /* Template */
    d_advance (di, 2);
    op = d_template_head (di, bad);
    kind = DEMANGLE_COMPONENT_TEMPLATE_TEMPLATE_PARM;
    if (!op || !d_check_char (di, 'E'))
    {
    *bad = 1;
    return nullptr;
    }
    }

return d_make_comp (di, kind, op, nullptr);
}

/* <template-head> ::= <template-head>? <template-parm>  */

static struct demangle_component *
d_template_head (struct d_info *di, int *bad)
{
struct demangle_component *res = nullptr, **slot = &res;
struct demangle_component *op;

while ((op = d_template_parm (di, bad)))
    {
    *slot = op;
    slot = &d_right (op);
    }

/* Wrap it in a template head, to make concatenating with any parm list, and
    printing simpler.  */
if (res)
    res = d_make_comp (di, DEMANGLE_COMPONENT_TEMPLATE_HEAD, res, nullptr);

return res;
}

/* <closure-type-name> ::= Ul <template-head>? <lambda-sig> E [ <nonnegative number> ] _ */

static struct demangle_component *
d_lambda (struct d_info *di)
{
if (! d_check_char (di, 'U'))
    return nullptr;
if (! d_check_char (di, 'l'))
    return nullptr;

int bad = 0;
struct demangle_component *head = d_template_head (di, &bad);
if (bad)
    return nullptr;

struct demangle_component *tl = d_parmlist (di);
if (tl == nullptr)
    return nullptr;
if (head)
    {
    d_right (head) = tl;
    tl = head;
    }

if (! d_check_char (di, 'E'))
    return nullptr;

int num = d_compact_number (di);
if (num < 0)
    return nullptr;

struct demangle_component *ret = d_make_empty (di);
if (ret)
    {
    ret->type = DEMANGLE_COMPONENT_LAMBDA;
    ret->u.s_unary_num.sub = tl;
    ret->u.s_unary_num.num = num;
    }

return ret;
}

/* <unnamed-type-name> ::= Ut [ <nonnegative number> ] _ */

static struct demangle_component *
d_unnamed_type (struct d_info *di)
{
struct demangle_component *ret;
int num;

if (! d_check_char (di, 'U'))
    return nullptr;
if (! d_check_char (di, 't'))
    return nullptr;

num = d_compact_number (di);
if (num < 0)
    return nullptr;

ret = d_make_empty (di);
if (ret)
    {
    ret->type = DEMANGLE_COMPONENT_UNNAMED_TYPE;
    ret->u.s_number.number = num;
    }

if (! d_add_substitution (di, ret))
    return nullptr;

return ret;
}

/* <clone-suffix> ::= [ . <clone-type-identifier> ] [ . <nonnegative number> ]*
*/

static struct demangle_component *
d_clone_suffix (struct d_info *di, struct demangle_component *encoding)
{
const char *suffix = d_str (di);
const char *pend = suffix;
struct demangle_component *n;

if (*pend == '.' && (IS_LOWER (pend[1]) || IS_DIGIT (pend[1])
            || pend[1] == '_'))
    {
    pend += 2;
    while (IS_LOWER (*pend) || IS_DIGIT (*pend) || *pend == '_')
    ++pend;
    }
while (*pend == '.' && IS_DIGIT (pend[1]))
    {
    pend += 2;
    while (IS_DIGIT (*pend))
    ++pend;
    }
d_advance (di, pend - suffix);
n = d_make_name (di, suffix, pend - suffix);
return d_make_comp (di, DEMANGLE_COMPONENT_CLONE, encoding, n);
}

/* Add a new substitution.  */

static int
d_add_substitution (struct d_info *di, struct demangle_component *dc)
{
if (dc == nullptr)
    return 0;
if (di->next_sub >= di->num_subs)
    return 0;
di->subs[di->next_sub] = dc;
++di->next_sub;
return 1;
}

/* <substitution> ::= S <seq-id> _
                ::= S_
                ::= St
                ::= Sa
                ::= Sb
                ::= Ss
                ::= Si
                ::= So
                ::= Sd

If PREFIX is non-zero, then this type is being used as a prefix in
a qualified name.  In this case, for the standard substitutions, we
need to check whether we are being used as a prefix for a
constructor or destructor, and return a full template name.
Otherwise we will get something like std::iostream::~iostream()
which does not correspond particularly well to any function which
actually appears in the source.
*/

static const struct d_standard_sub_info standard_subs[] =
{
{ 't', NL ("std"),
    NL ("std"),
    nullptr, 0 },
{ 'a', NL ("std::allocator"),
    NL ("std::allocator"),
    NL ("allocator") },
{ 'b', NL ("std::basic_string"),
    NL ("std::basic_string"),
    NL ("basic_string") },
{ 's', NL ("std::string"),
    NL ("std::basic_string<char, std::char_traits<char>, std::allocator<char> >"),
    NL ("basic_string") },
{ 'i', NL ("std::istream"),
    NL ("std::basic_istream<char, std::char_traits<char> >"),
    NL ("basic_istream") },
{ 'o', NL ("std::ostream"),
    NL ("std::basic_ostream<char, std::char_traits<char> >"),
    NL ("basic_ostream") },
{ 'd', NL ("std::iostream"),
    NL ("std::basic_iostream<char, std::char_traits<char> >"),
    NL ("basic_iostream") }
};

static struct demangle_component *
d_substitution (struct d_info *di, int prefix)
{
char c;

if (! d_check_char (di, 'S'))
    return nullptr;

c = d_next_char (di);
if (c == '_' || IS_DIGIT (c) || IS_UPPER (c))
    {
    unsigned int id;

    id = 0;
    if (c != '_')
    {
    do
        {
        unsigned int new_id;

        if (IS_DIGIT (c))
        new_id = id * 36 + c - '0';
        else if (IS_UPPER (c))
        new_id = id * 36 + c - 'A' + 10;
        else
        return nullptr;
        if (new_id < id)
        return nullptr;
        id = new_id;
        c = d_next_char (di);
        }
    while (c != '_');

    ++id;
    }

    if (id >= (unsigned int) di->next_sub)
    return nullptr;

    return di->subs[id];
    }
else
    {
    int verbose;
    const struct d_standard_sub_info *p;
    const struct d_standard_sub_info *pend;

    verbose = (di->options & DMGL_VERBOSE) != 0;
    if (! verbose && prefix)
    {
    char peek;

    peek = d_peek_char (di);
    if (peek == 'C' || peek == 'D')
        verbose = 1;
    }

    pend = (&standard_subs[0]
        + sizeof standard_subs / sizeof standard_subs[0]);
    for (p = &standard_subs[0]; p < pend; ++p)
    {
    if (c == p->code)
        {
        const char *s;
        int len;
        struct demangle_component *dc;

        if (p->set_last_name != nullptr)
        di->last_name = d_make_sub (di, p->set_last_name,
                        p->set_last_name_len);
        if (verbose)
        {
        s = p->full_expansion;
        len = p->full_len;
        }
        else
        {
        s = p->simple_expansion;
        len = p->simple_len;
        }
        di->expansion += len;
        dc = d_make_sub (di, s, len);
        if (d_peek_char (di) == 'B')
        {
        /* If there are ABI tags on the abbreviation, it becomes
            a substitution candidate.  */
        dc = d_abi_tags (di, dc);
        if (! d_add_substitution (di, dc))
            return nullptr;
        }
        return dc;
        }
    }

    return nullptr;
    }
}

static void
d_checkpoint (struct d_info *di, struct d_info_checkpoint *checkpoint)
{
checkpoint->n = di->n;
checkpoint->next_comp = di->next_comp;
checkpoint->next_sub = di->next_sub;
checkpoint->expansion = di->expansion;
}

static void
d_backtrack (struct d_info *di, struct d_info_checkpoint *checkpoint)
{
di->n = checkpoint->n;
di->next_comp = checkpoint->next_comp;
di->next_sub = checkpoint->next_sub;
di->expansion = checkpoint->expansion;
}

/* Initialize a growable string.  */

static void
d_growable_string_init (struct d_growable_string *dgs, size_t estimate)
{
dgs->buf = nullptr;
dgs->len = 0;
dgs->alc = 0;
dgs->allocation_failure = 0;

if (estimate > 0)
    d_growable_string_resize (dgs, estimate);
}

/* Grow a growable string to a given size.  */

static inline void
d_growable_string_resize (struct d_growable_string *dgs, size_t need)
{
size_t newalc;
char *newbuf;

if (dgs->allocation_failure)
    return;

/* Start allocation at two bytes to avoid any possibility of confusion
    with the special value of 1 used as a return in *palc to indicate
    allocation failures.  */
newalc = dgs->alc > 0 ? dgs->alc : 2;
while (newalc < need)
    newalc <<= 1;

newbuf = (char *) realloc (dgs->buf, newalc);
if (newbuf == nullptr)
    {
    free (dgs->buf);
    dgs->buf = nullptr;
    dgs->len = 0;
    dgs->alc = 0;
    dgs->allocation_failure = 1;
    return;
    }
dgs->buf = newbuf;
dgs->alc = newalc;
}

/* Append a buffer to a growable string.  */

static inline void
d_growable_string_append_buffer (struct d_growable_string *dgs,
                                const char *s, size_t l)
{
size_t need;

need = dgs->len + l + 1;
if (need > dgs->alc)
    d_growable_string_resize (dgs, need);

if (dgs->allocation_failure)
    return;

std::memcpy (dgs->buf + dgs->len, s, l);
dgs->buf[dgs->len + l] = '\0';
dgs->len += l;
}

/* Bridge growable strings to the callback mechanism.  */

static void
d_growable_string_callback_adapter (const char *s, size_t l, void *opaque)
{
struct d_growable_string *dgs = (struct d_growable_string*) opaque;

d_growable_string_append_buffer (dgs, s, l);
}

/* Walk the tree, counting the number of templates encountered, and
the number of times a scope might be saved.  These counts will be
used to allocate data structures for d_print_comp, so the logic
here must mirror the logic d_print_comp will use.  It is not
important that the resulting numbers are exact, so long as they
are larger than the actual numbers encountered.  */

static void
d_count_templates_scopes (struct d_print_info *dpi,
            struct demangle_component *dc)
{
if (dc == nullptr || dc->d_counting > 1 || dpi->recursion > MAX_RECURSION_COUNT)
    return;

++ dc->d_counting;

switch (dc->type)
    {
    case DEMANGLE_COMPONENT_NAME:
    case DEMANGLE_COMPONENT_TEMPLATE_PARAM:
    case DEMANGLE_COMPONENT_FUNCTION_PARAM:
    case DEMANGLE_COMPONENT_SUB_STD:
    case DEMANGLE_COMPONENT_BUILTIN_TYPE:
    case DEMANGLE_COMPONENT_EXTENDED_BUILTIN_TYPE:
    case DEMANGLE_COMPONENT_OPERATOR:
    case DEMANGLE_COMPONENT_CHARACTER:
    case DEMANGLE_COMPONENT_NUMBER:
    case DEMANGLE_COMPONENT_UNNAMED_TYPE:
    case DEMANGLE_COMPONENT_STRUCTURED_BINDING:
    case DEMANGLE_COMPONENT_MODULE_NAME:
    case DEMANGLE_COMPONENT_MODULE_PARTITION:
    case DEMANGLE_COMPONENT_MODULE_INIT:
    case DEMANGLE_COMPONENT_FIXED_TYPE:
    case DEMANGLE_COMPONENT_TEMPLATE_HEAD:
    case DEMANGLE_COMPONENT_TEMPLATE_TYPE_PARM:
    case DEMANGLE_COMPONENT_TEMPLATE_NON_TYPE_PARM:
    case DEMANGLE_COMPONENT_TEMPLATE_TEMPLATE_PARM:
    case DEMANGLE_COMPONENT_TEMPLATE_PACK_PARM:
    break;

    case DEMANGLE_COMPONENT_TEMPLATE:
    dpi->num_copy_templates++;
    goto recurse_left_right;

    case DEMANGLE_COMPONENT_REFERENCE:
    case DEMANGLE_COMPONENT_RVALUE_REFERENCE:
    if (d_left (dc)->type == DEMANGLE_COMPONENT_TEMPLATE_PARAM)
    dpi->num_saved_scopes++;
    goto recurse_left_right;

    case DEMANGLE_COMPONENT_QUAL_NAME:
    case DEMANGLE_COMPONENT_LOCAL_NAME:
    case DEMANGLE_COMPONENT_TYPED_NAME:
    case DEMANGLE_COMPONENT_VTABLE:
    case DEMANGLE_COMPONENT_VTT:
    case DEMANGLE_COMPONENT_CONSTRUCTION_VTABLE:
    case DEMANGLE_COMPONENT_TYPEINFO:
    case DEMANGLE_COMPONENT_TYPEINFO_NAME:
    case DEMANGLE_COMPONENT_TYPEINFO_FN:
    case DEMANGLE_COMPONENT_THUNK:
    case DEMANGLE_COMPONENT_VIRTUAL_THUNK:
    case DEMANGLE_COMPONENT_COVARIANT_THUNK:
    case DEMANGLE_COMPONENT_JAVA_CLASS:
    case DEMANGLE_COMPONENT_GUARD:
    case DEMANGLE_COMPONENT_TLS_INIT:
    case DEMANGLE_COMPONENT_TLS_WRAPPER:
    case DEMANGLE_COMPONENT_REFTEMP:
    case DEMANGLE_COMPONENT_HIDDEN_ALIAS:
    case DEMANGLE_COMPONENT_RESTRICT:
    case DEMANGLE_COMPONENT_VOLATILE:
    case DEMANGLE_COMPONENT_CONST:
    case DEMANGLE_COMPONENT_RESTRICT_THIS:
    case DEMANGLE_COMPONENT_VOLATILE_THIS:
    case DEMANGLE_COMPONENT_CONST_THIS:
    case DEMANGLE_COMPONENT_REFERENCE_THIS:
    case DEMANGLE_COMPONENT_RVALUE_REFERENCE_THIS:
    case DEMANGLE_COMPONENT_XOBJ_MEMBER_FUNCTION:
    case DEMANGLE_COMPONENT_TRANSACTION_SAFE:
    case DEMANGLE_COMPONENT_NOEXCEPT:
    case DEMANGLE_COMPONENT_THROW_SPEC:
    case DEMANGLE_COMPONENT_VENDOR_TYPE_QUAL:
    case DEMANGLE_COMPONENT_POINTER:
    case DEMANGLE_COMPONENT_COMPLEX:
    case DEMANGLE_COMPONENT_IMAGINARY:
    case DEMANGLE_COMPONENT_VENDOR_TYPE:
    case DEMANGLE_COMPONENT_FUNCTION_TYPE:
    case DEMANGLE_COMPONENT_ARRAY_TYPE:
    case DEMANGLE_COMPONENT_PTRMEM_TYPE:
    case DEMANGLE_COMPONENT_VECTOR_TYPE:
    case DEMANGLE_COMPONENT_ARGLIST:
    case DEMANGLE_COMPONENT_TEMPLATE_ARGLIST:
    case DEMANGLE_COMPONENT_TPARM_OBJ:
    case DEMANGLE_COMPONENT_INITIALIZER_LIST:
    case DEMANGLE_COMPONENT_CAST:
    case DEMANGLE_COMPONENT_CONVERSION:
    case DEMANGLE_COMPONENT_NULLARY:
    case DEMANGLE_COMPONENT_UNARY:
    case DEMANGLE_COMPONENT_BINARY:
    case DEMANGLE_COMPONENT_BINARY_ARGS:
    case DEMANGLE_COMPONENT_TRINARY:
    case DEMANGLE_COMPONENT_TRINARY_ARG1:
    case DEMANGLE_COMPONENT_TRINARY_ARG2:
    case DEMANGLE_COMPONENT_LITERAL:
    case DEMANGLE_COMPONENT_LITERAL_NEG:
    case DEMANGLE_COMPONENT_VENDOR_EXPR:
    case DEMANGLE_COMPONENT_JAVA_RESOURCE:
    case DEMANGLE_COMPONENT_COMPOUND_NAME:
    case DEMANGLE_COMPONENT_DECLTYPE:
    case DEMANGLE_COMPONENT_TRANSACTION_CLONE:
    case DEMANGLE_COMPONENT_NONTRANSACTION_CLONE:
    case DEMANGLE_COMPONENT_PACK_EXPANSION:
    case DEMANGLE_COMPONENT_TAGGED_NAME:
    case DEMANGLE_COMPONENT_CLONE:
    case DEMANGLE_COMPONENT_CONSTRAINTS:
    recurse_left_right:
    /* PR 89394 - Check for too much recursion.  */
    if (dpi->recursion > DEMANGLE_RECURSION_LIMIT)
    /* FIXME: There ought to be a way to report to the
    user that the recursion limit has been reached.  */
    return;

    ++ dpi->recursion;
    d_count_templates_scopes (dpi, d_left (dc));
    d_count_templates_scopes (dpi, d_right (dc));
    -- dpi->recursion;
    break;

    case DEMANGLE_COMPONENT_CTOR:
    d_count_templates_scopes (dpi, dc->u.s_ctor.name);
    break;

    case DEMANGLE_COMPONENT_DTOR:
    d_count_templates_scopes (dpi, dc->u.s_dtor.name);
    break;

    case DEMANGLE_COMPONENT_EXTENDED_OPERATOR:
    d_count_templates_scopes (dpi, dc->u.s_extended_operator.name);
    break;

    case DEMANGLE_COMPONENT_GLOBAL_CONSTRUCTORS:
    case DEMANGLE_COMPONENT_GLOBAL_DESTRUCTORS:
    case DEMANGLE_COMPONENT_MODULE_ENTITY:
    case DEMANGLE_COMPONENT_FRIEND:
    d_count_templates_scopes (dpi, d_left (dc));
    break;

    case DEMANGLE_COMPONENT_LAMBDA:
    case DEMANGLE_COMPONENT_DEFAULT_ARG:
    d_count_templates_scopes (dpi, dc->u.s_unary_num.sub);
    break;
    }
}

/* Initialize a print information structure.  */

static void
d_print_init (struct d_print_info *dpi, demangle_callbackref callback,
        void *opaque, struct demangle_component *dc)
{
dpi->len = 0;
dpi->last_char = '\0';
dpi->templates = nullptr;
dpi->modifiers = nullptr;
dpi->pack_index = 0;
dpi->flush_count = 0;

dpi->callback = callback;
dpi->opaque = opaque;

dpi->demangle_failure = 0;
dpi->recursion = 0;
dpi->lambda_tpl_parms = 0;

dpi->component_stack = nullptr;

dpi->saved_scopes = nullptr;
dpi->next_saved_scope = 0;
dpi->num_saved_scopes = 0;

dpi->copy_templates = nullptr;
dpi->next_copy_template = 0;
dpi->num_copy_templates = 0;

d_count_templates_scopes (dpi, dc);
/* If we did not reach the recursion limit, then reset the
    current recursion value back to 0, so that we can print
    the templates.  */
if (dpi->recursion < DEMANGLE_RECURSION_LIMIT)
    dpi->recursion = 0;
dpi->num_copy_templates *= dpi->num_saved_scopes;

dpi->current_template = nullptr;
}

/* Indicate that an error occurred during printing, and test for error.  */

static inline void
d_print_error (struct d_print_info *dpi)
{
dpi->demangle_failure = 1;
}

static inline int
d_print_saw_error (struct d_print_info *dpi)
{
return dpi->demangle_failure != 0;
}

/* Flush buffered characters to the callback.  */

static inline void
d_print_flush (struct d_print_info *dpi)
{
dpi->buf[dpi->len] = '\0';
dpi->callback (dpi->buf, dpi->len, dpi->opaque);
dpi->len = 0;
dpi->flush_count++;
}

/* Append characters and buffers for printing.  */

static inline void
d_append_char (struct d_print_info *dpi, char c)
{
if (dpi->len == sizeof (dpi->buf) - 1)
    d_print_flush (dpi);

dpi->buf[dpi->len++] = c;
dpi->last_char = c;
}

static inline void
d_append_buffer (struct d_print_info *dpi, const char *s, size_t l)
{
size_t i;

for (i = 0; i < l; i++)
    d_append_char (dpi, s[i]);
}

static inline void
d_append_string (struct d_print_info *dpi, const char *s)
{
d_append_buffer (dpi, s, std::strlen (s));
}

static inline void
d_append_num (struct d_print_info *dpi, int l)
{
    char buf[25];
    auto size = sprint(buf, "{}", l);
    d_append_buffer (dpi, buf, size);
}

static inline char
d_last_char (struct d_print_info *dpi)
{
return dpi->last_char;
}

/* Turn components into a human readable string.  OPTIONS is the
options bits passed to the demangler.  DC is the tree to print.
CALLBACK is a function to call to flush demangled string segments
as they fill the intermediate buffer, and OPAQUE is a generalized
callback argument.  On success, this returns 1.  On failure,
it returns 0, indicating a bad parse.  It does not use heap
memory to build an output string, so cannot encounter memory
allocation failure.  */

static
int
cplus_demangle_print_callback (int options,
                            struct demangle_component *dc,
                            demangle_callbackref callback, void *opaque)
{
struct d_print_info dpi;

d_print_init (&dpi, callback, opaque, dc);

{
    /* Avoid zero-length VLAs, which are prohibited by the C99 standard
    and flagged as errors by Address Sanitizer.  */
    __extension__ struct d_saved_scope scopes[(dpi.num_saved_scopes > 0)
                                            ? dpi.num_saved_scopes : 1];
    __extension__ struct d_print_template temps[(dpi.num_copy_templates > 0)
                                                ? dpi.num_copy_templates : 1];

    dpi.saved_scopes = scopes;
    dpi.copy_templates = temps;

    d_print_comp (&dpi, options, dc);
}

d_print_flush (&dpi);

return ! d_print_saw_error (&dpi);
}

/* Turn components into a human readable string.  OPTIONS is the
options bits passed to the demangler.  DC is the tree to print.
ESTIMATE is a guess at the length of the result.  This returns a
string allocated by malloc, or nullptr on error.  On success, this
sets *PALC to the size of the allocated buffer.  On failure, this
sets *PALC to 0 for a bad parse, or to 1 for a memory allocation
failure.  */

static
char *
cplus_demangle_print (int options, struct demangle_component *dc,
                    int estimate, size_t *palc)
{
struct d_growable_string dgs;

d_growable_string_init (&dgs, estimate);

if (! cplus_demangle_print_callback (options, dc,
                                    d_growable_string_callback_adapter,
                                    &dgs))
    {
    free (dgs.buf);
    *palc = 0;
    return nullptr;
    }

*palc = dgs.allocation_failure ? 1 : dgs.alc;
return dgs.buf;
}

/* Returns the I'th element of the template arglist ARGS, or nullptr on
failure.  If I is negative, return the entire arglist.  */

static struct demangle_component *
d_index_template_argument (struct demangle_component *args, int i)
{
struct demangle_component *a;

if (i < 0)
    /* Print the whole argument pack.  */
    return args;

for (a = args;
    a != nullptr;
    a = d_right (a))
    {
    if (a->type != DEMANGLE_COMPONENT_TEMPLATE_ARGLIST)
    return nullptr;
    if (i <= 0)
    break;
    --i;
    }
if (i != 0 || a == nullptr)
    return nullptr;

return d_left (a);
}

/* Returns the template argument from the current context indicated by DC,
which is a DEMANGLE_COMPONENT_TEMPLATE_PARAM, or nullptr.  */

static struct demangle_component *
d_lookup_template_argument (struct d_print_info *dpi,
                const struct demangle_component *dc)
{
if (dpi->templates == nullptr)
    {
    d_print_error (dpi);
    return nullptr;
    }
    
return d_index_template_argument
    (d_right (dpi->templates->template_decl),
    dc->u.s_number.number);
}

/* Returns a template argument pack used in DC (any will do), or nullptr.  */

static struct demangle_component *
d_find_pack (struct d_print_info *dpi,
        const struct demangle_component *dc)
{
struct demangle_component *a;
if (dc == nullptr)
    return nullptr;

switch (dc->type)
    {
    case DEMANGLE_COMPONENT_TEMPLATE_PARAM:
    a = d_lookup_template_argument (dpi, dc);
    if (a && a->type == DEMANGLE_COMPONENT_TEMPLATE_ARGLIST)
    return a;
    return nullptr;

    case DEMANGLE_COMPONENT_PACK_EXPANSION:
    return nullptr;
    
    case DEMANGLE_COMPONENT_LAMBDA:
    case DEMANGLE_COMPONENT_NAME:
    case DEMANGLE_COMPONENT_TAGGED_NAME:
    case DEMANGLE_COMPONENT_OPERATOR:
    case DEMANGLE_COMPONENT_BUILTIN_TYPE:
    case DEMANGLE_COMPONENT_EXTENDED_BUILTIN_TYPE:
    case DEMANGLE_COMPONENT_SUB_STD:
    case DEMANGLE_COMPONENT_CHARACTER:
    case DEMANGLE_COMPONENT_FUNCTION_PARAM:
    case DEMANGLE_COMPONENT_UNNAMED_TYPE:
    case DEMANGLE_COMPONENT_DEFAULT_ARG:
    case DEMANGLE_COMPONENT_NUMBER:
    return nullptr;

    case DEMANGLE_COMPONENT_EXTENDED_OPERATOR:
    return d_find_pack (dpi, dc->u.s_extended_operator.name);
    case DEMANGLE_COMPONENT_CTOR:
    return d_find_pack (dpi, dc->u.s_ctor.name);
    case DEMANGLE_COMPONENT_DTOR:
    return d_find_pack (dpi, dc->u.s_dtor.name);

    default:
    a = d_find_pack (dpi, d_left (dc));
    if (a)
    return a;
    return d_find_pack (dpi, d_right (dc));
    }
}

/* Returns the length of the template argument pack DC.  */

static int
d_pack_length (const struct demangle_component *dc)
{
int count = 0;
while (dc && dc->type == DEMANGLE_COMPONENT_TEMPLATE_ARGLIST
    && d_left (dc) != nullptr)
    {
    ++count;
    dc = d_right (dc);
    }
return count;
}

/* Returns the number of template args in DC, expanding any pack expansions
found there.  */

static int
d_args_length (struct d_print_info *dpi, const struct demangle_component *dc)
{
int count = 0;
for (; dc && dc->type == DEMANGLE_COMPONENT_TEMPLATE_ARGLIST;
    dc = d_right (dc))
    {
    struct demangle_component *elt = d_left (dc);
    if (elt == nullptr)
    break;
    if (elt->type == DEMANGLE_COMPONENT_PACK_EXPANSION)
    {
    struct demangle_component *a = d_find_pack (dpi, d_left (elt));
    count += d_pack_length (a);
    }
    else
    ++count;
    }
return count;
}

/* DC is a component of a mangled expression.  Print it, wrapped in parens
if needed.  */

static void
d_print_subexpr (struct d_print_info *dpi, int options,
        struct demangle_component *dc)
{
int simple = 0;
if (dc->type == DEMANGLE_COMPONENT_NAME
    || dc->type == DEMANGLE_COMPONENT_QUAL_NAME
    || dc->type == DEMANGLE_COMPONENT_INITIALIZER_LIST
    || dc->type == DEMANGLE_COMPONENT_FUNCTION_PARAM)
    simple = 1;
if (!simple)
    d_append_char (dpi, '(');
d_print_comp (dpi, options, dc);
if (!simple)
    d_append_char (dpi, ')');
}

/* Save the current scope.  */

static void
d_save_scope (struct d_print_info *dpi,
        const struct demangle_component *container)
{
struct d_saved_scope *scope;
struct d_print_template *src, **link;

if (dpi->next_saved_scope >= dpi->num_saved_scopes)
    {
    d_print_error (dpi);
    return;
    }
scope = &dpi->saved_scopes[dpi->next_saved_scope];
dpi->next_saved_scope++;

scope->container = container;
link = &scope->templates;

for (src = dpi->templates; src != nullptr; src = src->next)
    {
    struct d_print_template *dst;

    if (dpi->next_copy_template >= dpi->num_copy_templates)
    {
    d_print_error (dpi);
    return;
    }
    dst = &dpi->copy_templates[dpi->next_copy_template];
    dpi->next_copy_template++;

    dst->template_decl = src->template_decl;
    *link = dst;
    link = &dst->next;
    }

*link = nullptr;
}

/* Attempt to locate a previously saved scope.  Returns nullptr if no
corresponding saved scope was found.  */

static struct d_saved_scope *
d_get_saved_scope (struct d_print_info *dpi,
        const struct demangle_component *container)
{
int i;

for (i = 0; i < dpi->next_saved_scope; i++)
    if (dpi->saved_scopes[i].container == container)
    return &dpi->saved_scopes[i];

return nullptr;
}

/* If DC is a C++17 fold-expression, print it and return true; otherwise
return false.  */

static int
d_maybe_print_fold_expression (struct d_print_info *dpi, int options,
                struct demangle_component *dc)
{
struct demangle_component *ops, *operator_, *op1, *op2;
int save_idx;

const char *fold_code = d_left (dc)->u.s_operator.op->code;
if (fold_code[0] != 'f')
    return 0;

ops = d_right (dc);
operator_ = d_left (ops);
op1 = d_right (ops);
op2 = 0;
if (op1->type == DEMANGLE_COMPONENT_TRINARY_ARG2)
    {
    op2 = d_right (op1);
    op1 = d_left (op1);
    }

/* Print the whole pack.  */
save_idx = dpi->pack_index;
dpi->pack_index = -1;

switch (fold_code[1])
    {
    /* Unary left fold, (... + X).  */
    case 'l':
    d_append_string (dpi, "(...");
    d_print_expr_op (dpi, options, operator_);
    d_print_subexpr (dpi, options, op1);
    d_append_char (dpi, ')');
    break;

    /* Unary right fold, (X + ...).  */
    case 'r':
    d_append_char (dpi, '(');
    d_print_subexpr (dpi, options, op1);
    d_print_expr_op (dpi, options, operator_);
    d_append_string (dpi, "...)");
    break;

    /* Binary left fold, (42 + ... + X).  */
    case 'L':
    /* Binary right fold, (X + ... + 42).  */
    case 'R':
    d_append_char (dpi, '(');
    d_print_subexpr (dpi, options, op1);
    d_print_expr_op (dpi, options, operator_);
    d_append_string (dpi, "...");
    d_print_expr_op (dpi, options, operator_);
    d_print_subexpr (dpi, options, op2);
    d_append_char (dpi, ')');
    break;
    }

dpi->pack_index = save_idx;
return 1;
}

/* True iff DC represents a C99-style designated initializer.  */

static int
is_designated_init (struct demangle_component *dc)
{
if (dc->type != DEMANGLE_COMPONENT_BINARY
    && dc->type != DEMANGLE_COMPONENT_TRINARY)
    return 0;

struct demangle_component *op = d_left (dc);
const char *code = op->u.s_operator.op->code;
return (code[0] == 'd'
    && (code[1] == 'i' || code[1] == 'x' || code[1] == 'X'));
}

/* If DC represents a C99-style designated initializer, print it and return
true; otherwise, return false.  */

static int
d_maybe_print_designated_init (struct d_print_info *dpi, int options,
                struct demangle_component *dc)
{
if (!is_designated_init (dc))
    return 0;

const char *code = d_left (dc)->u.s_operator.op->code;

struct demangle_component *operands = d_right (dc);
struct demangle_component *op1 = d_left (operands);
struct demangle_component *op2 = d_right (operands);

if (code[1] == 'i')
    d_append_char (dpi, '.');
else
    d_append_char (dpi, '[');

d_print_comp (dpi, options, op1);
if (code[1] == 'X')
    {
    d_append_string (dpi, " ... ");
    d_print_comp (dpi, options, d_left (op2));
    op2 = d_right (op2);
    }
if (code[1] != 'i')
    d_append_char (dpi, ']');
if (is_designated_init (op2))
    {
    /* Don't put '=' or '(' between chained designators.  */
    d_print_comp (dpi, options, op2);
    }
else
    {
    d_append_char (dpi, '=');
    d_print_subexpr (dpi, options, op2);
    }
return 1;
}

static void
d_print_lambda_parm_name (struct d_print_info *dpi, int type, unsigned index)
{
const char *str;
switch (type)
    {
    default:
    dpi->demangle_failure = 1;
    str = "";
    break;

    case DEMANGLE_COMPONENT_TEMPLATE_TYPE_PARM:
    str = "$T";
    break;

    case DEMANGLE_COMPONENT_TEMPLATE_NON_TYPE_PARM:
    str = "$N";
    break;

    case DEMANGLE_COMPONENT_TEMPLATE_TEMPLATE_PARM:
    str = "$TT";
    break;
    }
d_append_string (dpi, str);
d_append_num (dpi, index);
}

/* Subroutine to handle components.  */

static void
d_print_comp_inner (struct d_print_info *dpi, int options,
            struct demangle_component *dc)
{
/* Magic variable to let reference smashing skip over the next modifier
    without needing to modify *dc.  */
struct demangle_component *mod_inner = nullptr;

/* Variable used to store the current templates while a previously
    captured scope is used.  */
struct d_print_template *saved_templates;

/* Nonzero if templates have been stored in the above variable.  */
int need_template_restore = 0;

if (dc == nullptr)
    {
    d_print_error (dpi);
    return;
    }
if (d_print_saw_error (dpi))
    return;

switch (dc->type)
    {
    case DEMANGLE_COMPONENT_NAME:
    if ((options & DMGL_JAVA) == 0)
    d_append_buffer (dpi, dc->u.s_name.s, dc->u.s_name.len);
    else
    d_print_java_identifier (dpi, dc->u.s_name.s, dc->u.s_name.len);
    return;

    case DEMANGLE_COMPONENT_TAGGED_NAME:
    d_print_comp (dpi, options, d_left (dc));
    d_append_string (dpi, "[abi:");
    d_print_comp (dpi, options, d_right (dc));
    d_append_char (dpi, ']');
    return;

    case DEMANGLE_COMPONENT_STRUCTURED_BINDING:
    d_append_char (dpi, '[');
    for (;;)
    {
    d_print_comp (dpi, options, d_left (dc));
    dc = d_right (dc);
    if (!dc)
        break;
    d_append_string (dpi, ", ");
    }
    d_append_char (dpi, ']');
    return;

    case DEMANGLE_COMPONENT_MODULE_ENTITY:
    d_print_comp (dpi, options, d_left (dc));
    d_append_char (dpi, '@');
    d_print_comp (dpi, options, d_right (dc));
    return;

    case DEMANGLE_COMPONENT_MODULE_NAME:
    case DEMANGLE_COMPONENT_MODULE_PARTITION:
    {
    if (d_left (dc))
    d_print_comp (dpi, options, d_left (dc));
    char c = dc->type == DEMANGLE_COMPONENT_MODULE_PARTITION
    ? ':' : d_left (dc) ? '.' : 0;
    if (c)
    d_append_char (dpi, c);
    d_print_comp (dpi, options, d_right (dc));
    }
    return;

    case DEMANGLE_COMPONENT_QUAL_NAME:
    case DEMANGLE_COMPONENT_LOCAL_NAME:
    d_print_comp (dpi, options, d_left (dc));
    if ((options & DMGL_JAVA) == 0)
    d_append_string (dpi, "::");
    else
    d_append_char (dpi, '.');
    {
    struct demangle_component *local_name = d_right (dc);
    if (local_name->type == DEMANGLE_COMPONENT_DEFAULT_ARG)
    {
        d_append_string (dpi, "{default arg#");
        d_append_num (dpi, local_name->u.s_unary_num.num + 1);
        d_append_string (dpi, "}::");
        local_name = local_name->u.s_unary_num.sub;
    }
    d_print_comp (dpi, options, local_name);
    }
    return;

    case DEMANGLE_COMPONENT_TYPED_NAME:
    {
    struct d_print_mod *hold_modifiers;
    struct demangle_component *typed_name;
    struct d_print_mod adpm[4];
    unsigned int i;
    struct d_print_template dpt;

    /* Pass the name down to the type so that it can be printed in
    the right place for the type.  We also have to pass down
    any CV-qualifiers, which apply to the this parameter.  */
    hold_modifiers = dpi->modifiers;
    dpi->modifiers = 0;
    i = 0;
    typed_name = d_left (dc);
    while (typed_name != nullptr)
    {
        if (i >= sizeof adpm / sizeof adpm[0])
        {
        d_print_error (dpi);
        return;
        }

        adpm[i].next = dpi->modifiers;
        dpi->modifiers = &adpm[i];
        adpm[i].mod = typed_name;
        adpm[i].printed = 0;
        adpm[i].templates = dpi->templates;
        ++i;

        if (!is_fnqual_component_type (typed_name->type))
        break;

        typed_name = d_left (typed_name);
    }

    if (typed_name == nullptr)
    {
        d_print_error (dpi);
        return;
    }

    /* If typed_name is a DEMANGLE_COMPONENT_LOCAL_NAME, then
    there may be CV-qualifiers on its right argument which
    really apply here; this happens when parsing a class that
    is local to a function.  */
    if (typed_name->type == DEMANGLE_COMPONENT_LOCAL_NAME)
    {
        typed_name = d_right (typed_name);
        if (typed_name->type == DEMANGLE_COMPONENT_DEFAULT_ARG)
        typed_name = typed_name->u.s_unary_num.sub;
        while (typed_name != nullptr
        && is_fnqual_component_type (typed_name->type))
        {
        if (i >= sizeof adpm / sizeof adpm[0])
        {
            d_print_error (dpi);
            return;
        }

        adpm[i] = adpm[i - 1];
        adpm[i].next = &adpm[i - 1];
        dpi->modifiers = &adpm[i];

        adpm[i - 1].mod = typed_name;
        adpm[i - 1].printed = 0;
        adpm[i - 1].templates = dpi->templates;
        ++i;

        typed_name = d_left (typed_name);
        }
        if (typed_name == nullptr)
        {
        d_print_error (dpi);
        return;
        }
    }

    /* If typed_name is a template, then it applies to the
    function type as well.  */
    if (typed_name->type == DEMANGLE_COMPONENT_TEMPLATE)
    {
        dpt.next = dpi->templates;
        dpi->templates = &dpt;
        dpt.template_decl = typed_name;

        /* Constraints are mangled as part of the template argument list,
        so they wrap the _TEMPLATE_ARGLIST.  But
        d_lookup_template_argument expects the RHS of _TEMPLATE to be
        the _ARGLIST, and constraints need to refer to these args.  So
        move the _CONSTRAINTS out of the _TEMPLATE and onto the type.
        This will result in them being printed after the () like a
        trailing requires-clause, but that seems like our best option
        given that we aren't printing a template-head.  */
        struct demangle_component *tnr = d_right (typed_name);
        if (tnr->type == DEMANGLE_COMPONENT_CONSTRAINTS)
        {
        d_right (typed_name) = d_left (tnr);
        d_left (tnr) = d_right (dc);
        d_right (dc) = tnr;
        }
    }

    d_print_comp (dpi, options, d_right (dc));

    if (typed_name->type == DEMANGLE_COMPONENT_TEMPLATE)
    dpi->templates = dpt.next;

    /* If the modifiers didn't get printed by the type, print them
    now.  */
    while (i > 0)
    {
        --i;
        if (! adpm[i].printed)
        {
        d_append_char (dpi, ' ');
        d_print_mod (dpi, options, adpm[i].mod);
        }
    }

    dpi->modifiers = hold_modifiers;

    return;
    }

    case DEMANGLE_COMPONENT_TEMPLATE:
    {
    struct d_print_mod *hold_dpm;
    struct demangle_component *dcl;
    const struct demangle_component *hold_current;

    /* This template may need to be referenced by a cast operator
    contained in its subtree.  */
    hold_current = dpi->current_template;
    dpi->current_template = dc;

    /* Don't push modifiers into a template definition.  Doing so
    could give the wrong definition for a template argument.
    Instead, treat the template essentially as a name.  */

    hold_dpm = dpi->modifiers;
    dpi->modifiers = nullptr;

        dcl = d_left (dc);

        if ((options & DMGL_JAVA) != 0
            && dcl->type == DEMANGLE_COMPONENT_NAME
            && dcl->u.s_name.len == 6
            && std::strncmp (dcl->u.s_name.s, "JArray", 6) == 0)
        {
            /* Special-case Java arrays, so that JArray<TYPE> appears
            instead as TYPE[].  */

            d_print_comp (dpi, options, d_right (dc));
            d_append_string (dpi, "[]");
        }
        else
        {
        d_print_comp (dpi, options, dcl);
        if (d_last_char (dpi) == '<')
        d_append_char (dpi, ' ');
        d_append_char (dpi, '<');
        d_print_comp (dpi, options, d_right (dc));
        /* Avoid generating two consecutive '>' characters, to avoid
        the C++ syntactic ambiguity.  */
        if (d_last_char (dpi) == '>')
        d_append_char (dpi, ' ');
        d_append_char (dpi, '>');
        }

    dpi->modifiers = hold_dpm;
    dpi->current_template = hold_current;

    return;
    }

    case DEMANGLE_COMPONENT_TEMPLATE_PARAM:
    if (dpi->lambda_tpl_parms > dc->u.s_number.number + 1)
    {
    const struct demangle_component *a
        = d_left (dpi->templates->template_decl);
    unsigned c;
    for (c = dc->u.s_number.number; a && c; c--)
        a = d_right (a);
    if (a && a->type == DEMANGLE_COMPONENT_TEMPLATE_PACK_PARM)
        a = d_left (a);
    if (!a)
        dpi->demangle_failure = 1;
    else
        d_print_lambda_parm_name (dpi, a->type, dc->u.s_number.number);
    }
    else if (dpi->lambda_tpl_parms)
    {
    /* Show the template parm index, as that's how g++ displays
        these, and future proofs us against potential
        '[]<typename T> (T *a, T *b) {...}'.  */
    d_append_buffer (dpi, "auto:", 5);
    d_append_num (dpi, dc->u.s_number.number + 1);
    }
    else
    {
    struct d_print_template *hold_dpt;
    struct demangle_component *a = d_lookup_template_argument (dpi, dc);

    if (a && a->type == DEMANGLE_COMPONENT_TEMPLATE_ARGLIST)
        a = d_index_template_argument (a, dpi->pack_index);

    if (a == nullptr)
        {
        d_print_error (dpi);
        return;
        }

    /* While processing this parameter, we need to pop the list
        of templates.  This is because the template parameter may
        itself be a reference to a parameter of an outer
        template.  */

    hold_dpt = dpi->templates;
    dpi->templates = hold_dpt->next;

    d_print_comp (dpi, options, a);

    dpi->templates = hold_dpt;
    }
    return;

    case DEMANGLE_COMPONENT_TPARM_OBJ:
    d_append_string (dpi, "template parameter object for ");
    d_print_comp (dpi, options, d_left (dc));
    return;

    case DEMANGLE_COMPONENT_CTOR:
    d_print_comp (dpi, options, dc->u.s_ctor.name);
    return;

    case DEMANGLE_COMPONENT_DTOR:
    d_append_char (dpi, '~');
    d_print_comp (dpi, options, dc->u.s_dtor.name);
    return;

    case DEMANGLE_COMPONENT_MODULE_INIT:
    d_append_string (dpi, "initializer for module ");
    d_print_comp (dpi, options, d_left (dc));
    return;

    case DEMANGLE_COMPONENT_VTABLE:
    d_append_string (dpi, "vtable for ");
    d_print_comp (dpi, options, d_left (dc));
    return;

    case DEMANGLE_COMPONENT_VTT:
    d_append_string (dpi, "VTT for ");
    d_print_comp (dpi, options, d_left (dc));
    return;

    case DEMANGLE_COMPONENT_CONSTRUCTION_VTABLE:
    d_append_string (dpi, "construction vtable for ");
    d_print_comp (dpi, options, d_left (dc));
    d_append_string (dpi, "-in-");
    d_print_comp (dpi, options, d_right (dc));
    return;

    case DEMANGLE_COMPONENT_TYPEINFO:
    d_append_string (dpi, "typeinfo for ");
    d_print_comp (dpi, options, d_left (dc));
    return;

    case DEMANGLE_COMPONENT_TYPEINFO_NAME:
    d_append_string (dpi, "typeinfo name for ");
    d_print_comp (dpi, options, d_left (dc));
    return;

    case DEMANGLE_COMPONENT_TYPEINFO_FN:
    d_append_string (dpi, "typeinfo fn for ");
    d_print_comp (dpi, options, d_left (dc));
    return;

    case DEMANGLE_COMPONENT_THUNK:
    d_append_string (dpi, "non-virtual thunk to ");
    d_print_comp (dpi, options, d_left (dc));
    return;

    case DEMANGLE_COMPONENT_VIRTUAL_THUNK:
    d_append_string (dpi, "virtual thunk to ");
    d_print_comp (dpi, options, d_left (dc));
    return;

    case DEMANGLE_COMPONENT_COVARIANT_THUNK:
    d_append_string (dpi, "covariant return thunk to ");
    d_print_comp (dpi, options, d_left (dc));
    return;

    case DEMANGLE_COMPONENT_JAVA_CLASS:
    d_append_string (dpi, "java Class for ");
    d_print_comp (dpi, options, d_left (dc));
    return;

    case DEMANGLE_COMPONENT_GUARD:
    d_append_string (dpi, "guard variable for ");
    d_print_comp (dpi, options, d_left (dc));
    return;

    case DEMANGLE_COMPONENT_TLS_INIT:
    d_append_string (dpi, "TLS init function for ");
    d_print_comp (dpi, options, d_left (dc));
    return;

    case DEMANGLE_COMPONENT_TLS_WRAPPER:
    d_append_string (dpi, "TLS wrapper function for ");
    d_print_comp (dpi, options, d_left (dc));
    return;

    case DEMANGLE_COMPONENT_REFTEMP:
    d_append_string (dpi, "reference temporary #");
    d_print_comp (dpi, options, d_right (dc));
    d_append_string (dpi, " for ");
    d_print_comp (dpi, options, d_left (dc));
    return;

    case DEMANGLE_COMPONENT_HIDDEN_ALIAS:
    d_append_string (dpi, "hidden alias for ");
    d_print_comp (dpi, options, d_left (dc));
    return;

    case DEMANGLE_COMPONENT_TRANSACTION_CLONE:
    d_append_string (dpi, "transaction clone for ");
    d_print_comp (dpi, options, d_left (dc));
    return;

    case DEMANGLE_COMPONENT_NONTRANSACTION_CLONE:
    d_append_string (dpi, "non-transaction clone for ");
    d_print_comp (dpi, options, d_left (dc));
    return;

    case DEMANGLE_COMPONENT_SUB_STD:
    d_append_buffer (dpi, dc->u.s_string.string, dc->u.s_string.len);
    return;

    case DEMANGLE_COMPONENT_RESTRICT:
    case DEMANGLE_COMPONENT_VOLATILE:
    case DEMANGLE_COMPONENT_CONST:
    {
    struct d_print_mod *pdpm;

    /* When printing arrays, it's possible to have cases where the
    same CV-qualifier gets pushed on the stack multiple times.
    We only need to print it once.  */

    for (pdpm = dpi->modifiers; pdpm != nullptr; pdpm = pdpm->next)
    {
        if (! pdpm->printed)
        {
        if (pdpm->mod->type != DEMANGLE_COMPONENT_RESTRICT
            && pdpm->mod->type != DEMANGLE_COMPONENT_VOLATILE
            && pdpm->mod->type != DEMANGLE_COMPONENT_CONST)
        break;
        if (pdpm->mod->type == dc->type)
        {
            d_print_comp (dpi, options, d_left (dc));
            return;
        }
        }
    }
    }
    goto modifier;

    case DEMANGLE_COMPONENT_REFERENCE:
    case DEMANGLE_COMPONENT_RVALUE_REFERENCE:
    {
    /* Handle reference smashing: & + && = &.  */
    struct demangle_component *sub = d_left (dc);
    if (!dpi->lambda_tpl_parms
        && sub->type == DEMANGLE_COMPONENT_TEMPLATE_PARAM)
    {
        struct d_saved_scope *scope = d_get_saved_scope (dpi, sub);
        struct demangle_component *a;

        if (scope == nullptr)
        {
        /* This is the first time SUB has been traversed.
        We need to capture the current templates so
        they can be restored if SUB is reentered as a
        substitution.  */
        d_save_scope (dpi, sub);
        if (d_print_saw_error (dpi))
        return;
        }
        else
        {
        const struct d_component_stack *dcse;
        int found_self_or_parent = 0;

        /* This traversal is reentering SUB as a substition.
        If we are not beneath SUB or DC in the tree then we
        need to restore SUB's template stack temporarily.  */
        for (dcse = dpi->component_stack; dcse != nullptr;
            dcse = dcse->parent)
        {
            if (dcse->dc == sub
            || (dcse->dc == dc
                && dcse != dpi->component_stack))
            {
            found_self_or_parent = 1;
            break;
            }
        }

        if (!found_self_or_parent)
        {
            saved_templates = dpi->templates;
            dpi->templates = scope->templates;
            need_template_restore = 1;
        }
        }

        a = d_lookup_template_argument (dpi, sub);
        if (a && a->type == DEMANGLE_COMPONENT_TEMPLATE_ARGLIST)
        a = d_index_template_argument (a, dpi->pack_index);

        if (a == nullptr)
        {
        if (need_template_restore)
        dpi->templates = saved_templates;

        d_print_error (dpi);
        return;
        }

        sub = a;
    }

    if (sub->type == DEMANGLE_COMPONENT_REFERENCE
        || sub->type == dc->type)
    dc = sub;
    else if (sub->type == DEMANGLE_COMPONENT_RVALUE_REFERENCE)
    mod_inner = d_left (sub);
    }
    /* Fall through.  */

    case DEMANGLE_COMPONENT_VENDOR_TYPE_QUAL:
    case DEMANGLE_COMPONENT_POINTER:
    case DEMANGLE_COMPONENT_COMPLEX:
    case DEMANGLE_COMPONENT_IMAGINARY:
    FNQUAL_COMPONENT_CASE:
    modifier:
    {
    /* We keep a list of modifiers on the stack.  */
    struct d_print_mod dpm;

    dpm.next = dpi->modifiers;
    dpi->modifiers = &dpm;
    dpm.mod = dc;
    dpm.printed = 0;
    dpm.templates = dpi->templates;

    if (!mod_inner)
    mod_inner = d_left (dc);

    d_print_comp (dpi, options, mod_inner);

    /* If the modifier didn't get printed by the type, print it
    now.  */
    if (! dpm.printed)
    d_print_mod (dpi, options, dc);

    dpi->modifiers = dpm.next;

    if (need_template_restore)
    dpi->templates = saved_templates;

    return;
    }

    case DEMANGLE_COMPONENT_BUILTIN_TYPE:
    if ((options & DMGL_JAVA) == 0)
    d_append_buffer (dpi, dc->u.s_builtin.type->name,
            dc->u.s_builtin.type->len);
    else
    d_append_buffer (dpi, dc->u.s_builtin.type->java_name,
            dc->u.s_builtin.type->java_len);
    return;

    case DEMANGLE_COMPONENT_EXTENDED_BUILTIN_TYPE:
    d_append_buffer (dpi, dc->u.s_extended_builtin.type->name,
            dc->u.s_extended_builtin.type->len);
    d_append_num (dpi, dc->u.s_extended_builtin.arg);
    if (dc->u.s_extended_builtin.suffix)
    d_append_buffer (dpi, &dc->u.s_extended_builtin.suffix, 1);
    return;

    case DEMANGLE_COMPONENT_VENDOR_TYPE:
    d_print_comp (dpi, options, d_left (dc));
    return;

    case DEMANGLE_COMPONENT_FUNCTION_TYPE:
    {
    if ((options & DMGL_RET_POSTFIX) != 0)
    d_print_function_type (dpi,
                options & ~(DMGL_RET_POSTFIX | DMGL_RET_DROP),
                dc, dpi->modifiers);

    /* Print return type if present */
    if (d_left (dc) != nullptr && (options & DMGL_RET_POSTFIX) != 0)
    d_print_comp (dpi, options & ~(DMGL_RET_POSTFIX | DMGL_RET_DROP),
            d_left (dc));
    else if (d_left (dc) != nullptr && (options & DMGL_RET_DROP) == 0)
    {
        struct d_print_mod dpm;

        /* We must pass this type down as a modifier in order to
        print it in the right location.  */
        dpm.next = dpi->modifiers;
        dpi->modifiers = &dpm;
        dpm.mod = dc;
        dpm.printed = 0;
        dpm.templates = dpi->templates;

        d_print_comp (dpi, options & ~(DMGL_RET_POSTFIX | DMGL_RET_DROP),
            d_left (dc));

        dpi->modifiers = dpm.next;

        if (dpm.printed)
        return;

        /* In standard prefix notation, there is a space between the
        return type and the function signature.  */
        if ((options & DMGL_RET_POSTFIX) == 0)
        d_append_char (dpi, ' ');
    }

    if ((options & DMGL_RET_POSTFIX) == 0)
    d_print_function_type (dpi,
                options & ~(DMGL_RET_POSTFIX | DMGL_RET_DROP),
                dc, dpi->modifiers);

    return;
    }

    case DEMANGLE_COMPONENT_ARRAY_TYPE:
    {
    struct d_print_mod *hold_modifiers;
    struct d_print_mod adpm[4];
    unsigned int i;
    struct d_print_mod *pdpm;

    /* We must pass this type down as a modifier in order to print
    multi-dimensional arrays correctly.  If the array itself is
    CV-qualified, we act as though the element type were
    CV-qualified.  We do this by copying the modifiers down
    rather than fiddling pointers, so that we don't wind up
    with a d_print_mod higher on the stack pointing into our
    stack frame after we return.  */

    hold_modifiers = dpi->modifiers;

    adpm[0].next = hold_modifiers;
    dpi->modifiers = &adpm[0];
    adpm[0].mod = dc;
    adpm[0].printed = 0;
    adpm[0].templates = dpi->templates;

    i = 1;
    pdpm = hold_modifiers;
    while (pdpm != nullptr
        && (pdpm->mod->type == DEMANGLE_COMPONENT_RESTRICT
        || pdpm->mod->type == DEMANGLE_COMPONENT_VOLATILE
        || pdpm->mod->type == DEMANGLE_COMPONENT_CONST))
    {
        if (! pdpm->printed)
        {
        if (i >= sizeof adpm / sizeof adpm[0])
        {
            d_print_error (dpi);
            return;
        }

        adpm[i] = *pdpm;
        adpm[i].next = dpi->modifiers;
        dpi->modifiers = &adpm[i];
        pdpm->printed = 1;
        ++i;
        }

        pdpm = pdpm->next;
    }

    d_print_comp (dpi, options, d_right (dc));

    dpi->modifiers = hold_modifiers;

    if (adpm[0].printed)
    return;

    while (i > 1)
    {
        --i;
        d_print_mod (dpi, options, adpm[i].mod);
    }

    d_print_array_type (dpi, options, dc, dpi->modifiers);

    return;
    }

    case DEMANGLE_COMPONENT_PTRMEM_TYPE:
    case DEMANGLE_COMPONENT_VECTOR_TYPE:
    {
    struct d_print_mod dpm;

    dpm.next = dpi->modifiers;
    dpi->modifiers = &dpm;
    dpm.mod = dc;
    dpm.printed = 0;
    dpm.templates = dpi->templates;

    d_print_comp (dpi, options, d_right (dc));

    /* If the modifier didn't get printed by the type, print it
    now.  */
    if (! dpm.printed)
    d_print_mod (dpi, options, dc);

    dpi->modifiers = dpm.next;

    return;
    }

    case DEMANGLE_COMPONENT_ARGLIST:
    case DEMANGLE_COMPONENT_TEMPLATE_ARGLIST:
    if (d_left (dc) != nullptr)
    d_print_comp (dpi, options, d_left (dc));
    if (d_right (dc) != nullptr)
    {
    size_t len;
    unsigned long int flush_count;
    /* Make sure ", " isn't flushed by d_append_string, otherwise
        dpi->len -= 2 wouldn't work.  */
    if (dpi->len >= sizeof (dpi->buf) - 2)
        d_print_flush (dpi);
    d_append_string (dpi, ", ");
    len = dpi->len;
    flush_count = dpi->flush_count;
    d_print_comp (dpi, options, d_right (dc));
    /* If that didn't print anything (which can happen with empty
        template argument packs), remove the comma and space.  */
    if (dpi->flush_count == flush_count && dpi->len == len)
        dpi->len -= 2;
    }
    return;

    case DEMANGLE_COMPONENT_INITIALIZER_LIST:
    {
    struct demangle_component *type = d_left (dc);
    struct demangle_component *list = d_right (dc);

    if (type)
    d_print_comp (dpi, options, type);
    d_append_char (dpi, '{');
    d_print_comp (dpi, options, list);
    d_append_char (dpi, '}');
    }
    return;

    case DEMANGLE_COMPONENT_OPERATOR:
    {
    const struct demangle_operator_info *op = dc->u.s_operator.op;
    int len = op->len;

    d_append_string (dpi, "operator");
    /* Add a space before new/delete.  */
    if (IS_LOWER (op->name[0]))
    d_append_char (dpi, ' ');
    /* Omit a trailing space.  */
    if (op->name[len-1] == ' ')
    --len;
    d_append_buffer (dpi, op->name, len);
    return;
    }

    case DEMANGLE_COMPONENT_EXTENDED_OPERATOR:
    d_append_string (dpi, "operator ");
    d_print_comp (dpi, options, dc->u.s_extended_operator.name);
    return;

    case DEMANGLE_COMPONENT_CONVERSION:
    d_append_string (dpi, "operator ");
    d_print_conversion (dpi, options, dc);
    return;

    case DEMANGLE_COMPONENT_NULLARY:
    d_print_expr_op (dpi, options, d_left (dc));
    return;

    case DEMANGLE_COMPONENT_UNARY:
    {
    struct demangle_component *op = d_left (dc);
    struct demangle_component *operand = d_right (dc);
    const char *code = nullptr;

    if (op->type == DEMANGLE_COMPONENT_OPERATOR)
    {
        code = op->u.s_operator.op->code;
        if (!std::strcmp (code, "ad"))
        {
        /* Don't print the argument list for the address of a
        function.  */
        if (operand->type == DEMANGLE_COMPONENT_TYPED_NAME
            && d_left (operand)->type == DEMANGLE_COMPONENT_QUAL_NAME
            && d_right (operand)->type == DEMANGLE_COMPONENT_FUNCTION_TYPE)
        operand = d_left (operand);
        }
        if (operand->type == DEMANGLE_COMPONENT_BINARY_ARGS)
        {
        /* This indicates a suffix operator.  */
        operand = d_left (operand);
        d_print_subexpr (dpi, options, operand);
        d_print_expr_op (dpi, options, op);
        return;
        }
    }

    /* For sizeof..., just print the pack length.  */
    if (code && !std::strcmp (code, "sZ"))
    {
        struct demangle_component *a = d_find_pack (dpi, operand);
        int len = d_pack_length (a);
        d_append_num (dpi, len);
        return;
    }
    else if (code && !std::strcmp (code, "sP"))
    {
        int len = d_args_length (dpi, operand);
        d_append_num (dpi, len);
        return;
    }

    if (op->type != DEMANGLE_COMPONENT_CAST)
    d_print_expr_op (dpi, options, op);
    else
    {
        d_append_char (dpi, '(');
        d_print_cast (dpi, options, op);
        d_append_char (dpi, ')');
    }
    if (code && !std::strcmp (code, "gs"))
    /* Avoid parens after '::'.  */
    d_print_comp (dpi, options, operand);
    else if (code && (!std::strcmp (code, "st") || !std::strcmp (code, "nx")))
    /* Always print parens for sizeof (type) and noexcept(expr).  */
    {
        d_append_char (dpi, '(');
        d_print_comp (dpi, options, operand);
        d_append_char (dpi, ')');
    }
    else
    d_print_subexpr (dpi, options, operand);
    }
    return;

    case DEMANGLE_COMPONENT_BINARY:
    if (d_right (dc)->type != DEMANGLE_COMPONENT_BINARY_ARGS)
    {
    d_print_error (dpi);
    return;
    }

    if (op_is_new_cast (d_left (dc)))
    {
    d_print_expr_op (dpi, options, d_left (dc));
    d_append_char (dpi, '<');
    d_print_comp (dpi, options, d_left (d_right (dc)));
    d_append_string (dpi, ">(");
    d_print_comp (dpi, options, d_right (d_right (dc)));
    d_append_char (dpi, ')');
    return;
    }

    if (d_maybe_print_fold_expression (dpi, options, dc))
    return;

    if (d_maybe_print_designated_init (dpi, options, dc))
    return;

    /* We wrap an expression which uses the greater-than operator in
    an extra layer of parens so that it does not get confused
    with the '>' which ends the template parameters.  */
    if (d_left (dc)->type == DEMANGLE_COMPONENT_OPERATOR
    && d_left (dc)->u.s_operator.op->len == 1
    && d_left (dc)->u.s_operator.op->name[0] == '>')
    d_append_char (dpi, '(');

    if (std::strcmp (d_left (dc)->u.s_operator.op->code, "cl") == 0
        && d_left (d_right (dc))->type == DEMANGLE_COMPONENT_TYPED_NAME)
    {
    /* Function call used in an expression should not have printed types
        of the function arguments.  Values of the function arguments still
        get printed below.  */

    const struct demangle_component *func = d_left (d_right (dc));

    if (d_right (func)->type != DEMANGLE_COMPONENT_FUNCTION_TYPE)
        d_print_error (dpi);
    d_print_subexpr (dpi, options, d_left (func));
    }
    else
    d_print_subexpr (dpi, options, d_left (d_right (dc)));
    if (std::strcmp (d_left (dc)->u.s_operator.op->code, "ix") == 0)
    {
    d_append_char (dpi, '[');
    d_print_comp (dpi, options, d_right (d_right (dc)));
    d_append_char (dpi, ']');
    }
    else
    {
    if (std::strcmp (d_left (dc)->u.s_operator.op->code, "cl") != 0)
        d_print_expr_op (dpi, options, d_left (dc));
    d_print_subexpr (dpi, options, d_right (d_right (dc)));
    }

    if (d_left (dc)->type == DEMANGLE_COMPONENT_OPERATOR
    && d_left (dc)->u.s_operator.op->len == 1
    && d_left (dc)->u.s_operator.op->name[0] == '>')
    d_append_char (dpi, ')');

    return;

    case DEMANGLE_COMPONENT_BINARY_ARGS:
    /* We should only see this as part of DEMANGLE_COMPONENT_BINARY.  */
    d_print_error (dpi);
    return;

    case DEMANGLE_COMPONENT_TRINARY:
    if (d_right (dc)->type != DEMANGLE_COMPONENT_TRINARY_ARG1
    || d_right (d_right (dc))->type != DEMANGLE_COMPONENT_TRINARY_ARG2)
    {
    d_print_error (dpi);
    return;
    }
    if (d_maybe_print_fold_expression (dpi, options, dc))
    return;
    if (d_maybe_print_designated_init (dpi, options, dc))
    return;
    {
    struct demangle_component *op = d_left (dc);
    struct demangle_component *first = d_left (d_right (dc));
    struct demangle_component *second = d_left (d_right (d_right (dc)));
    struct demangle_component *third = d_right (d_right (d_right (dc)));

    if (!std::strcmp (op->u.s_operator.op->code, "qu"))
    {
        d_print_subexpr (dpi, options, first);
        d_print_expr_op (dpi, options, op);
        d_print_subexpr (dpi, options, second);
        d_append_string (dpi, " : ");
        d_print_subexpr (dpi, options, third);
    }
    else
    {
        d_append_string (dpi, "new ");
        if (d_left (first) != nullptr)
        {
        d_print_subexpr (dpi, options, first);
        d_append_char (dpi, ' ');
        }
        d_print_comp (dpi, options, second);
        if (third)
        d_print_subexpr (dpi, options, third);
    }
    }
    return;

    case DEMANGLE_COMPONENT_TRINARY_ARG1:
    case DEMANGLE_COMPONENT_TRINARY_ARG2:
    /* We should only see these are part of DEMANGLE_COMPONENT_TRINARY.  */
    d_print_error (dpi);
    return;

    case DEMANGLE_COMPONENT_LITERAL:
    case DEMANGLE_COMPONENT_LITERAL_NEG:
    {
    enum d_builtin_type_print tp;

    /* For some builtin types, produce simpler output.  */
    tp = D_PRINT_DEFAULT;
    if (d_left (dc)->type == DEMANGLE_COMPONENT_BUILTIN_TYPE)
    {
        tp = d_left (dc)->u.s_builtin.type->print;
        switch (tp)
        {
        case D_PRINT_INT:
        case D_PRINT_UNSIGNED:
        case D_PRINT_LONG:
        case D_PRINT_UNSIGNED_LONG:
        case D_PRINT_LONG_LONG:
        case D_PRINT_UNSIGNED_LONG_LONG:
        if (d_right (dc)->type == DEMANGLE_COMPONENT_NAME)
        {
            if (dc->type == DEMANGLE_COMPONENT_LITERAL_NEG)
            d_append_char (dpi, '-');
            d_print_comp (dpi, options, d_right (dc));
            switch (tp)
            {
            default:
            break;
            case D_PRINT_UNSIGNED:
            d_append_char (dpi, 'u');
            break;
            case D_PRINT_LONG:
            d_append_char (dpi, 'l');
            break;
            case D_PRINT_UNSIGNED_LONG:
            d_append_string (dpi, "ul");
            break;
            case D_PRINT_LONG_LONG:
            d_append_string (dpi, "ll");
            break;
            case D_PRINT_UNSIGNED_LONG_LONG:
            d_append_string (dpi, "ull");
            break;
            }
            return;
        }
        break;

        case D_PRINT_BOOL:
        if (d_right (dc)->type == DEMANGLE_COMPONENT_NAME
            && d_right (dc)->u.s_name.len == 1
            && dc->type == DEMANGLE_COMPONENT_LITERAL)
        {
            switch (d_right (dc)->u.s_name.s[0])
            {
            case '0':
            d_append_string (dpi, "false");
            return;
            case '1':
            d_append_string (dpi, "true");
            return;
            default:
            break;
            }
        }
        break;

        default:
        break;
        }
    }

    d_append_char (dpi, '(');
    d_print_comp (dpi, options, d_left (dc));
    d_append_char (dpi, ')');
    if (dc->type == DEMANGLE_COMPONENT_LITERAL_NEG)
    d_append_char (dpi, '-');
    if (tp == D_PRINT_FLOAT)
    d_append_char (dpi, '[');
    d_print_comp (dpi, options, d_right (dc));
    if (tp == D_PRINT_FLOAT)
    d_append_char (dpi, ']');
    }
    return;

    case DEMANGLE_COMPONENT_VENDOR_EXPR:
    d_print_comp (dpi, options, d_left (dc));
    d_append_char (dpi, '(');
    d_print_comp (dpi, options, d_right (dc));
    d_append_char (dpi, ')');
    return;

    case DEMANGLE_COMPONENT_NUMBER:
    d_append_num (dpi, dc->u.s_number.number);
    return;

    case DEMANGLE_COMPONENT_JAVA_RESOURCE:
    d_append_string (dpi, "java resource ");
    d_print_comp (dpi, options, d_left (dc));
    return;

    case DEMANGLE_COMPONENT_COMPOUND_NAME:
    d_print_comp (dpi, options, d_left (dc));
    d_print_comp (dpi, options, d_right (dc));
    return;

    case DEMANGLE_COMPONENT_CHARACTER:
    d_append_char (dpi, dc->u.s_character.character);
    return;

    case DEMANGLE_COMPONENT_DECLTYPE:
    d_append_string (dpi, "decltype (");
    d_print_comp (dpi, options, d_left (dc));
    d_append_char (dpi, ')');
    return;

    case DEMANGLE_COMPONENT_PACK_EXPANSION:
    {
    struct demangle_component *a = nullptr;

    if (!dpi->lambda_tpl_parms)
    a = d_find_pack (dpi, d_left (dc));
    if (a == nullptr)
    {
        /* d_find_pack won't find anything if the only packs involved
        in this expansion are function parameter packs; in that
        case, just print the pattern and "...".  */
        d_print_subexpr (dpi, options, d_left (dc));
        d_append_string (dpi, "...");
    }
    else
    {
        int len = d_pack_length (a);
        int i;

        dc = d_left (dc);
        for (i = 0; i < len; ++i)
        {
        if (i)
        d_append_string (dpi, ", ");
        dpi->pack_index = i;
        d_print_comp (dpi, options, dc);
        }
    }
    }
    return;

    case DEMANGLE_COMPONENT_FUNCTION_PARAM:
    {
    long num = dc->u.s_number.number;
    if (num == 0)
    d_append_string (dpi, "this");
    else
    {
        d_append_string (dpi, "{parm#");
        d_append_num (dpi, num);
        d_append_char (dpi, '}');
    }
    }
    return;

    case DEMANGLE_COMPONENT_GLOBAL_CONSTRUCTORS:
    d_append_string (dpi, "global constructors keyed to ");
    d_print_comp (dpi, options, dc->u.s_binary.left);
    return;

    case DEMANGLE_COMPONENT_GLOBAL_DESTRUCTORS:
    d_append_string (dpi, "global destructors keyed to ");
    d_print_comp (dpi, options, dc->u.s_binary.left);
    return;

    case DEMANGLE_COMPONENT_LAMBDA:
    {
    d_append_string (dpi, "{lambda");
    struct demangle_component *parms = dc->u.s_unary_num.sub;
    struct d_print_template dpt;
    /* Generic lambda auto parms are mangled as the (synthedic) template
    type parm they are.  We need to tell the printer that (a) we're in
    a lambda, and (b) the number of synthetic parms.  */
    int saved_tpl_parms = dpi->lambda_tpl_parms;
    dpi->lambda_tpl_parms = 0;
    /* Hang any lambda head as-if template args.  */
    dpt.template_decl = nullptr;
    dpt.next = dpi->templates;
    dpi->templates = &dpt;
    if (parms && parms->type == DEMANGLE_COMPONENT_TEMPLATE_HEAD)
    {
        dpt.template_decl = parms;

        d_append_char (dpi, '<');
        struct demangle_component *parm;
        for (parm = d_left (parms); parm; parm = d_right (parm))
        {
        if (dpi->lambda_tpl_parms++)
        d_append_string (dpi, ", ");
        d_print_comp (dpi, options, parm);
        d_append_char (dpi, ' ');
        if (parm->type == DEMANGLE_COMPONENT_TEMPLATE_PACK_PARM)
        parm = d_left (parm);
        d_print_lambda_parm_name (dpi, parm->type,
                    dpi->lambda_tpl_parms - 1);
        }
        d_append_char (dpi, '>');

        parms = d_right (parms);
    }
    dpi->lambda_tpl_parms++;

    d_append_char (dpi, '(');
    d_print_comp (dpi, options, parms);
    dpi->lambda_tpl_parms = saved_tpl_parms;
    dpi->templates = dpt.next;
    d_append_string (dpi, ")#");
    d_append_num (dpi, dc->u.s_unary_num.num + 1);
    d_append_char (dpi, '}');
    }
    return;

    case DEMANGLE_COMPONENT_UNNAMED_TYPE:
    d_append_string (dpi, "{unnamed type#");
    d_append_num (dpi, dc->u.s_number.number + 1);
    d_append_char (dpi, '}');
    return;

    case DEMANGLE_COMPONENT_CLONE:
    d_print_comp (dpi, options, d_left (dc));
    d_append_string (dpi, " [clone ");
    d_print_comp (dpi, options, d_right (dc));
    d_append_char (dpi, ']');
    return;

    case DEMANGLE_COMPONENT_FRIEND:
    d_print_comp (dpi, options, d_left (dc));
    d_append_string (dpi, "[friend]");
    return;

    case DEMANGLE_COMPONENT_TEMPLATE_HEAD:
    {
    d_append_char (dpi, '<');
    int count = 0;
    struct demangle_component *parm;
    for (parm = d_left (dc); parm; parm = d_right (parm))
    {
        if (count++)
        d_append_string (dpi, ", ");
        d_print_comp (dpi, options, parm);
    }
    d_append_char (dpi, '>');
    }
    return;

    case DEMANGLE_COMPONENT_TEMPLATE_TYPE_PARM:
    d_append_string (dpi, "typename");
    return;

    case DEMANGLE_COMPONENT_TEMPLATE_NON_TYPE_PARM:
    d_print_comp (dpi, options, d_left (dc));
    return;

    case DEMANGLE_COMPONENT_TEMPLATE_TEMPLATE_PARM:
    d_append_string (dpi, "template");
    d_print_comp (dpi, options, d_left (dc));
    d_append_string (dpi, " class");
    return;

    case DEMANGLE_COMPONENT_TEMPLATE_PACK_PARM:
    d_print_comp (dpi, options, d_left (dc));
    d_append_string (dpi, "...");
    return;

    case DEMANGLE_COMPONENT_CONSTRAINTS:
    d_print_comp (dpi, options, d_left (dc));
    d_append_string (dpi, " requires ");
    d_print_comp (dpi, options, d_right (dc));
    return;

    default:
    d_print_error (dpi);
    return;
    }
}

static void
d_print_comp (struct d_print_info *dpi, int options,
        struct demangle_component *dc)
{
struct d_component_stack self;
if (dc == nullptr || dc->d_printing > 1 || dpi->recursion > MAX_RECURSION_COUNT)
    {
    d_print_error (dpi);
    return;
    }

dc->d_printing++;
dpi->recursion++;

self.dc = dc;
self.parent = dpi->component_stack;
dpi->component_stack = &self;

d_print_comp_inner (dpi, options, dc);

dpi->component_stack = self.parent;
dc->d_printing--;
dpi->recursion--;
}

/* Print a Java dentifier.  For Java we try to handle encoded extended
Unicode characters.  The C++ ABI doesn't mention Unicode encoding,
so we don't it for C++.  Characters are encoded as
__U<hex-char>+_.  */

static void
d_print_java_identifier (struct d_print_info *dpi, const char *name, int len)
{
const char *p;
const char *end;

end = name + len;
for (p = name; p < end; ++p)
    {
    if (end - p > 3
    && p[0] == '_'
    && p[1] == '_'
    && p[2] == 'U')
    {
    unsigned long c;
    const char *q;

    c = 0;
    for (q = p + 3; q < end; ++q)
        {
        int dig;

        if (IS_DIGIT (*q))
        dig = *q - '0';
        else if (*q >= 'A' && *q <= 'F')
        dig = *q - 'A' + 10;
        else if (*q >= 'a' && *q <= 'f')
        dig = *q - 'a' + 10;
        else
        break;

        c = c * 16 + dig;
        }
    /* If the Unicode character is larger than 256, we don't try
        to deal with it here.  FIXME.  */
    if (q < end && *q == '_' && c < 256)
        {
        d_append_char (dpi, c);
        p = q;
        continue;
        }
    }

    d_append_char (dpi, *p);
    }
}

/* Print a list of modifiers.  SUFFIX is 1 if we are printing
qualifiers on this after printing a function.  */

static void
d_print_mod_list (struct d_print_info *dpi, int options,
                struct d_print_mod *mods, int suffix)
{
struct d_print_template *hold_dpt;

if (mods == nullptr || d_print_saw_error (dpi))
    return;

if (mods->printed
    || (! suffix
    && (is_fnqual_component_type (mods->mod->type))))
    {
    d_print_mod_list (dpi, options, mods->next, suffix);
    return;
    }

mods->printed = 1;

hold_dpt = dpi->templates;
dpi->templates = mods->templates;

if (mods->mod->type == DEMANGLE_COMPONENT_FUNCTION_TYPE)
    {
    d_print_function_type (dpi, options, mods->mod, mods->next);
    dpi->templates = hold_dpt;
    return;
    }
else if (mods->mod->type == DEMANGLE_COMPONENT_ARRAY_TYPE)
    {
    d_print_array_type (dpi, options, mods->mod, mods->next);
    dpi->templates = hold_dpt;
    return;
    }
else if (mods->mod->type == DEMANGLE_COMPONENT_LOCAL_NAME)
    {
    struct d_print_mod *hold_modifiers;
    struct demangle_component *dc;

    /* When this is on the modifier stack, we have pulled any
    qualifiers off the right argument already.  Otherwise, we
    print it as usual, but don't let the left argument see any
    modifiers.  */

    hold_modifiers = dpi->modifiers;
    dpi->modifiers = nullptr;
    d_print_comp (dpi, options, d_left (mods->mod));
    dpi->modifiers = hold_modifiers;

    if ((options & DMGL_JAVA) == 0)
    d_append_string (dpi, "::");
    else
    d_append_char (dpi, '.');

    dc = d_right (mods->mod);

    if (dc->type == DEMANGLE_COMPONENT_DEFAULT_ARG)
    {
    d_append_string (dpi, "{default arg#");
    d_append_num (dpi, dc->u.s_unary_num.num + 1);
    d_append_string (dpi, "}::");
    dc = dc->u.s_unary_num.sub;
    }

    while (is_fnqual_component_type (dc->type))
    dc = d_left (dc);

    d_print_comp (dpi, options, dc);

    dpi->templates = hold_dpt;
    return;
    }

d_print_mod (dpi, options, mods->mod);

dpi->templates = hold_dpt;

d_print_mod_list (dpi, options, mods->next, suffix);
}

/* Print a modifier.  */

static void
d_print_mod (struct d_print_info *dpi, int options,
            struct demangle_component *mod)
{
switch (mod->type)
    {
    case DEMANGLE_COMPONENT_RESTRICT:
    case DEMANGLE_COMPONENT_RESTRICT_THIS:
    d_append_string (dpi, " restrict");
    return;
    case DEMANGLE_COMPONENT_VOLATILE:
    case DEMANGLE_COMPONENT_VOLATILE_THIS:
    d_append_string (dpi, " volatile");
    return;
    case DEMANGLE_COMPONENT_CONST:
    case DEMANGLE_COMPONENT_CONST_THIS:
    d_append_string (dpi, " const");
    return;
    case DEMANGLE_COMPONENT_TRANSACTION_SAFE:
    d_append_string (dpi, " transaction_safe");
    return;
    case DEMANGLE_COMPONENT_NOEXCEPT:
    d_append_string (dpi, " noexcept");
    if (d_right (mod))
    {
    d_append_char (dpi, '(');
    d_print_comp (dpi, options, d_right (mod));
    d_append_char (dpi, ')');
    }
    return;
    case DEMANGLE_COMPONENT_THROW_SPEC:
    d_append_string (dpi, " throw");
    if (d_right (mod))
    {
    d_append_char (dpi, '(');
    d_print_comp (dpi, options, d_right (mod));
    d_append_char (dpi, ')');
    }
    return;
    case DEMANGLE_COMPONENT_VENDOR_TYPE_QUAL:
    d_append_char (dpi, ' ');
    d_print_comp (dpi, options, d_right (mod));
    return;
    case DEMANGLE_COMPONENT_POINTER:
    /* There is no pointer symbol in Java.  */
    if ((options & DMGL_JAVA) == 0)
    d_append_char (dpi, '*');
    return;
    case DEMANGLE_COMPONENT_REFERENCE_THIS:
    /* For the ref-qualifier, put a space before the &.  */
    d_append_char (dpi, ' ');
    /* FALLTHRU */
    case DEMANGLE_COMPONENT_REFERENCE:
    d_append_char (dpi, '&');
    return;
    case DEMANGLE_COMPONENT_RVALUE_REFERENCE_THIS:
    d_append_char (dpi, ' ');
    /* FALLTHRU */
    case DEMANGLE_COMPONENT_RVALUE_REFERENCE:
    d_append_string (dpi, "&&");
    return;
    case DEMANGLE_COMPONENT_XOBJ_MEMBER_FUNCTION:
    return;
    case DEMANGLE_COMPONENT_COMPLEX:
    d_append_string (dpi, " _Complex");
    return;
    case DEMANGLE_COMPONENT_IMAGINARY:
    d_append_string (dpi, " _Imaginary");
    return;
    case DEMANGLE_COMPONENT_PTRMEM_TYPE:
    if (d_last_char (dpi) != '(')
    d_append_char (dpi, ' ');
    d_print_comp (dpi, options, d_left (mod));
    d_append_string (dpi, "::*");
    return;
    case DEMANGLE_COMPONENT_TYPED_NAME:
    d_print_comp (dpi, options, d_left (mod));
    return;
    case DEMANGLE_COMPONENT_VECTOR_TYPE:
    d_append_string (dpi, " __vector(");
    d_print_comp (dpi, options, d_left (mod));
    d_append_char (dpi, ')');
    return;

    default:
    /* Otherwise, we have something that won't go back on the
    modifier stack, so we can just print it.  */
    d_print_comp (dpi, options, mod);
    return;
    }
}

/* Print a function type, except for the return type.  */

static void
d_print_function_type (struct d_print_info *dpi, int options,
                    struct demangle_component *dc,
                    struct d_print_mod *mods)
{
int need_paren;
int need_space;
int xobj_memfn;
struct d_print_mod *p;
struct d_print_mod *hold_modifiers;

need_paren = 0;
need_space = 0;
xobj_memfn = 0;
for (p = mods; p != nullptr; p = p->next)
    {
    if (p->printed)
    break;

    switch (p->mod->type)
    {
    case DEMANGLE_COMPONENT_POINTER:
    case DEMANGLE_COMPONENT_REFERENCE:
    case DEMANGLE_COMPONENT_RVALUE_REFERENCE:
    need_paren = 1;
    break;
    case DEMANGLE_COMPONENT_RESTRICT:
    case DEMANGLE_COMPONENT_VOLATILE:
    case DEMANGLE_COMPONENT_CONST:
    case DEMANGLE_COMPONENT_VENDOR_TYPE_QUAL:
    case DEMANGLE_COMPONENT_COMPLEX:
    case DEMANGLE_COMPONENT_IMAGINARY:
    case DEMANGLE_COMPONENT_PTRMEM_TYPE:
    need_space = 1;
    need_paren = 1;
    break;
    case DEMANGLE_COMPONENT_XOBJ_MEMBER_FUNCTION:
    xobj_memfn = 1;
    break;
    default:
    break;
    }
    if (need_paren)
    break;
    }

if (need_paren)
    {
    if (! need_space)
    {
    if (d_last_char (dpi) != '('
        && d_last_char (dpi) != '*')
        need_space = 1;
    }
    if (need_space && d_last_char (dpi) != ' ')
    d_append_char (dpi, ' ');
    d_append_char (dpi, '(');
    }

hold_modifiers = dpi->modifiers;
dpi->modifiers = nullptr;

d_print_mod_list (dpi, options, mods, 0);

if (need_paren)
    d_append_char (dpi, ')');

d_append_char (dpi, '(');
if (xobj_memfn)
    d_append_string (dpi, "this ");

if (d_right (dc) != nullptr)
    d_print_comp (dpi, options, d_right (dc));

d_append_char (dpi, ')');

d_print_mod_list (dpi, options, mods, 1);

dpi->modifiers = hold_modifiers;
}

/* Print an array type, except for the element type.  */

static void
d_print_array_type (struct d_print_info *dpi, int options,
                    struct demangle_component *dc,
                    struct d_print_mod *mods)
{
int need_space;

need_space = 1;
if (mods != nullptr)
    {
    int need_paren;
    struct d_print_mod *p;

    need_paren = 0;
    for (p = mods; p != nullptr; p = p->next)
    {
    if (! p->printed)
        {
        if (p->mod->type == DEMANGLE_COMPONENT_ARRAY_TYPE)
        {
        need_space = 0;
        break;
        }
        else
        {
        need_paren = 1;
        need_space = 1;
        break;
        }
        }
    }

    if (need_paren)
    d_append_string (dpi, " (");

    d_print_mod_list (dpi, options, mods, 0);

    if (need_paren)
    d_append_char (dpi, ')');
    }

if (need_space)
    d_append_char (dpi, ' ');

d_append_char (dpi, '[');

if (d_left (dc) != nullptr)
    d_print_comp (dpi, options, d_left (dc));

d_append_char (dpi, ']');
}

/* Print an operator in an expression.  */

static void
d_print_expr_op (struct d_print_info *dpi, int options,
                struct demangle_component *dc)
{
if (dc->type == DEMANGLE_COMPONENT_OPERATOR)
    d_append_buffer (dpi, dc->u.s_operator.op->name,
            dc->u.s_operator.op->len);
else
    d_print_comp (dpi, options, dc);
}

/* Print a cast.  */

static void
d_print_cast (struct d_print_info *dpi, int options,
        struct demangle_component *dc)
{
d_print_comp (dpi, options, d_left (dc));
}

/* Print a conversion operator.  */

static void
d_print_conversion (struct d_print_info *dpi, int options,
            struct demangle_component *dc)
{
struct d_print_template dpt;

/* For a conversion operator, we need the template parameters from
    the enclosing template in scope for processing the type.  */
if (dpi->current_template != nullptr)
    {
    dpt.next = dpi->templates;
    dpi->templates = &dpt;
    dpt.template_decl = dpi->current_template;
    }

d_print_comp (dpi, options, d_left (dc));

if (dpi->current_template != nullptr)
    dpi->templates = dpt.next;
}

/* Initialize the information structure we use to pass around
information.  */

static
void
cplus_demangle_init_info (const char *mangled, int options, size_t len,
                        struct d_info *di)
{
di->s = mangled;
di->send = mangled + len;
di->options = options;

di->n = mangled;

/* We cannot need more components than twice the number of chars in
    the mangled string.  Most components correspond directly to
    chars, but the ARGLIST types are exceptions.  */
di->num_comps = 2 * len;
di->next_comp = 0;

/* Similarly, we cannot need more substitutions than there are
    chars in the mangled string.  */
di->num_subs = len;
di->next_sub = 0;

di->last_name = nullptr;

di->expansion = 0;
di->is_expression = 0;
di->is_conversion = 0;
di->recursion_level = 0;
}

/* Internal implementation for the demangler.  If MANGLED is a g++ v3 ABI
mangled name, return strings in repeated callback giving the demangled
name.  OPTIONS is the usual libiberty demangler options.  On success,
this returns 1.  On failure, returns 0.  */

static int
d_demangle_callback (const char *mangled, int options,
                    demangle_callbackref callback, void *opaque)
{
enum
    {
    DCT_TYPE,
    DCT_MANGLED,
    DCT_GLOBAL_CTORS,
    DCT_GLOBAL_DTORS
    }
type;
struct d_info di;
struct demangle_component *dc;
int status;

if (mangled[0] == '_' && mangled[1] == 'Z')
    type = DCT_MANGLED;
else if (std::strncmp (mangled, "_GLOBAL_", 8) == 0
    && (mangled[8] == '.' || mangled[8] == '_' || mangled[8] == '$')
    && (mangled[9] == 'D' || mangled[9] == 'I')
    && mangled[10] == '_')
    type = mangled[9] == 'I' ? DCT_GLOBAL_CTORS : DCT_GLOBAL_DTORS;
else
    {
    if ((options & DMGL_TYPES) == 0)
    return 0;
    type = DCT_TYPE;
    }

di.unresolved_name_state = 1;

again:
cplus_demangle_init_info (mangled, options, std::strlen (mangled), &di);

/* PR 87675 - Check for a mangled string that is so long
    that we do not have enough stack space to demangle it.  */
if (((options & DMGL_NO_RECURSE_LIMIT) == 0)
    /* This check is a bit arbitrary, since what we really want to do is to
    compare the sizes of the di.comps and di.subs arrays against the
    amount of stack space remaining.  But there is no portable way to do
    this, so instead we use the recursion limit as a guide to the maximum
    size of the arrays.  */
    && (unsigned long) di.num_comps > DEMANGLE_RECURSION_LIMIT)
    {
    /* FIXME: We need a way to indicate that a stack limit has been reached.  */
    return 0;
    }

{
    __extension__ struct demangle_component comps[di.num_comps];
    __extension__ struct demangle_component *subs[di.num_subs];

    di.comps = comps;
    di.subs = subs;

    switch (type)
    {
    case DCT_TYPE:
    dc = cplus_demangle_type (&di);
    break;
    case DCT_MANGLED:
    dc = cplus_demangle_mangled_name (&di, 1);
    break;
    case DCT_GLOBAL_CTORS:
    case DCT_GLOBAL_DTORS:
    d_advance (&di, 11);
    dc = d_make_comp (&di,
            (type == DCT_GLOBAL_CTORS
            ? DEMANGLE_COMPONENT_GLOBAL_CONSTRUCTORS
            : DEMANGLE_COMPONENT_GLOBAL_DESTRUCTORS),
            d_make_demangle_mangled_name (&di, d_str (&di)),
            nullptr);
    d_advance (&di, std::strlen (d_str (&di)));
    break;
    default:
        __builtin_unreachable(); /* We have listed all the cases.  */
    }

    /* If DMGL_PARAMS is set, then if we didn't consume the entire
    mangled string, then we didn't successfully demangle it.  If
    DMGL_PARAMS is not set, we didn't look at the trailing
    parameters.  */
    if (((options & DMGL_PARAMS) != 0) && d_peek_char (&di) != '\0')
    dc = nullptr;

    /* See discussion in d_unresolved_name.  */
    if (dc == nullptr && di.unresolved_name_state == -1)
    {
    di.unresolved_name_state = 0;
    goto again;
    }

#ifdef CP_DEMANGLE_DEBUG
    d_dump (dc, 0);
#endif

    status = (dc != nullptr)
            ? cplus_demangle_print_callback (options, dc, callback, opaque)
            : 0;
}

return status;
}

/* Entry point for the demangler.  If MANGLED is a g++ v3 ABI mangled
name, return a buffer allocated with malloc holding the demangled
name.  OPTIONS is the usual libiberty demangler options.  On
success, this sets *PALC to the allocated size of the returned
buffer.  On failure, this sets *PALC to 0 for a bad name, or 1 for
a memory allocation failure, and returns nullptr.  */

static char *
d_demangle (const char *mangled, int options, size_t *palc)
{
struct d_growable_string dgs;
int status;

d_growable_string_init (&dgs, 0);

status = d_demangle_callback (mangled, options,
                                d_growable_string_callback_adapter, &dgs);
if (status == 0)
    {
    free (dgs.buf);
    *palc = 0;
    return nullptr;
    }

*palc = dgs.allocation_failure ? 1 : dgs.alc;
return dgs.buf;
}

#if defined(IN_LIBGCC2) || defined(IN_GLIBCPP_V3)

extern char *__cxa_demangle (const char *, char *, size_t *, int *);

/* ia64 ABI-mandated entry point in the C++ runtime library for
performing demangling.  MANGLED_NAME is a NUL-terminated character
string containing the name to be demangled.

OUTPUT_BUFFER is a region of memory, allocated with malloc, of
*LENGTH bytes, into which the demangled name is stored.  If
OUTPUT_BUFFER is not long enough, it is expanded using realloc.
OUTPUT_BUFFER may instead be nullptr; in that case, the demangled name
is placed in a region of memory allocated with malloc.

If LENGTH is non-nullptr, the length of the buffer containing the
demangled name, is placed in *LENGTH.

The return value is a pointer to the start of the NUL-terminated
demangled name, or nullptr if the demangling fails.  The caller is
responsible for deallocating this memory using free.

*STATUS is set to one of the following values:
    0: The demangling operation succeeded.
    -1: A memory allocation failure occurred.
    -2: MANGLED_NAME is not a valid name under the C++ ABI mangling rules.
    -3: One of the arguments is invalid.

The demangling is performed using the C++ ABI mangling rules, with
GNU extensions.  */

char *
__cxa_demangle (const char *mangled_name, char *output_buffer,
                size_t *length, int *status)
{
char *demangled;
size_t alc;

if (mangled_name == nullptr)
    {
    if (status != nullptr)
    *status = -3;
    return nullptr;
    }

if (output_buffer != nullptr && length == nullptr)
    {
    if (status != nullptr)
    *status = -3;
    return nullptr;
    }

demangled = d_demangle (mangled_name, DMGL_PARAMS | DMGL_TYPES, &alc);

if (demangled == nullptr)
    {
    if (status != nullptr)
    {
    if (alc == 1)
        *status = -1;
    else
        *status = -2;
    }
    return nullptr;
    }

if (output_buffer == nullptr)
    {
    if (length != nullptr)
    *length = alc;
    }
else
    {
    if (strlen (demangled) < *length)
    {
    strcpy (output_buffer, demangled);
    free (demangled);
    demangled = output_buffer;
    }
    else
    {
    free (output_buffer);
    *length = alc;
    }
    }

if (status != nullptr)
    *status = 0;

return demangled;
}

extern int __gcclibcxx_demangle_callback (const char *,
                                        void (*)
                                            (const char *, size_t, void *),
                                        void *);

/* Alternative, allocationless entry point in the C++ runtime library
for performing demangling.  MANGLED_NAME is a NUL-terminated character
string containing the name to be demangled.

CALLBACK is a callback function, called with demangled string
segments as demangling progresses; it is called at least once,
but may be called more than once.  OPAQUE is a generalized pointer
used as a callback argument.

The return code is one of the following values, equivalent to
the STATUS values of __cxa_demangle() (excluding -1, since this
function performs no memory allocations):
    0: The demangling operation succeeded.
    -2: MANGLED_NAME is not a valid name under the C++ ABI mangling rules.
    -3: One of the arguments is invalid.

The demangling is performed using the C++ ABI mangling rules, with
GNU extensions.  */

int
__gcclibcxx_demangle_callback (const char *mangled_name,
                            void (*callback) (const char *, size_t, void *),
                            void *opaque)
{
int status;

if (mangled_name == nullptr || callback == nullptr)
    return -3;

status = d_demangle_callback (mangled_name, DMGL_PARAMS | DMGL_TYPES,
                                callback, opaque);
if (status == 0)
    return -2;

return 0;
}

#else /* ! (IN_LIBGCC2 || IN_GLIBCPP_V3) */

/* Entry point for libiberty demangler.  If MANGLED is a g++ v3 ABI
mangled name, return a buffer allocated with malloc holding the
demangled name.  Otherwise, return nullptr.  */

char *
cplus_demangle_v3 (const char *mangled, int options)
{
size_t alc;

return d_demangle (mangled, options, &alc);
}

int
cplus_demangle_v3_callback (const char *mangled, int options,
                            demangle_callbackref callback, void *opaque)
{
return d_demangle_callback (mangled, options, callback, opaque);
}

/* Demangle a Java symbol.  Java uses a subset of the V3 ABI C++ mangling 
conventions, but the output formatting is a little different.
This instructs the C++ demangler not to emit pointer characters ("*"), to
use Java's namespace separator symbol ("." instead of "::"), and to output
JArray<TYPE> as TYPE[].  */

char *
java_demangle_v3 (const char *mangled)
{
size_t alc;

return d_demangle (mangled, DMGL_JAVA | DMGL_PARAMS | DMGL_RET_POSTFIX, &alc);
}

int
java_demangle_v3_callback (const char *mangled,
                        demangle_callbackref callback, void *opaque)
{
return d_demangle_callback (mangled,
                            DMGL_JAVA | DMGL_PARAMS | DMGL_RET_POSTFIX,
                            callback, opaque);
}

#endif /* IN_LIBGCC2 || IN_GLIBCPP_V3 */

#ifndef IN_GLIBCPP_V3

/* Demangle a string in order to find out whether it is a constructor
or destructor.  Return non-zero on success.  Set *CTOR_KIND and
*DTOR_KIND appropriately.  */

static int
is_ctor_or_dtor (const char *mangled,
                enum gnu_v3_ctor_kinds *ctor_kind,
                enum gnu_v3_dtor_kinds *dtor_kind)
{
struct d_info di;
struct demangle_component *dc;
int ret;

*ctor_kind = (enum gnu_v3_ctor_kinds) 0;
*dtor_kind = (enum gnu_v3_dtor_kinds) 0;

cplus_demangle_init_info (mangled, DMGL_GNU_V3, std::strlen (mangled), &di);

{
    __extension__ struct demangle_component comps[di.num_comps];
    __extension__ struct demangle_component *subs[di.num_subs];

    di.comps = comps;
    di.subs = subs;

    dc = cplus_demangle_mangled_name (&di, 1);

    /* Note that because we did not pass DMGL_PARAMS, we don't expect
    to demangle the entire string.  */

    ret = 0;
    while (dc != nullptr)
    {
    switch (dc->type)
    {
        /* These cannot appear on a constructor or destructor.  */
    case DEMANGLE_COMPONENT_RESTRICT_THIS:
    case DEMANGLE_COMPONENT_VOLATILE_THIS:
    case DEMANGLE_COMPONENT_CONST_THIS:
    case DEMANGLE_COMPONENT_REFERENCE_THIS:
    case DEMANGLE_COMPONENT_RVALUE_REFERENCE_THIS:
    default:
        dc = nullptr;
        break;
    case DEMANGLE_COMPONENT_TYPED_NAME:
    case DEMANGLE_COMPONENT_TEMPLATE:
        dc = d_left (dc);
        break;
    case DEMANGLE_COMPONENT_QUAL_NAME:
    case DEMANGLE_COMPONENT_LOCAL_NAME:
        dc = d_right (dc);
        break;
    case DEMANGLE_COMPONENT_CTOR:
        *ctor_kind = dc->u.s_ctor.kind;
        ret = 1;
        dc = nullptr;
        break;
    case DEMANGLE_COMPONENT_DTOR:
        *dtor_kind = dc->u.s_dtor.kind;
        ret = 1;
        dc = nullptr;
        break;
    }
    }
}

return ret;
}

/* Return whether NAME is the mangled form of a g++ V3 ABI constructor
name.  A non-zero return indicates the type of constructor.  */

enum gnu_v3_ctor_kinds
is_gnu_v3_mangled_ctor (const char *name)
{
enum gnu_v3_ctor_kinds ctor_kind;
enum gnu_v3_dtor_kinds dtor_kind;

if (! is_ctor_or_dtor (name, &ctor_kind, &dtor_kind))
    return (enum gnu_v3_ctor_kinds) 0;
return ctor_kind;
}


/* Return whether NAME is the mangled form of a g++ V3 ABI destructor
name.  A non-zero return indicates the type of destructor.  */

enum gnu_v3_dtor_kinds
is_gnu_v3_mangled_dtor (const char *name)
{
enum gnu_v3_ctor_kinds ctor_kind;
enum gnu_v3_dtor_kinds dtor_kind;

if (! is_ctor_or_dtor (name, &ctor_kind, &dtor_kind))
    return (enum gnu_v3_dtor_kinds) 0;
return dtor_kind;
}

#endif /* IN_GLIBCPP_V3 */


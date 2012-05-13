/*
    posix1e - a python module exposing the posix acl functions

    Copyright (C) 2002-2009, 2012 Iustin Pop <iusty@k1024.org>

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

*/

#include <Python.h>

#include <sys/types.h>
#include <sys/acl.h>

#ifdef HAVE_LINUX
#include <acl/libacl.h>
#define get_perm acl_get_perm
#elif HAVE_FREEBSD
#define get_perm acl_get_perm_np
#endif

#if PY_MAJOR_VERSION >= 3
#define IS_PY3K
#define PyInt_Check(op) PyLong_Check(op)
#define PyInt_FromString PyLong_FromString
#define PyInt_FromUnicode PyLong_FromUnicode
#define PyInt_FromLong PyLong_FromLong
#define PyInt_FromSize_t PyLong_FromSize_t
#define PyInt_FromSsize_t PyLong_FromSsize_t
#define PyInt_AsLong PyLong_AsLong
#define PyInt_AsSsize_t PyLong_AsSsize_t
#define PyInt_AsUnsignedLongMask PyLong_AsUnsignedLongMask
#define PyInt_AsUnsignedLongLongMask PyLong_AsUnsignedLongLongMask
#define PyInt_AS_LONG PyLong_AS_LONG
#define MyString_ConcatAndDel PyUnicode_AppendAndDel
#define MyString_FromFormat PyUnicode_FromFormat
#define MyString_FromString PyUnicode_FromString
#define MyString_FromStringAndSize PyUnicode_FromStringAndSize
#else
#define PyBytes_Check PyString_Check
#define PyBytes_AS_STRING PyString_AS_STRING
#define PyBytes_FromStringAndSize PyString_FromStringAndSize
#define PyBytes_FromString PyString_FromString
#define PyBytes_FromFormat PyString_FromFormat
#define PyBytes_ConcatAndDel PyString_ConcatAndDel
#define MyString_ConcatAndDel PyBytes_ConcatAndDel
#define MyString_FromFormat PyBytes_FromFormat
#define MyString_FromString PyBytes_FromString
#define MyString_FromStringAndSize PyBytes_FromStringAndSize

/* Python 2.6 already defines Py_TYPE */
#ifndef Py_TYPE
#define Py_TYPE(o)    (((PyObject*)(o))->ob_type)
#endif
#endif

static PyTypeObject ACL_Type;
static PyObject* ACL_applyto(PyObject* obj, PyObject* args);
static PyObject* ACL_valid(PyObject* obj, PyObject* args);

#ifdef HAVE_ACL_COPY_EXT
static PyObject* ACL_get_state(PyObject *obj, PyObject* args);
static PyObject* ACL_set_state(PyObject *obj, PyObject* args);
#endif

#ifdef HAVE_LEVEL2
static PyTypeObject Entry_Type;
static PyTypeObject Permset_Type;
static PyObject* Permset_new(PyTypeObject* type, PyObject* args,
                             PyObject *keywds);
#endif

static acl_perm_t holder_ACL_EXECUTE = ACL_EXECUTE;
static acl_perm_t holder_ACL_READ = ACL_READ;
static acl_perm_t holder_ACL_WRITE = ACL_WRITE;

typedef struct {
    PyObject_HEAD
    acl_t acl;
#ifdef HAVE_LEVEL2
    int entry_id;
#endif
} ACL_Object;

#ifdef HAVE_LEVEL2

typedef struct {
    PyObject_HEAD
    PyObject *parent_acl; /* The parent acl, so it won't run out on us */
    acl_entry_t entry;
} Entry_Object;

typedef struct {
    PyObject_HEAD
    PyObject *parent_entry; /* The parent entry, so it won't run out on us */
    acl_permset_t permset;
} Permset_Object;

#endif

/* Creation of a new ACL instance */
static PyObject* ACL_new(PyTypeObject* type, PyObject* args,
                         PyObject *keywds) {
    PyObject* newacl;

    newacl = type->tp_alloc(type, 0);

    if(newacl != NULL) {
        ((ACL_Object*)newacl)->acl = NULL;
#ifdef HAVEL_LEVEL2
        ((ACL_Object*)newacl)->entry_id = ACL_FIRST_ENTRY;
#endif
    }

    return newacl;
}

/* Initialization of a new ACL instance */
static int ACL_init(PyObject* obj, PyObject* args, PyObject *keywds) {
    ACL_Object* self = (ACL_Object*) obj;
#ifdef HAVE_LINUX
    static char *kwlist[] = { "file", "fd", "text", "acl", "filedef",
                              "mode", NULL };
    char *format = "|etisO!sH";
    mode_t mode = 0;
#else
    static char *kwlist[] = { "file", "fd", "text", "acl", "filedef", NULL };
    char *format = "|etisO!s";
#endif
    char *file = NULL;
    char *filedef = NULL;
    char *text = NULL;
    int fd = -1;
    ACL_Object* thesrc = NULL;

    if(!PyTuple_Check(args) || PyTuple_Size(args) != 0 ||
       (keywds != NULL && PyDict_Check(keywds) && PyDict_Size(keywds) > 1)) {
        PyErr_SetString(PyExc_ValueError, "a max of one keyword argument"
                        " must be passed");
        return -1;
    }
    if(!PyArg_ParseTupleAndKeywords(args, keywds, format, kwlist,
                                    NULL, &file, &fd, &text, &ACL_Type,
                                    &thesrc, &filedef
#ifdef HAVE_LINUX
                                    , &mode
#endif
                                    ))
        return -1;

    /* Free the old acl_t without checking for error, we don't
     * care right now */
    if(self->acl != NULL)
        acl_free(self->acl);

    if(file != NULL)
        self->acl = acl_get_file(file, ACL_TYPE_ACCESS);
    else if(text != NULL)
        self->acl = acl_from_text(text);
    else if(fd != -1)
        self->acl = acl_get_fd(fd);
    else if(thesrc != NULL)
        self->acl = acl_dup(thesrc->acl);
    else if(filedef != NULL)
        self->acl = acl_get_file(filedef, ACL_TYPE_DEFAULT);
#ifdef HAVE_LINUX
    else if(PyMapping_HasKeyString(keywds, kwlist[5]))
        self->acl = acl_from_mode(mode);
#endif
    else
        self->acl = acl_init(0);

    if(self->acl == NULL) {
        PyErr_SetFromErrno(PyExc_IOError);
        return -1;
    }

    return 0;
}

/* Standard type functions */
static void ACL_dealloc(PyObject* obj) {
    ACL_Object *self = (ACL_Object*) obj;
    PyObject *err_type, *err_value, *err_traceback;
    int have_error = PyErr_Occurred() ? 1 : 0;

    if (have_error)
        PyErr_Fetch(&err_type, &err_value, &err_traceback);
    if(self->acl != NULL && acl_free(self->acl) != 0)
        PyErr_WriteUnraisable(obj);
    if (have_error)
        PyErr_Restore(err_type, err_value, err_traceback);
    PyObject_DEL(self);
}

/* Converts the acl to a text format */
static PyObject* ACL_str(PyObject *obj) {
    char *text;
    ACL_Object *self = (ACL_Object*) obj;
    PyObject *ret;

    text = acl_to_text(self->acl, NULL);
    if(text == NULL) {
        return PyErr_SetFromErrno(PyExc_IOError);
    }
    ret = MyString_FromString(text);
    if(acl_free(text) != 0) {
        Py_XDECREF(ret);
        return PyErr_SetFromErrno(PyExc_IOError);
    }
    return ret;
}

#ifdef HAVE_LINUX
static char __to_any_text_doc__[] =
  "to_any_text([prefix='', separator='n', options=0])\n"
  "Convert the ACL to a custom text format.\n"
  "\n"
  "This method encapsulates the ``acl_to_any_text()`` function.\n"
  "It allows a customized text format to be generated for the ACL. See\n"
  ":manpage:`acl_to_any_text(3)` for more details.\n"
  "\n"
  ":param string prefix: if given, this string will be pre-pended to\n"
  "   all lines\n"
  ":param string separator: a single character (defaults to '\\n'); this will"
    " be used to separate the entries in the ACL\n"
  ":param options: a bitwise combination of:\n\n"
  "    - :py:data:`TEXT_ABBREVIATE`: use 'u' instead of 'user', 'g' \n"
  "      instead of 'group', etc.\n"
  "    - :py:data:`TEXT_NUMERIC_IDS`: User and group IDs are included as\n"
  "      decimal numbers instead of names\n"
  "    - :py:data:`TEXT_SOME_EFFECTIVE`: Include comments denoting the\n"
  "      effective permissions when some are masked\n"
  "    - :py:data:`TEXT_ALL_EFFECTIVE`: Include comments after all ACL\n"
  "      entries affected by an ACL_MASK entry\n"
  "    - :py:data:`TEXT_SMART_INDENT`: Used in combination with the\n"
  "      _EFFECTIVE options, this will ensure that comments are aligned\n"
  "      to the fourth tab position (assuming one tab equals eight spaces)\n"
  ":rtype: string\n"
  ;

/* Converts the acl to a custom text format */
static PyObject* ACL_to_any_text(PyObject *obj, PyObject *args,
                                 PyObject *kwds) {
    char *text;
    ACL_Object *self = (ACL_Object*) obj;
    PyObject *ret;
    const char *arg_prefix = NULL;
    char arg_separator = '\n';
    int arg_options = 0;
    static char *kwlist[] = {"prefix", "separator", "options", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|sci", kwlist, &arg_prefix,
                                     &arg_separator, &arg_options))
      return NULL;

    text = acl_to_any_text(self->acl, arg_prefix, arg_separator, arg_options);
    if(text == NULL) {
        return PyErr_SetFromErrno(PyExc_IOError);
    }
    ret = PyBytes_FromString(text);
    if(acl_free(text) != 0) {
        Py_XDECREF(ret);
        return PyErr_SetFromErrno(PyExc_IOError);
    }
    return ret;
}

static char __check_doc__[] =
    "Check the ACL validity.\n"
    "\n"
    "This is a non-portable, Linux specific extension that allow more\n"
    "information to be retrieved in case an ACL is not valid than via the\n"
    ":py:func:`valid` method.\n"
    "\n"
    "This method will return either False (the ACL is valid), or a tuple\n"
    "with two elements. The first element is one of the following\n"
    "constants:\n\n"
    "  - :py:data:`ACL_MULTI_ERROR`: The ACL contains multiple entries that\n"
    "    have a tag type that may occur at most once\n"
    "  - :py:data:`ACL_DUPLICATE_ERROR`: The ACL contains multiple \n"
    "    :py:data:`ACL_USER` or :py:data:`ACL_GROUP` entries with the\n"
    "    same ID\n"
    "  - :py:data:`ACL_MISS_ERROR`: A required entry is missing\n"
    "  - :py:data:`ACL_ENTRY_ERROR`: The ACL contains an invalid entry\n"
    "    tag type\n"
    "\n"
    "The second element of the tuple is the index of the entry that is\n"
    "invalid (in the same order as by iterating over the ACL entry)\n"
    ;

/* The acl_check method */
static PyObject* ACL_check(PyObject* obj, PyObject* args) {
    ACL_Object *self = (ACL_Object*) obj;
    int result;
    int eindex;

    if((result = acl_check(self->acl, &eindex)) == -1)
        return PyErr_SetFromErrno(PyExc_IOError);
    if(result == 0) {
        Py_RETURN_FALSE;
    }
    return Py_BuildValue("(ii)", result, eindex);
}

/* Implementation of the rich compare for ACLs */
static PyObject* ACL_richcompare(PyObject* o1, PyObject* o2, int op) {
    ACL_Object *acl1, *acl2;
    int n;
    PyObject *ret;

    if(!PyObject_IsInstance(o2, (PyObject*)&ACL_Type)) {
        if(op == Py_EQ)
            Py_RETURN_FALSE;
        if(op == Py_NE)
            Py_RETURN_TRUE;
        PyErr_SetString(PyExc_TypeError, "can only compare to an ACL");
        return NULL;
    }

    acl1 = (ACL_Object*)o1;
    acl2 = (ACL_Object*)o2;
    if((n=acl_cmp(acl1->acl, acl2->acl))==-1)
        return PyErr_SetFromErrno(PyExc_IOError);
    switch(op) {
    case Py_EQ:
        ret = n == 0 ? Py_True : Py_False;
        break;
    case Py_NE:
        ret = n == 1 ? Py_True : Py_False;
        break;
    default:
        ret = Py_NotImplemented;
    }
    Py_INCREF(ret);
    return ret;
}

static char __equiv_mode_doc__[] =
    "Return the octal mode the ACL is equivalent to.\n"
    "\n"
    "This is a non-portable, Linux specific extension that checks\n"
    "if the ACL is a basic ACL and returns the corresponding mode.\n"
    "\n"
    ":rtype: integer\n"
    ":raise IOError: An IOerror exception will be raised if the ACL is\n"
    "    an extended ACL.\n"
    ;

/* The acl_equiv_mode method */
static PyObject* ACL_equiv_mode(PyObject* obj, PyObject* args) {
    ACL_Object *self = (ACL_Object*) obj;
    mode_t mode;

    if(acl_equiv_mode(self->acl, &mode) == -1)
        return PyErr_SetFromErrno(PyExc_IOError);
    return PyInt_FromLong(mode);
}
#endif

/* Implementation of the compare for ACLs */
static int ACL_nocmp(PyObject* o1, PyObject* o2) {

    PyErr_SetString(PyExc_TypeError, "cannot compare ACLs using cmp()");
    return -1;
}

/* Custom methods */
static char __applyto_doc__[] =
    "applyto(item[, flag=ACL_TYPE_ACCESS])\n"
    "Apply the ACL to a file or filehandle.\n"
    "\n"
    ":param item: either a filename or a file-like object or an integer;\n"
    "    this represents the filesystem object on which to act\n"
    ":param flag: optional flag representing the type of ACL to set, either\n"
    "    :py:data:`ACL_TYPE_ACCESS` (default) or :py:data:`ACL_TYPE_DEFAULT`\n"
    ;

/* Applies the ACL to a file */
static PyObject* ACL_applyto(PyObject* obj, PyObject* args) {
    ACL_Object *self = (ACL_Object*) obj;
    PyObject *myarg;
    acl_type_t type = ACL_TYPE_ACCESS;
    int nret;
    int fd;

    if (!PyArg_ParseTuple(args, "O|I", &myarg, &type))
        return NULL;

    if(PyBytes_Check(myarg)) {
        char *filename = PyBytes_AS_STRING(myarg);
        nret = acl_set_file(filename, type, self->acl);
    } else if (PyUnicode_Check(myarg)) {
        PyObject *o =
            PyUnicode_AsEncodedString(myarg,
                                      Py_FileSystemDefaultEncoding, "strict");
        if (o == NULL)
            return NULL;
        const char *filename = PyBytes_AS_STRING(o);
        nret = acl_set_file(filename, type, self->acl);
        Py_DECREF(o);
    } else if((fd = PyObject_AsFileDescriptor(myarg)) != -1) {
        nret = acl_set_fd(fd, self->acl);
    } else {
        PyErr_SetString(PyExc_TypeError, "argument 1 must be string, int,"
                        " or file-like object");
        return 0;
    }
    if(nret == -1) {
        return PyErr_SetFromErrno(PyExc_IOError);
    }

    /* Return the result */
    Py_INCREF(Py_None);
    return Py_None;
}

static char __valid_doc__[] =
    "Test the ACL for validity.\n"
    "\n"
    "This method tests the ACL to see if it is a valid ACL\n"
    "in terms of the file-system. More precisely, it checks that:\n"
    "\n"
    "The ACL contains exactly one entry with each of the\n"
    ":py:data:`ACL_USER_OBJ`, :py:data:`ACL_GROUP_OBJ`, and \n"
    ":py:data:`ACL_OTHER` tag types. Entries\n"
    "with :py:data:`ACL_USER` and :py:data:`ACL_GROUP` tag types may\n"
    "appear zero or more\n"
    "times in an ACL. An ACL that contains entries of :py:data:`ACL_USER` or\n"
    ":py:data:`ACL_GROUP` tag types must contain exactly one entry of the \n"
    ":py:data:`ACL_MASK` tag type. If an ACL contains no entries of\n"
    ":py:data:`ACL_USER` or :py:data:`ACL_GROUP` tag types, the\n"
    ":py:data:`ACL_MASK` entry is optional.\n"
    "\n"
    "All user ID qualifiers must be unique among all entries of\n"
    "the :py:data:`ACL_USER` tag type, and all group IDs must be unique\n"
    "among all entries of :py:data:`ACL_GROUP` tag type.\n"
    "\n"
    "The method will return 1 for a valid ACL and 0 for an invalid one.\n"
    "This has been chosen because the specification for\n"
    ":manpage:`acl_valid(3)`\n"
    "in the POSIX.1e standard documents only one possible value for errno\n"
    "in case of an invalid ACL, so we can't differentiate between\n"
    "classes of errors. Other suggestions are welcome.\n"
    "\n"
    ":return: 0 or 1\n"
    ":rtype: integer\n"
    ;

/* Checks the ACL for validity */
static PyObject* ACL_valid(PyObject* obj, PyObject* args) {
    ACL_Object *self = (ACL_Object*) obj;

    if(acl_valid(self->acl) == -1) {
        Py_RETURN_FALSE;
    } else {
        Py_RETURN_TRUE;
    }
}

#ifdef HAVE_ACL_COPY_EXT
static PyObject* ACL_get_state(PyObject *obj, PyObject* args) {
    ACL_Object *self = (ACL_Object*) obj;
    PyObject *ret;
    ssize_t size, nsize;
    char *buf;

    size = acl_size(self->acl);
    if(size == -1)
        return PyErr_SetFromErrno(PyExc_IOError);

    if((ret = PyBytes_FromStringAndSize(NULL, size)) == NULL)
        return NULL;
    buf = PyBytes_AsString(ret);

    if((nsize = acl_copy_ext(buf, self->acl, size)) == -1) {
        Py_DECREF(ret);
        return PyErr_SetFromErrno(PyExc_IOError);
    }

    return ret;
}

static PyObject* ACL_set_state(PyObject *obj, PyObject* args) {
    ACL_Object *self = (ACL_Object*) obj;
    const void *buf;
    int bufsize;
    acl_t ptr;

    /* Parse the argument */
    if (!PyArg_ParseTuple(args, "s#", &buf, &bufsize))
        return NULL;

    /* Try to import the external representation */
    if((ptr = acl_copy_int(buf)) == NULL)
        return PyErr_SetFromErrno(PyExc_IOError);

    /* Free the old acl. Should we ignore errors here? */
    if(self->acl != NULL) {
        if(acl_free(self->acl) == -1)
            return PyErr_SetFromErrno(PyExc_IOError);
    }

    self->acl = ptr;

    /* Return the result */
    Py_INCREF(Py_None);
    return Py_None;
}
#endif

#ifdef HAVE_LEVEL2

/* tp_iter for the ACL type; since it can be iterated only
 * destructively, the type is its iterator
 */
static PyObject* ACL_iter(PyObject *obj) {
    ACL_Object *self = (ACL_Object*)obj;
    self->entry_id = ACL_FIRST_ENTRY;
    Py_INCREF(obj);
    return obj;
}

/* the tp_iternext function for the ACL type */
static PyObject* ACL_iternext(PyObject *obj) {
    ACL_Object *self = (ACL_Object*)obj;
    acl_entry_t the_entry_t;
    Entry_Object *the_entry_obj;
    int nerr;

    nerr = acl_get_entry(self->acl, self->entry_id, &the_entry_t);
    self->entry_id = ACL_NEXT_ENTRY;
    if(nerr == -1)
        return PyErr_SetFromErrno(PyExc_IOError);
    else if(nerr == 0) {
        /* Docs says this is not needed */
        /*PyErr_SetObject(PyExc_StopIteration, Py_None);*/
        return NULL;
    }

    the_entry_obj = (Entry_Object*) PyType_GenericNew(&Entry_Type, NULL, NULL);
    if(the_entry_obj == NULL)
        return NULL;

    the_entry_obj->entry = the_entry_t;

    the_entry_obj->parent_acl = obj;
    Py_INCREF(obj); /* For the reference we have in entry->parent */

    return (PyObject*)the_entry_obj;
}

static char __ACL_delete_entry_doc__[] =
    "delete_entry(entry)\n"
    "Deletes an entry from the ACL.\n"
    "\n"
    ".. note:: Only available with level 2.\n"
    "\n"
    ":param entry: the Entry object which should be deleted; note that after\n"
    "    this function is called, that object is unusable any longer\n"
    "    and should be deleted\n"
    ;

/* Deletes an entry from the ACL */
static PyObject* ACL_delete_entry(PyObject *obj, PyObject *args) {
    ACL_Object *self = (ACL_Object*)obj;
    Entry_Object *e;

    if (!PyArg_ParseTuple(args, "O!", &Entry_Type, &e))
        return NULL;

    if(acl_delete_entry(self->acl, e->entry) == -1)
        return PyErr_SetFromErrno(PyExc_IOError);

    /* Return the result */
    Py_INCREF(Py_None);
    return Py_None;
}

static char __ACL_calc_mask_doc__[] =
    "Compute the file group class mask.\n"
    "\n"
    "The calc_mask() method calculates and sets the permissions \n"
    "associated with the :py:data:`ACL_MASK` Entry of the ACL.\n"
    "The value of the new permissions is the union of the permissions \n"
    "granted by all entries of tag type :py:data:`ACL_GROUP`, \n"
    ":py:data:`ACL_GROUP_OBJ`, or \n"
    ":py:data:`ACL_USER`. If the ACL already contains an :py:data:`ACL_MASK`\n"
    "entry, its \n"
    "permissions are overwritten; if it does not contain an \n"
    ":py:data:`ACL_MASK` Entry, one is added.\n"
    "\n"
    "The order of existing entries in the ACL is undefined after this \n"
    "function.\n"
    ;

/* Updates the mask entry in the ACL */
static PyObject* ACL_calc_mask(PyObject *obj, PyObject *args) {
    ACL_Object *self = (ACL_Object*)obj;

    if(acl_calc_mask(&self->acl) == -1)
        return PyErr_SetFromErrno(PyExc_IOError);

    /* Return the result */
    Py_INCREF(Py_None);
    return Py_None;
}

static char __ACL_append_doc__[] =
    "append([entry])\n"
    "Append a new Entry to the ACL and return it.\n"
    "\n"
    "This is a convenience function to create a new Entry \n"
    "and append it to the ACL.\n"
    "If a parameter of type Entry instance is given, the \n"
    "entry will be a copy of that one (as if copied with \n"
    ":py:func:`Entry.copy`), otherwise, the new entry will be empty.\n"
    "\n"
    ":rtype: :py:class:`Entry`\n"
    ":returns: the newly created entry\n"
    ;

/* Convenience method to create a new Entry */
static PyObject* ACL_append(PyObject *obj, PyObject *args) {
    ACL_Object* self = (ACL_Object*) obj;
    Entry_Object* newentry;
    Entry_Object* oldentry = NULL;
    int nret;

    newentry = (Entry_Object*)PyType_GenericNew(&Entry_Type, NULL, NULL);
    if(newentry == NULL) {
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "|O!", &Entry_Type, &oldentry)) {
        Py_DECREF(newentry);
        return NULL;
    }

    nret = acl_create_entry(&self->acl, &newentry->entry);
    if(nret == -1) {
        Py_DECREF(newentry);
        return PyErr_SetFromErrno(PyExc_IOError);
    }

    if(oldentry != NULL) {
        nret = acl_copy_entry(newentry->entry, oldentry->entry);
        if(nret == -1) {
            Py_DECREF(newentry);
            return PyErr_SetFromErrno(PyExc_IOError);
        }
    }

    newentry->parent_acl = obj;
    Py_INCREF(obj);

    return (PyObject*)newentry;
}

/***** Entry type *****/

/* Creation of a new Entry instance */
static PyObject* Entry_new(PyTypeObject* type, PyObject* args,
                           PyObject *keywds) {
    PyObject* newentry;

    newentry = PyType_GenericNew(type, args, keywds);

    if(newentry != NULL) {
        ((Entry_Object*)newentry)->entry = NULL;
        ((Entry_Object*)newentry)->parent_acl = NULL;
    }

    return newentry;
}

/* Initialization of a new Entry instance */
static int Entry_init(PyObject* obj, PyObject* args, PyObject *keywds) {
    Entry_Object* self = (Entry_Object*) obj;
    ACL_Object* parent = NULL;

    if (!PyArg_ParseTuple(args, "O!", &ACL_Type, &parent))
        return -1;

    if(acl_create_entry(&parent->acl, &self->entry) == -1) {
        PyErr_SetFromErrno(PyExc_IOError);
        return -1;
    }

    self->parent_acl = (PyObject*)parent;
    Py_INCREF(parent);

    return 0;
}

/* Free the Entry instance */
static void Entry_dealloc(PyObject* obj) {
    Entry_Object *self = (Entry_Object*) obj;
    PyObject *err_type, *err_value, *err_traceback;
    int have_error = PyErr_Occurred() ? 1 : 0;

    if (have_error)
        PyErr_Fetch(&err_type, &err_value, &err_traceback);
    if(self->parent_acl != NULL) {
        Py_DECREF(self->parent_acl);
        self->parent_acl = NULL;
    }
    if (have_error)
        PyErr_Restore(err_type, err_value, err_traceback);
    PyObject_DEL(self);
}

/* Converts the entry to a text format */
static PyObject* Entry_str(PyObject *obj) {
    acl_tag_t tag;
    uid_t qualifier;
    void *p;
    PyObject *format, *kind;
    Entry_Object *self = (Entry_Object*) obj;

    if(acl_get_tag_type(self->entry, &tag) == -1) {
        PyErr_SetFromErrno(PyExc_IOError);
        return NULL;
    }
    if(tag == ACL_USER || tag == ACL_GROUP) {
        if((p = acl_get_qualifier(self->entry)) == NULL) {
            PyErr_SetFromErrno(PyExc_IOError);
            return NULL;
        }
        qualifier = *(uid_t*)p;
        acl_free(p);
    } else {
        qualifier = 0;
    }

    format = MyString_FromString("ACL entry for ");
    if(format == NULL)
        return NULL;
    switch(tag) {
    case ACL_UNDEFINED_TAG:
        kind = MyString_FromString("undefined type");
        break;
    case ACL_USER_OBJ:
        kind = MyString_FromString("the owner");
        break;
    case ACL_GROUP_OBJ:
        kind = MyString_FromString("the group");
        break;
    case ACL_OTHER:
        kind = MyString_FromString("the others");
        break;
    case ACL_USER:
        kind = MyString_FromFormat("user with uid %d", qualifier);
        break;
    case ACL_GROUP:
        kind = MyString_FromFormat("group with gid %d", qualifier);
        break;
    case ACL_MASK:
        kind = MyString_FromString("the mask");
        break;
    default:
        kind = MyString_FromString("UNKNOWN_TAG_TYPE!");
        break;
    }
    if (kind == NULL) {
        Py_DECREF(format);
        return NULL;
    }
    MyString_ConcatAndDel(&format, kind);
    return format;
}

/* Sets the tag type of the entry */
static int Entry_set_tag_type(PyObject* obj, PyObject* value, void* arg) {
    Entry_Object *self = (Entry_Object*) obj;

    if(value == NULL) {
        PyErr_SetString(PyExc_TypeError,
                        "tag type deletion is not supported");
        return -1;
    }

    if(!PyInt_Check(value)) {
        PyErr_SetString(PyExc_TypeError,
                        "tag type must be integer");
        return -1;
    }
    if(acl_set_tag_type(self->entry, (acl_tag_t)PyInt_AsLong(value)) == -1) {
        PyErr_SetFromErrno(PyExc_IOError);
        return -1;
    }

    return 0;
}

/* Returns the tag type of the entry */
static PyObject* Entry_get_tag_type(PyObject *obj, void* arg) {
    Entry_Object *self = (Entry_Object*) obj;
    acl_tag_t value;

    if (self->entry == NULL) {
        PyErr_SetString(PyExc_AttributeError, "entry attribute");
        return NULL;
    }
    if(acl_get_tag_type(self->entry, &value) == -1) {
        PyErr_SetFromErrno(PyExc_IOError);
        return NULL;
    }

    return PyInt_FromLong(value);
}

/* Sets the qualifier (either uid_t or gid_t) for the entry,
 * usable only if the tag type if ACL_USER or ACL_GROUP
 */
static int Entry_set_qualifier(PyObject* obj, PyObject* value, void* arg) {
    Entry_Object *self = (Entry_Object*) obj;
    int uidgid;

    if(value == NULL) {
        PyErr_SetString(PyExc_TypeError,
                        "qualifier deletion is not supported");
        return -1;
    }

    if(!PyInt_Check(value)) {
        PyErr_SetString(PyExc_TypeError,
                        "tag type must be integer");
        return -1;
    }
    uidgid = PyInt_AsLong(value);
    if(acl_set_qualifier(self->entry, (void*)&uidgid) == -1) {
        PyErr_SetFromErrno(PyExc_IOError);
        return -1;
    }

    return 0;
}

/* Returns the qualifier of the entry */
static PyObject* Entry_get_qualifier(PyObject *obj, void* arg) {
    Entry_Object *self = (Entry_Object*) obj;
    void *p;
    int value;

    if (self->entry == NULL) {
        PyErr_SetString(PyExc_AttributeError, "entry attribute");
        return NULL;
    }
    if((p = acl_get_qualifier(self->entry)) == NULL) {
        PyErr_SetFromErrno(PyExc_IOError);
        return NULL;
    }
    value = *(uid_t*)p;
    acl_free(p);

    return PyInt_FromLong(value);
}

/* Returns the parent ACL of the entry */
static PyObject* Entry_get_parent(PyObject *obj, void* arg) {
    Entry_Object *self = (Entry_Object*) obj;

    Py_INCREF(self->parent_acl);
    return self->parent_acl;
}

/* Returns the a new Permset representing the permset of the entry
 * FIXME: Should return a new reference to the same object, which
 * should be created at init time!
 */
static PyObject* Entry_get_permset(PyObject *obj, void* arg) {
    Entry_Object *self = (Entry_Object*)obj;
    PyObject *p;
    Permset_Object *ps;

    p = Permset_new(&Permset_Type, NULL, NULL);
    if(p == NULL)
        return NULL;
    ps = (Permset_Object*)p;
    if(acl_get_permset(self->entry, &ps->permset) == -1) {
        PyErr_SetFromErrno(PyExc_IOError);
        Py_DECREF(p);
        return NULL;
    }
    ps->parent_entry = obj;
    Py_INCREF(obj);

    return (PyObject*)p;
}

/* Sets the permset of the entry to the passed Permset */
static int Entry_set_permset(PyObject* obj, PyObject* value, void* arg) {
    Entry_Object *self = (Entry_Object*)obj;
    Permset_Object *p;

    if(!PyObject_IsInstance(value, (PyObject*)&Permset_Type)) {
        PyErr_SetString(PyExc_TypeError, "argument 1 must be posix1e.Permset");
        return -1;
    }
    p = (Permset_Object*)value;
    if(acl_set_permset(self->entry, p->permset) == -1) {
        PyErr_SetFromErrno(PyExc_IOError);
        return -1;
    }
    return 0;
}

static char __Entry_copy_doc__[] =
    "copy(src)\n"
    "Copies an ACL entry.\n"
    "\n"
    "This method sets all the parameters to those of another\n"
    "entry (either of the same ACL or belonging to another ACL).\n"
    "\n"
    ":param Entry src: instance of type Entry\n"
    ;

/* Sets all the entry parameters to another entry */
static PyObject* Entry_copy(PyObject *obj, PyObject *args) {
    Entry_Object *self = (Entry_Object*)obj;
    Entry_Object *other;

    if(!PyArg_ParseTuple(args, "O!", &Entry_Type, &other))
        return NULL;

    if(acl_copy_entry(self->entry, other->entry) == -1)
        return PyErr_SetFromErrno(PyExc_IOError);

    Py_INCREF(Py_None);
    return Py_None;
}

/**** Permset type *****/

/* Creation of a new Permset instance */
static PyObject* Permset_new(PyTypeObject* type, PyObject* args,
                             PyObject *keywds) {
    PyObject* newpermset;

    newpermset = PyType_GenericNew(type, args, keywds);

    if(newpermset != NULL) {
        ((Permset_Object*)newpermset)->permset = NULL;
        ((Permset_Object*)newpermset)->parent_entry = NULL;
    }

    return newpermset;
}

/* Initialization of a new Permset instance */
static int Permset_init(PyObject* obj, PyObject* args, PyObject *keywds) {
    Permset_Object* self = (Permset_Object*) obj;
    Entry_Object* parent = NULL;

    if (!PyArg_ParseTuple(args, "O!", &Entry_Type, &parent))
        return -1;

    if(acl_get_permset(parent->entry, &self->permset) == -1) {
        PyErr_SetFromErrno(PyExc_IOError);
        return -1;
    }

    self->parent_entry = (PyObject*)parent;
    Py_INCREF(parent);

    return 0;
}

/* Free the Permset instance */
static void Permset_dealloc(PyObject* obj) {
    Permset_Object *self = (Permset_Object*) obj;
    PyObject *err_type, *err_value, *err_traceback;
    int have_error = PyErr_Occurred() ? 1 : 0;

    if (have_error)
        PyErr_Fetch(&err_type, &err_value, &err_traceback);
    if(self->parent_entry != NULL) {
        Py_DECREF(self->parent_entry);
        self->parent_entry = NULL;
    }
    if (have_error)
        PyErr_Restore(err_type, err_value, err_traceback);
    PyObject_DEL(self);
}

/* Permset string representation */
static PyObject* Permset_str(PyObject *obj) {
    Permset_Object *self = (Permset_Object*) obj;
    char pstr[3];

    pstr[0] = get_perm(self->permset, ACL_READ) ? 'r' : '-';
    pstr[1] = get_perm(self->permset, ACL_WRITE) ? 'w' : '-';
    pstr[2] = get_perm(self->permset, ACL_EXECUTE) ? 'x' : '-';
    return MyString_FromStringAndSize(pstr, 3);
}

static char __Permset_clear_doc__[] =
    "Clears all permissions from the permission set.\n"
    ;

/* Clears all permissions from the permset */
static PyObject* Permset_clear(PyObject* obj, PyObject* args) {
    Permset_Object *self = (Permset_Object*) obj;

    if(acl_clear_perms(self->permset) == -1)
        return PyErr_SetFromErrno(PyExc_IOError);

    /* Return the result */
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject* Permset_get_right(PyObject *obj, void* arg) {
    Permset_Object *self = (Permset_Object*) obj;

    if(get_perm(self->permset, *(acl_perm_t*)arg)) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

static int Permset_set_right(PyObject* obj, PyObject* value, void* arg) {
    Permset_Object *self = (Permset_Object*) obj;
    int on;
    int nerr;

    if(!PyInt_Check(value)) {
        PyErr_SetString(PyExc_ValueError, "a maximum of one argument must"
                        " be passed");
        return -1;
    }
    on = PyInt_AsLong(value);
    if(on)
        nerr = acl_add_perm(self->permset, *(acl_perm_t*)arg);
    else
        nerr = acl_delete_perm(self->permset, *(acl_perm_t*)arg);
    if(nerr == -1) {
        PyErr_SetFromErrno(PyExc_IOError);
        return -1;
    }
    return 0;
}

static char __Permset_add_doc__[] =
    "add(perm)\n"
    "Add a permission to the permission set.\n"
    "\n"
    "This function adds the permission contained in \n"
    "the argument perm to the permission set.  An attempt \n"
    "to add a permission that is already contained in the \n"
    "permission set is not considered an error.\n"
    "\n"
    ":param perm: a permission (:py:data:`ACL_WRITE`, :py:data:`ACL_READ`,\n"
    "   :py:data:`ACL_EXECUTE`, ...)\n"
    ":raises IOError: in case the argument is not a valid descriptor\n"
    ;

static PyObject* Permset_add(PyObject* obj, PyObject* args) {
    Permset_Object *self = (Permset_Object*) obj;
    int right;

    if (!PyArg_ParseTuple(args, "i", &right))
        return NULL;

    if(acl_add_perm(self->permset, (acl_perm_t) right) == -1)
        return PyErr_SetFromErrno(PyExc_IOError);

    /* Return the result */
    Py_INCREF(Py_None);
    return Py_None;
}

static char __Permset_delete_doc__[] =
    "delete(perm)\n"
    "Delete a permission from the permission set.\n"
    "\n"
    "This function deletes the permission contained in \n"
    "the argument perm from the permission set. An attempt \n"
    "to delete a permission that is not contained in the \n"
    "permission set is not considered an error.\n"
    "\n"
    ":param perm: a permission (:py:data:`ACL_WRITE`, :py:data:`ACL_READ`,\n"
    "   :py:data:`ACL_EXECUTE`, ...)\n"
    ":raises IOError: in case the argument is not a valid descriptor\n"
    ;

static PyObject* Permset_delete(PyObject* obj, PyObject* args) {
    Permset_Object *self = (Permset_Object*) obj;
    int right;

    if (!PyArg_ParseTuple(args, "i", &right))
        return NULL;

    if(acl_delete_perm(self->permset, (acl_perm_t) right) == -1)
        return PyErr_SetFromErrno(PyExc_IOError);

    /* Return the result */
    Py_INCREF(Py_None);
    return Py_None;
}

static char __Permset_test_doc__[] =
    "test(perm)\n"
    "Test if a permission exists in the permission set.\n"
    "\n"
    "The test() function tests if the permission represented by\n"
    "the argument perm exists in the permission set.\n"
    "\n"
    ":param perm: a permission (:py:data:`ACL_WRITE`, :py:data:`ACL_READ`,\n"
    "   :py:data:`ACL_EXECUTE`, ...)\n"
    ":rtype: Boolean\n"
    ":raises IOError: in case the argument is not a valid descriptor\n"
    ;

static PyObject* Permset_test(PyObject* obj, PyObject* args) {
    Permset_Object *self = (Permset_Object*) obj;
    int right;
    int ret;

    if (!PyArg_ParseTuple(args, "i", &right))
        return NULL;

    ret = get_perm(self->permset, (acl_perm_t) right);
    if(ret == -1)
        return PyErr_SetFromErrno(PyExc_IOError);

    if(ret) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

#endif

static char __ACL_Type_doc__[] =
    "Type which represents a POSIX ACL\n"
    "\n"
    ".. note:: only one keyword parameter should be provided\n"
    "\n"
    ":param string file: creates an ACL representing\n"
    "    the access ACL of the specified file\n"
    ":param string filedef: creates an ACL representing\n"
    "    the default ACL of the given directory\n"
    ":param int fd: creates an ACL representing\n"
    "    the access ACL of the given file descriptor\n"
    ":param string text: creates an ACL from a \n"
    "    textual description\n"
    ":param ACL acl: creates a copy of an existing ACL instance\n"
    ":param int mode: creates an ACL from a numeric mode\n"
    "    (e.g. mode=0644) (this is valid only when the C library\n"
    "    provides the acl_from_mode call)\n"
    "\n"
    "If no parameters are passed, an empty ACL will be created; this\n"
    "makes sense only when your OS supports ACL modification\n"
    "(i.e. it implements full POSIX.1e support), otherwise the ACL won't\n"
    "be useful.\n"
    ;

/* ACL type methods */
static PyMethodDef ACL_methods[] = {
    {"applyto", ACL_applyto, METH_VARARGS, __applyto_doc__},
    {"valid", ACL_valid, METH_NOARGS, __valid_doc__},
#ifdef HAVE_LINUX
    {"to_any_text", (PyCFunction)ACL_to_any_text, METH_VARARGS | METH_KEYWORDS,
     __to_any_text_doc__},
    {"check", ACL_check, METH_NOARGS, __check_doc__},
    {"equiv_mode", ACL_equiv_mode, METH_NOARGS, __equiv_mode_doc__},
#endif
#ifdef HAVE_ACL_COPYEXT
    {"__getstate__", ACL_get_state, METH_NOARGS,
     "Dumps the ACL to an external format."},
    {"__setstate__", ACL_set_state, METH_VARARGS,
     "Loads the ACL from an external format."},
#endif
#ifdef HAVE_LEVEL2
    {"delete_entry", ACL_delete_entry, METH_VARARGS, __ACL_delete_entry_doc__},
    {"calc_mask", ACL_calc_mask, METH_NOARGS, __ACL_calc_mask_doc__},
    {"append", ACL_append, METH_VARARGS, __ACL_append_doc__},
#endif
    {NULL, NULL, 0, NULL}
};


/* The definition of the ACL Type */
static PyTypeObject ACL_Type = {
#ifdef IS_PY3K
    PyVarObject_HEAD_INIT(NULL, 0)
#else
    PyObject_HEAD_INIT(NULL)
    0,
#endif
    "posix1e.ACL",
    sizeof(ACL_Object),
    0,
    ACL_dealloc,        /* tp_dealloc */
    0,                  /* tp_print */
    0,                  /* tp_getattr */
    0,                  /* tp_setattr */
    ACL_nocmp,          /* tp_compare */
    0,                  /* tp_repr */
    0,                  /* tp_as_number */
    0,                  /* tp_as_sequence */
    0,                  /* tp_as_mapping */
    0,                  /* tp_hash */
    0,                  /* tp_call */
    ACL_str,            /* tp_str */
    0,                  /* tp_getattro */
    0,                  /* tp_setattro */
    0,                  /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT, /* tp_flags */
    __ACL_Type_doc__,   /* tp_doc */
    0,                  /* tp_traverse */
    0,                  /* tp_clear */
#ifdef HAVE_LINUX
    ACL_richcompare,    /* tp_richcompare */
#else
    0,                  /* tp_richcompare */
#endif
    0,                  /* tp_weaklistoffset */
#ifdef HAVE_LEVEL2
    ACL_iter,
    ACL_iternext,
#else
    0,                  /* tp_iter */
    0,                  /* tp_iternext */
#endif
    ACL_methods,        /* tp_methods */
    0,                  /* tp_members */
    0,                  /* tp_getset */
    0,                  /* tp_base */
    0,                  /* tp_dict */
    0,                  /* tp_descr_get */
    0,                  /* tp_descr_set */
    0,                  /* tp_dictoffset */
    ACL_init,           /* tp_init */
    0,                  /* tp_alloc */
    ACL_new,            /* tp_new */
};

#ifdef HAVE_LEVEL2

/* Entry type methods */
static PyMethodDef Entry_methods[] = {
    {"copy", Entry_copy, METH_VARARGS, __Entry_copy_doc__},
    {NULL, NULL, 0, NULL}
};

static char __Entry_tagtype_doc__[] =
    "The tag type of the current entry\n"
    "\n"
    "This is one of:\n"
    " - :py:data:`ACL_UNDEFINED_TAG`\n"
    " - :py:data:`ACL_USER_OBJ`\n"
    " - :py:data:`ACL_USER`\n"
    " - :py:data:`ACL_GROUP_OBJ`\n"
    " - :py:data:`ACL_GROUP`\n"
    " - :py:data:`ACL_MASK`\n"
    " - :py:data:`ACL_OTHER`\n"
    ;

static char __Entry_qualifier_doc__[] =
    "The qualifier of the current entry\n"
    "\n"
    "If the tag type is :py:data:`ACL_USER`, this should be a user id.\n"
    "If the tag type if :py:data:`ACL_GROUP`, this should be a group id.\n"
    "Else it doesn't matter.\n"
    ;

static char __Entry_parent_doc__[] =
    "The parent ACL of this entry\n"
    ;

static char __Entry_permset_doc__[] =
    "The permission set of this ACL entry\n"
    ;

/* Entry getset */
static PyGetSetDef Entry_getsets[] = {
    {"tag_type", Entry_get_tag_type, Entry_set_tag_type,
     __Entry_tagtype_doc__},
    {"qualifier", Entry_get_qualifier, Entry_set_qualifier,
     __Entry_qualifier_doc__},
    {"parent", Entry_get_parent, NULL, __Entry_parent_doc__},
    {"permset", Entry_get_permset, Entry_set_permset, __Entry_permset_doc__},
    {NULL}
};

static char __Entry_Type_doc__[] =
    "Type which represents an entry in an ACL.\n"
    "\n"
    "The type exists only if the OS has full support for POSIX.1e\n"
    "Can be created either by:\n"
    "\n"
    "  >>> e = posix1e.Entry(myACL) # this creates a new entry in the ACL\n"
    "  >>> e = myACL.append() # another way for doing the same thing\n"
    "\n"
    "or by:\n"
    "\n"
    "  >>> for entry in myACL:\n"
    "  ...     print entry\n"
    "\n"
    "Note that the Entry keeps a reference to its ACL, so even if \n"
    "you delete the ACL, it won't be cleaned up and will continue to \n"
    "exist until its Entry(ies) will be deleted.\n"
    ;
/* The definition of the Entry Type */
static PyTypeObject Entry_Type = {
#ifdef IS_PY3K
    PyVarObject_HEAD_INIT(NULL, 0)
#else
    PyObject_HEAD_INIT(NULL)
    0,
#endif
    "posix1e.Entry",
    sizeof(Entry_Object),
    0,
    Entry_dealloc,      /* tp_dealloc */
    0,                  /* tp_print */
    0,                  /* tp_getattr */
    0,                  /* tp_setattr */
    0,                  /* tp_compare */
    0,                  /* tp_repr */
    0,                  /* tp_as_number */
    0,                  /* tp_as_sequence */
    0,                  /* tp_as_mapping */
    0,                  /* tp_hash */
    0,                  /* tp_call */
    Entry_str,          /* tp_str */
    0,                  /* tp_getattro */
    0,                  /* tp_setattro */
    0,                  /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT, /* tp_flags */
    __Entry_Type_doc__, /* tp_doc */
    0,                  /* tp_traverse */
    0,                  /* tp_clear */
    0,                  /* tp_richcompare */
    0,                  /* tp_weaklistoffset */
    0,                  /* tp_iter */
    0,                  /* tp_iternext */
    Entry_methods,      /* tp_methods */
    0,                  /* tp_members */
    Entry_getsets,      /* tp_getset */
    0,                  /* tp_base */
    0,                  /* tp_dict */
    0,                  /* tp_descr_get */
    0,                  /* tp_descr_set */
    0,                  /* tp_dictoffset */
    Entry_init,         /* tp_init */
    0,                  /* tp_alloc */
    Entry_new,          /* tp_new */
};

/* Permset type methods */
static PyMethodDef Permset_methods[] = {
    {"clear", Permset_clear, METH_NOARGS, __Permset_clear_doc__, },
    {"add", Permset_add, METH_VARARGS, __Permset_add_doc__, },
    {"delete", Permset_delete, METH_VARARGS, __Permset_delete_doc__, },
    {"test", Permset_test, METH_VARARGS, __Permset_test_doc__, },
    {NULL, NULL, 0, NULL}
};

static char __Permset_execute_doc__[] =
    "Execute permission property\n"
    "\n"
    "This is a convenience method of retrieving and setting the execute\n"
    "permission in the permission set; the \n"
    "same effect can be achieved using the functions\n"
    "add(), test(), delete(), and those can take any \n"
    "permission defined by your platform.\n"
    ;

static char __Permset_read_doc__[] =
    "Read permission property\n"
    "\n"
    "This is a convenience method of retrieving and setting the read\n"
    "permission in the permission set; the \n"
    "same effect can be achieved using the functions\n"
    "add(), test(), delete(), and those can take any \n"
    "permission defined by your platform.\n"
    ;

static char __Permset_write_doc__[] =
    "Write permission property\n"
    "\n"
    "This is a convenience method of retrieving and setting the write\n"
    "permission in the permission set; the \n"
    "same effect can be achieved using the functions\n"
    "add(), test(), delete(), and those can take any \n"
    "permission defined by your platform.\n"
    ;

/* Permset getset */
static PyGetSetDef Permset_getsets[] = {
    {"execute", Permset_get_right, Permset_set_right,
     __Permset_execute_doc__, &holder_ACL_EXECUTE},
    {"read", Permset_get_right, Permset_set_right,
     __Permset_read_doc__, &holder_ACL_READ},
    {"write", Permset_get_right, Permset_set_right,
     __Permset_write_doc__, &holder_ACL_WRITE},
    {NULL}
};

static char __Permset_Type_doc__[] =
    "Type which represents the permission set in an ACL entry\n"
    "\n"
    "The type exists only if the OS has full support for POSIX.1e\n"
    "Can be retrieved either by:\n\n"
    ">>> perms = myEntry.permset\n"
    "\n"
    "or by:\n\n"
    ">>> perms = posix1e.Permset(myEntry)\n"
    "\n"
    "Note that the Permset keeps a reference to its Entry, so even if \n"
    "you delete the entry, it won't be cleaned up and will continue to \n"
    "exist until its Permset will be deleted.\n"
    ;

/* The definition of the Permset Type */
static PyTypeObject Permset_Type = {
#ifdef IS_PY3K
    PyVarObject_HEAD_INIT(NULL, 0)
#else
    PyObject_HEAD_INIT(NULL)
    0,
#endif
    "posix1e.Permset",
    sizeof(Permset_Object),
    0,
    Permset_dealloc,    /* tp_dealloc */
    0,                  /* tp_print */
    0,                  /* tp_getattr */
    0,                  /* tp_setattr */
    0,                  /* tp_compare */
    0,                  /* tp_repr */
    0,                  /* tp_as_number */
    0,                  /* tp_as_sequence */
    0,                  /* tp_as_mapping */
    0,                  /* tp_hash */
    0,                  /* tp_call */
    Permset_str,        /* tp_str */
    0,                  /* tp_getattro */
    0,                  /* tp_setattro */
    0,                  /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT, /* tp_flags */
    __Permset_Type_doc__,/* tp_doc */
    0,                  /* tp_traverse */
    0,                  /* tp_clear */
    0,                  /* tp_richcompare */
    0,                  /* tp_weaklistoffset */
    0,                  /* tp_iter */
    0,                  /* tp_iternext */
    Permset_methods,    /* tp_methods */
    0,                  /* tp_members */
    Permset_getsets,    /* tp_getset */
    0,                  /* tp_base */
    0,                  /* tp_dict */
    0,                  /* tp_descr_get */
    0,                  /* tp_descr_set */
    0,                  /* tp_dictoffset */
    Permset_init,       /* tp_init */
    0,                  /* tp_alloc */
    Permset_new,        /* tp_new */
};

#endif

/* Module methods */

static char __deletedef_doc__[] =
    "delete_default(path)\n"
    "Delete the default ACL from a directory.\n"
    "\n"
    "This function deletes the default ACL associated with\n"
    "a directory (the ACL which will be ANDed with the mode\n"
    "parameter to the open, creat functions).\n"
    "\n"
    ":param string path: the directory whose default ACL should be deleted\n"
    ;

/* Deletes the default ACL from a directory */
static PyObject* aclmodule_delete_default(PyObject* obj, PyObject* args) {
    char *filename;

    /* Parse the arguments */
    if (!PyArg_ParseTuple(args, "et", NULL, &filename))
        return NULL;

    if(acl_delete_def_file(filename) == -1) {
        return PyErr_SetFromErrno(PyExc_IOError);
    }

    /* Return the result */
    Py_INCREF(Py_None);
    return Py_None;
}

#ifdef HAVE_LINUX
static char __has_extended_doc__[] =
    "has_extended(item)\n"
    "Check if a file or file handle has an extended ACL.\n"
    "\n"
    ":param item: either a file name or a file-like object or an integer;\n"
    "  it represents the file-system object on which to act\n"
    ;

/* Check for extended ACL a file or fd */
static PyObject* aclmodule_has_extended(PyObject* obj, PyObject* args) {
    PyObject *myarg;
    int nret;
    int fd;

    if (!PyArg_ParseTuple(args, "O", &myarg))
        return NULL;

    if(PyBytes_Check(myarg)) {
        const char *filename = PyBytes_AS_STRING(myarg);
        nret = acl_extended_file(filename);
    } else if (PyUnicode_Check(myarg)) {
        PyObject *o =
            PyUnicode_AsEncodedString(myarg,
                                      Py_FileSystemDefaultEncoding, "strict");
        if (o == NULL)
            return NULL;
        const char *filename = PyBytes_AS_STRING(o);
        nret = acl_extended_file(filename);
        Py_DECREF(o);
    } else if((fd = PyObject_AsFileDescriptor(myarg)) != -1) {
        nret = acl_extended_fd(fd);
    } else {
        PyErr_SetString(PyExc_TypeError, "argument 1 must be string, int,"
                        " or file-like object");
        return 0;
    }
    if(nret == -1) {
        return PyErr_SetFromErrno(PyExc_IOError);
    }

    /* Return the result */
    return PyBool_FromLong(nret);
}
#endif

/* The module methods */
static PyMethodDef aclmodule_methods[] = {
    {"delete_default", aclmodule_delete_default, METH_VARARGS,
     __deletedef_doc__},
#ifdef HAVE_LINUX
    {"has_extended", aclmodule_has_extended, METH_VARARGS,
     __has_extended_doc__},
#endif
    {NULL, NULL, 0, NULL}
};

static char __posix1e_doc__[] =
    "POSIX.1e ACLs manipulation\n"
    "==========================\n"
    "\n"
    "This module provides support for manipulating POSIX.1e ACLS\n"
    "\n"
    "Depending on the operating system support for POSIX.1e, \n"
    "the ACL type will have more or less capabilities:\n\n"
    "  - level 1, only basic support, you can create\n"
    "    ACLs from files and text descriptions;\n"
    "    once created, the type is immutable\n"
    "  - level 2, complete support, you can alter\n"
    "    the ACL once it is created\n"
    "\n"
    "Also, in level 2, more types are available, corresponding\n"
    "to acl_entry_t (the Entry type), acl_permset_t (the Permset type).\n"
    "\n"
    "The existence of level 2 support and other extensions can be\n"
    "checked by the constants:\n\n"
    "  - :py:data:`HAS_ACL_ENTRY` for level 2 and the Entry/Permset classes\n"
    "  - :py:data:`HAS_ACL_FROM_MODE` for ``ACL(mode=...)`` usage\n"
    "  - :py:data:`HAS_ACL_CHECK` for the :py:func:`ACL.check` function\n"
    "  - :py:data:`HAS_EXTENDED_CHECK` for the module-level\n"
    "    :py:func:`has_extended` function\n"
    "  - :py:data:`HAS_EQUIV_MODE` for the :py:func:`ACL.equiv_mode` method\n"
    "\n"
    "Example:\n"
    "\n"
    ">>> import posix1e\n"
    ">>> acl1 = posix1e.ACL(file=\"file.txt\") \n"
    ">>> print acl1\n"
    "user::rw-\n"
    "group::rw-\n"
    "other::r--\n"
    ">>>\n"
    ">>> b = posix1e.ACL(text=\"u::rx,g::-,o::-\")\n"
    ">>> print b\n"
    "user::r-x\n"
    "group::---\n"
    "other::---\n"
    ">>>\n"
    ">>> b.applyto(\"file.txt\")\n"
    ">>> print posix1e.ACL(file=\"file.txt\")\n"
    "user::r-x\n"
    "group::---\n"
    "other::---\n"
    ">>>\n"
    "\n"
    ".. py:data:: ACL_USER\n\n"
    "   Denotes a specific user entry in an ACL.\n"
    "\n"
    ".. py:data:: ACL_USER_OBJ\n\n"
    "   Denotes the user owner entry in an ACL.\n"
    "\n"
    ".. py:data:: ACL_GROUP\n\n"
    "   Denotes the a group entry in an ACL.\n"
    "\n"
    ".. py:data:: ACL_GROUP_OBJ\n\n"
    "   Denotes the group owner entry in an ACL.\n"
    "\n"
    ".. py:data:: ACL_OTHER\n\n"
    "   Denotes the 'others' entry in an ACL.\n"
    "\n"
    ".. py:data:: ACL_MASK\n\n"
    "   Denotes the mask entry in an ACL, representing the maximum\n"
    "   access granted other users, the owner group and other groups.\n"
    "\n"
    ".. py:data:: ACL_UNDEFINED_TAG\n\n"
    "   An undefined tag in an ACL.\n"
    "\n"
    ".. py:data:: ACL_READ\n\n"
    "   Read permission in a permission set.\n"
    "\n"
    ".. py:data:: ACL_WRITE\n\n"
    "   Write permission in a permission set.\n"
    "\n"
    ".. py:data:: ACL_EXECUTE\n\n"
    "   Execute permission in a permission set.\n"
    "\n"
    ".. py:data:: HAS_ACL_ENTRY\n\n"
    "   denotes support for level 2 and the Entry/Permset classes\n"
    "\n"
    ".. py:data:: HAS_ACL_FROM_MODE\n\n"
    "   denotes support for building an ACL from an octal mode\n"
    "\n"
    ".. py:data:: HAS_ACL_CHECK\n\n"
    "   denotes support for extended checks of an ACL's validity\n"
    "\n"
    ".. py:data:: HAS_EXTENDED_CHECK\n\n"
    "   denotes support for checking whether an ACL is basic or extended\n"
    "\n"
    ".. py:data:: HAS_EQUIV_MODE\n\n"
    "   denotes support for the equiv_mode function\n"
    "\n"
    ;

#ifdef IS_PY3K

static struct PyModuleDef posix1emodule = {
    PyModuleDef_HEAD_INIT,
    "posix1e",
    __posix1e_doc__,
    0,
    aclmodule_methods,
};

#define INITERROR return NULL

PyMODINIT_FUNC
PyInit_posix1e(void)

#else
#define INITERROR return

void initposix1e(void)
#endif
{
    PyObject *m, *d;

    Py_TYPE(&ACL_Type) = &PyType_Type;
    if(PyType_Ready(&ACL_Type) < 0)
        INITERROR;

#ifdef HAVE_LEVEL2
    Py_TYPE(&Entry_Type) = &PyType_Type;
    if(PyType_Ready(&Entry_Type) < 0)
        INITERROR;

    Py_TYPE(&Permset_Type) = &PyType_Type;
    if(PyType_Ready(&Permset_Type) < 0)
        INITERROR;
#endif

#ifdef IS_PY3K
    m = PyModule_Create(&posix1emodule);
#else
    m = Py_InitModule3("posix1e", aclmodule_methods, __posix1e_doc__);
#endif
    if (m==NULL)
        INITERROR;

    d = PyModule_GetDict(m);
    if (d == NULL)
        INITERROR;

    Py_INCREF(&ACL_Type);
    if (PyDict_SetItemString(d, "ACL",
                             (PyObject *) &ACL_Type) < 0)
        INITERROR;

    /* 23.3.6 acl_type_t values */
    PyModule_AddIntConstant(m, "ACL_TYPE_ACCESS", ACL_TYPE_ACCESS);
    PyModule_AddIntConstant(m, "ACL_TYPE_DEFAULT", ACL_TYPE_DEFAULT);


#ifdef HAVE_LEVEL2
    Py_INCREF(&Entry_Type);
    if (PyDict_SetItemString(d, "Entry",
                             (PyObject *) &Entry_Type) < 0)
        INITERROR;

    Py_INCREF(&Permset_Type);
    if (PyDict_SetItemString(d, "Permset",
                             (PyObject *) &Permset_Type) < 0)
        INITERROR;

    /* 23.2.2 acl_perm_t values */
    PyModule_AddIntConstant(m, "ACL_READ", ACL_READ);
    PyModule_AddIntConstant(m, "ACL_WRITE", ACL_WRITE);
    PyModule_AddIntConstant(m, "ACL_EXECUTE", ACL_EXECUTE);

    /* 23.2.5 acl_tag_t values */
    PyModule_AddIntConstant(m, "ACL_UNDEFINED_TAG", ACL_UNDEFINED_TAG);
    PyModule_AddIntConstant(m, "ACL_USER_OBJ", ACL_USER_OBJ);
    PyModule_AddIntConstant(m, "ACL_USER", ACL_USER);
    PyModule_AddIntConstant(m, "ACL_GROUP_OBJ", ACL_GROUP_OBJ);
    PyModule_AddIntConstant(m, "ACL_GROUP", ACL_GROUP);
    PyModule_AddIntConstant(m, "ACL_MASK", ACL_MASK);
    PyModule_AddIntConstant(m, "ACL_OTHER", ACL_OTHER);

    /* Document extended functionality via easy-to-use constants */
    PyModule_AddIntConstant(m, "HAS_ACL_ENTRY", 1);
#else
    PyModule_AddIntConstant(m, "HAS_ACL_ENTRY", 0);
#endif

#ifdef HAVE_LINUX
    /* Linux libacl specific acl_to_any_text constants */
    PyModule_AddIntConstant(m, "TEXT_ABBREVIATE", TEXT_ABBREVIATE);
    PyModule_AddIntConstant(m, "TEXT_NUMERIC_IDS", TEXT_NUMERIC_IDS);
    PyModule_AddIntConstant(m, "TEXT_SOME_EFFECTIVE", TEXT_SOME_EFFECTIVE);
    PyModule_AddIntConstant(m, "TEXT_ALL_EFFECTIVE", TEXT_ALL_EFFECTIVE);
    PyModule_AddIntConstant(m, "TEXT_SMART_INDENT", TEXT_SMART_INDENT);

    /* Linux libacl specific acl_check constants */
    PyModule_AddIntConstant(m, "ACL_MULTI_ERROR", ACL_MULTI_ERROR);
    PyModule_AddIntConstant(m, "ACL_DUPLICATE_ERROR", ACL_DUPLICATE_ERROR);
    PyModule_AddIntConstant(m, "ACL_MISS_ERROR", ACL_MISS_ERROR);
    PyModule_AddIntConstant(m, "ACL_ENTRY_ERROR", ACL_ENTRY_ERROR);

    /* declare the Linux extensions */
    PyModule_AddIntConstant(m, "HAS_ACL_FROM_MODE", 1);
    PyModule_AddIntConstant(m, "HAS_ACL_CHECK", 1);
    PyModule_AddIntConstant(m, "HAS_EXTENDED_CHECK", 1);
    PyModule_AddIntConstant(m, "HAS_EQUIV_MODE", 1);
#else
    PyModule_AddIntConstant(m, "HAS_ACL_FROM_MODE", 0);
    PyModule_AddIntConstant(m, "HAS_ACL_CHECK", 0);
    PyModule_AddIntConstant(m, "HAS_EXTENDED_CHECK", 0);
    PyModule_AddIntConstant(m, "HAS_EQUIV_MODE", 0);
#endif

#ifdef IS_PY3K
    return m;
#endif
}

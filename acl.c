/*
    posix1e - a python module exposing the posix acl functions

    Copyright (C) 2002-2009, 2012, 2014, 2015 Iustin Pop <iustin@k1024.org>

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

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <sys/types.h>
#include <sys/acl.h>

#ifdef HAVE_LINUX
#include <acl/libacl.h>
#define get_perm acl_get_perm
#elif HAVE_FREEBSD
#define get_perm acl_get_perm_np
#endif

/* Used for cpychecker: */
/* The checker automatically defines this preprocessor name when creating
   the custom attribute: */
#if defined(WITH_CPYCHECKER_TYPE_OBJECT_FOR_TYPEDEF_ATTRIBUTE)
#define CPYCHECKER_TYPE_OBJECT_FOR_TYPEDEF(typename) \
  __attribute__((cpychecker_type_object_for_typedef(typename)))
#else
/* This handles the case where we're compiling with a "vanilla"
   compiler that doesn't supply this attribute: */
#define CPYCHECKER_TYPE_OBJECT_FOR_TYPEDEF(typename)
#endif

/* The checker automatically defines this preprocessor name when creating
   the custom attribute: */
#if defined(WITH_CPYCHECKER_NEGATIVE_RESULT_SETS_EXCEPTION_ATTRIBUTE)
   #define CPYCHECKER_NEGATIVE_RESULT_SETS_EXCEPTION \
__attribute__((cpychecker_negative_result_sets_exception))
   #else
   #define CPYCHECKER_NEGATIVE_RESULT_SETS_EXCEPTION
#endif

static PyTypeObject ACL_Type
  CPYCHECKER_TYPE_OBJECT_FOR_TYPEDEF("ACL_Object");
static PyObject* ACL_applyto(PyObject* obj, PyObject* args);
static PyObject* ACL_valid(PyObject* obj, PyObject* args);

#ifdef HAVE_ACL_COPY_EXT
static PyObject* ACL_get_state(PyObject *obj, PyObject* args);
static PyObject* ACL_set_state(PyObject *obj, PyObject* args);
#endif

#ifdef HAVE_LEVEL2
static PyTypeObject Entry_Type
  CPYCHECKER_TYPE_OBJECT_FOR_TYPEDEF("Entry_Object");
static PyTypeObject Permset_Type
  CPYCHECKER_TYPE_OBJECT_FOR_TYPEDEF("Permset_Object");
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
    ACL_Object *acl;

    newacl = type->tp_alloc(type, 0);

    if(newacl == NULL) {
        return NULL;
    }
    acl = (ACL_Object*) newacl;

    acl->acl = acl_init(0);
    if (acl->acl == NULL) {
        /* LCOV_EXCL_START */
        PyErr_SetFromErrno(PyExc_IOError);
        Py_DECREF(newacl);
        return NULL;
        /* LCOV_EXCL_STOP */
    }
#ifdef HAVE_LEVEL2
    acl->entry_id = ACL_FIRST_ENTRY;
#endif

    return newacl;
}

/* Initialization of a new ACL instance */
static int ACL_init(PyObject* obj, PyObject* args, PyObject *keywds) {
    ACL_Object* self = (ACL_Object*) obj;
    static char *kwlist[] = { "file", "fd", "text", "acl", "filedef",
#ifdef HAVE_LINUX
                              "mode",
#endif
#ifdef HAVE_ACL_COPY_EXT
                              "data",
#endif
                              NULL };
    char *format = "|O&OsO!O&"
#ifdef HAVE_LINUX
      "i"
#endif
#ifdef HAVE_ACL_COPY_EXT
      "y#"
#endif
      ;
    acl_t new = NULL;
#ifdef HAVE_LINUX
    int mode = -1;
#endif
    PyObject *file = NULL;
    PyObject *filedef = NULL;
    char *text = NULL;
    PyObject *fd = NULL;
    ACL_Object* thesrc = NULL;
#ifdef HAVE_ACL_COPY_EXT
    const void *buf = NULL;
    Py_ssize_t bufsize;
#endif
    int set_err = 0;

    if(!PyTuple_Check(args) || PyTuple_Size(args) != 0 ||
       (keywds != NULL && PyDict_Check(keywds) && PyDict_Size(keywds) > 1)) {
        PyErr_SetString(PyExc_ValueError, "a max of one keyword argument"
                        " must be passed");
        return -1;
    }
    if(!PyArg_ParseTupleAndKeywords(args, keywds, format, kwlist,
                                    PyUnicode_FSConverter, &file,
                                    &fd, &text, &ACL_Type, &thesrc,
                                    PyUnicode_FSConverter, &filedef
#ifdef HAVE_LINUX
                                    , &mode
#endif
#ifdef HAVE_ACL_COPY_EXT
                                    , &buf, &bufsize
#endif
                                    ))
        return -1;

    if(file != NULL) {
        char *path = PyBytes_AS_STRING(file);
        new = acl_get_file(path, ACL_TYPE_ACCESS);
        // Set custom exception on this failure path which includes
        // the filename.
        if (new == NULL) {
          PyErr_SetFromErrnoWithFilename(PyExc_IOError, path);
          set_err = 1;
        }
        Py_DECREF(file);
    } else if(text != NULL)
        new = acl_from_text(text);
    else if(fd != NULL) {
        int fdval;
        if ((fdval = PyObject_AsFileDescriptor(fd)) != -1) {
            new = acl_get_fd(fdval);
        }
    } else if(thesrc != NULL)
        new = acl_dup(thesrc->acl);
    else if(filedef != NULL) {
        char *path = PyBytes_AS_STRING(filedef);
        new = acl_get_file(path, ACL_TYPE_DEFAULT);
        // Set custom exception on this failure path which includes
        // the filename.
        if (new == NULL) {
          PyErr_SetFromErrnoWithFilename(PyExc_IOError, path);
          set_err = 1;
        }
        Py_DECREF(filedef);
    }
#ifdef HAVE_LINUX
    else if(mode != -1)
        new = acl_from_mode(mode);
#endif
#ifdef HAVE_ACL_COPY_EXT
    else if(buf != NULL) {
      new = acl_copy_int(buf);
    }
#endif
    else
        new = acl_init(0);

    if(new == NULL) {
        if (!set_err) {
            PyErr_SetFromErrno(PyExc_IOError);
        }
        return -1;
    }

    /* Free the old acl_t without checking for error, we don't
     * care right now */
    if(self->acl != NULL)
        acl_free(self->acl);

    self->acl = new;

    return 0;
}

/* Standard type functions */
static void ACL_dealloc(PyObject* obj) {
    ACL_Object *self = (ACL_Object*) obj;
    PyObject *err_type, *err_value, *err_traceback;

    PyErr_Fetch(&err_type, &err_value, &err_traceback);
    if(self->acl != NULL && acl_free(self->acl) != 0)
        PyErr_WriteUnraisable(obj);  /* LCOV_EXCL_LINE */
    PyErr_Restore(err_type, err_value, err_traceback);
    Py_TYPE(obj)->tp_free(obj);
}

/* Converts the acl to a text format */
static PyObject* ACL_str(PyObject *obj) {
    char *text;
    ACL_Object *self = (ACL_Object*) obj;
    PyObject *ret;

    text = acl_to_text(self->acl, NULL);
    if(text == NULL) {
        /* LCOV_EXCL_START */
        return PyErr_SetFromErrno(PyExc_IOError);
        /* LCOV_EXCL_STOP */
    }
    ret = PyUnicode_FromString(text);
    if(acl_free(text) != 0) {
        /* LCOV_EXCL_START */
        Py_XDECREF(ret);
        return PyErr_SetFromErrno(PyExc_IOError);
        /* LCOV_EXCL_STOP */
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
        return PyErr_SetFromErrno(PyExc_IOError);  /* LCOV_EXCL_LINE */
    }
    ret = PyBytes_FromString(text);
    if(acl_free(text) != 0) {
        /* LCOV_EXCL_START */
        Py_XDECREF(ret);
        return PyErr_SetFromErrno(PyExc_IOError);
        /* LCOV_EXCL_STOP */
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
        return PyErr_SetFromErrno(PyExc_IOError);  /* LCOV_EXCL_LINE */
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
        return PyErr_SetFromErrno(PyExc_IOError);  /* LCOV_EXCL_LINE */
    switch(op) {
    case Py_EQ:
        ret = n == 0 ? Py_True : Py_False;
        break;
    case Py_NE:
        ret = n == 1 ? Py_True : Py_False;
        break;
    default:
        PyErr_SetString(PyExc_TypeError, "ACLs are not orderable");
        return NULL;
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
        return PyErr_SetFromErrno(PyExc_IOError);  /* LCOV_EXCL_LINE */
    return PyLong_FromLong(mode);
}
#endif

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
    PyObject *target, *tmp;
    acl_type_t type = ACL_TYPE_ACCESS;
    int nret;
    int fd;

    if (!PyArg_ParseTuple(args, "O|I", &target, &type))
        return NULL;
    if ((fd = PyObject_AsFileDescriptor(target)) != -1) {
        if((nret = acl_set_fd(fd, self->acl)) == -1) {
          PyErr_SetFromErrno(PyExc_IOError);
        }
    } else {
      // PyObject_AsFileDescriptor sets an error when failing, so clear
      // it such that further code works; some method lookups fail if an
      // error already occured when called, which breaks at least
      // PyOS_FSPath (called by FSConverter).
      PyErr_Clear();
      if(PyUnicode_FSConverter(target, &tmp)) {
        char *filename = PyBytes_AS_STRING(tmp);
        if ((nret = acl_set_file(filename, type, self->acl)) == -1) {
            PyErr_SetFromErrnoWithFilename(PyExc_IOError, filename);
        }
        Py_DECREF(tmp);
      } else {
        nret = -1;
      }
    }
    if (nret < 0) {
        return NULL;
    } else {
        Py_RETURN_NONE;
    }
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
        return PyErr_SetFromErrno(PyExc_IOError);  /* LCOV_EXCL_LINE */

    if((ret = PyBytes_FromStringAndSize(NULL, size)) == NULL)
        return NULL;
    buf = PyBytes_AsString(ret);

    if((nsize = acl_copy_ext(buf, self->acl, size)) == -1) {
        /* LCOV_EXCL_START */
        Py_DECREF(ret);
        return PyErr_SetFromErrno(PyExc_IOError);
        /* LCOV_EXCL_STOP */
    }

    return ret;
}

static PyObject* ACL_set_state(PyObject *obj, PyObject* args) {
    ACL_Object *self = (ACL_Object*) obj;
    const void *buf;
    Py_ssize_t bufsize;
    acl_t ptr;

    /* Parse the argument */
    if (!PyArg_ParseTuple(args, "y#", &buf, &bufsize))
        return NULL;

    /* Try to import the external representation */
    if((ptr = acl_copy_int(buf)) == NULL)
        return PyErr_SetFromErrno(PyExc_IOError);

    if(self->acl != NULL) {
        /* Ignore errors in freeing the previous acl. We already
           allocated the new acl, and the state of the previous one is
           suspect if freeing failed (in Linux's libacl, deallocating
           a valid ACL can't actually happen, so this path is
           unlikely. */
        acl_free(self->acl); /* LCOV_EXCL_LINE */
    }

    self->acl = ptr;

    Py_RETURN_NONE;
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
        return PyErr_SetFromErrno(PyExc_IOError);  /* LCOV_EXCL_LINE */
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

    if (e->parent_acl != obj) {
        PyErr_SetString(PyExc_ValueError,
                        "Can't remove un-owned entry");
        return NULL;
    }
    if(acl_delete_entry(self->acl, e->entry) == -1)
        return PyErr_SetFromErrno(PyExc_IOError);

    Py_RETURN_NONE;
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

    Py_RETURN_NONE;
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
    Entry_Object* newentry;
    Entry_Object* oldentry = NULL;
    int nret;

    if (!PyArg_ParseTuple(args, "|O!", &Entry_Type, &oldentry)) {
        return NULL;
    }

    PyObject *new_arglist = Py_BuildValue("(O)", obj);
    if (new_arglist == NULL) {
        return NULL;
    }
    newentry = (Entry_Object*) PyObject_CallObject((PyObject*)&Entry_Type, new_arglist);
    Py_DECREF(new_arglist);
    if(newentry == NULL) {
        return NULL;
    }

    if(oldentry != NULL) {
        nret = acl_copy_entry(newentry->entry, oldentry->entry);
        if(nret == -1) {
            /* LCOV_EXCL_START */
            Py_DECREF(newentry);
            return PyErr_SetFromErrno(PyExc_IOError);
           /* LCOV_EXCL_STOP */
        }
    }

    return (PyObject*)newentry;
}

/***** Entry type *****/

typedef struct {
    acl_tag_t tag;
    union {
        uid_t uid;
        gid_t gid;
    };
} tag_qual;

/* Pre-declaring the function is more friendly to cpychecker, sigh. */
static int get_tag_qualifier(acl_entry_t entry, tag_qual *tq)
  CPYCHECKER_NEGATIVE_RESULT_SETS_EXCEPTION;

/* Helper function to get the tag and qualifier of an Entry at the
   same time. This is "needed" because the acl_get_qualifier function
   returns a pointer to different types, based on the tag value, and
   thus it's not straightforward to get the right type.

   It sets a Python exception if an error occurs, and returns -1 in
   this case. If successful, the tag is set to the tag type, the
   qualifier (if any) to either the uid or the gid entry in the
   tag_qual structure, and the return value is 0.
*/
static int get_tag_qualifier(acl_entry_t entry, tag_qual *tq) {
    void *p;

    if(acl_get_tag_type(entry, &tq->tag) == -1) {
        /* LCOV_EXCL_START */
        PyErr_SetFromErrno(PyExc_IOError);
        return -1;
        /* LCOV_EXCL_STOP */
    }
    if (tq->tag == ACL_USER || tq->tag == ACL_GROUP) {
        if((p = acl_get_qualifier(entry)) == NULL) {
            /* LCOV_EXCL_START */
            PyErr_SetFromErrno(PyExc_IOError);
            return -1;
            /* LCOV_EXCL_STOP */
        }
        if (tq->tag == ACL_USER) {
            tq->uid = *(uid_t*)p;
        } else {
            tq->gid = *(gid_t*)p;
        }
        acl_free(p);
    }
    return 0;
}

#define ENTRY_SET_CHECK(self, attr, value)         \
    if (value == NULL) { \
        PyErr_SetString(PyExc_TypeError, \
                        attr " deletion is not supported"); \
        return -1; \
    }

/* Creation of a new Entry instance */
static PyObject* Entry_new(PyTypeObject* type, PyObject* args,
                           PyObject *keywds) {
    PyObject* newentry;
    Entry_Object* entry;
    ACL_Object* parent = NULL;

    if (!PyArg_ParseTuple(args, "O!", &ACL_Type, &parent))
        return NULL;

    newentry = PyType_GenericNew(type, args, keywds);

    if(newentry == NULL) {
        return NULL;
    }

    entry = (Entry_Object*)newentry;

    if(acl_create_entry(&parent->acl, &entry->entry) == -1) {
        /* LCOV_EXCL_START */
        PyErr_SetFromErrno(PyExc_IOError);
        Py_DECREF(newentry);
        return NULL;
        /* LCOV_EXCL_STOP */
    }
    Py_INCREF(parent);
    entry->parent_acl = (PyObject*)parent;
    return newentry;
}

/* Initialization of a new Entry instance */
static int Entry_init(PyObject* obj, PyObject* args, PyObject *keywds) {
    Entry_Object* self = (Entry_Object*) obj;
    ACL_Object* parent = NULL;

    if (!PyArg_ParseTuple(args, "O!", &ACL_Type, &parent))
        return -1;

    if ((PyObject*)parent != self->parent_acl) {
        PyErr_SetString(PyExc_ValueError,
                        "Can't reinitialize with a different parent");
        return -1;
    }
    return 0;
}

/* Free the Entry instance */
static void Entry_dealloc(PyObject* obj) {
    Entry_Object *self = (Entry_Object*) obj;
    PyObject *err_type, *err_value, *err_traceback;

    PyErr_Fetch(&err_type, &err_value, &err_traceback);
    if(self->parent_acl != NULL) {
        Py_DECREF(self->parent_acl);
        self->parent_acl = NULL;
    }
    PyErr_Restore(err_type, err_value, err_traceback);
    Py_TYPE(obj)->tp_free(obj);
}

/* Converts the entry to a text format */
static PyObject* Entry_str(PyObject *obj) {
    PyObject *format, *kind;
    Entry_Object *self = (Entry_Object*) obj;
    tag_qual tq;

    if(get_tag_qualifier(self->entry, &tq) < 0) {
        return NULL;
    }

    format = PyUnicode_FromString("ACL entry for ");
    if(format == NULL)
        return NULL;
    switch(tq.tag) {
    case ACL_UNDEFINED_TAG:
        kind = PyUnicode_FromString("undefined type");
        break;
    case ACL_USER_OBJ:
        kind = PyUnicode_FromString("the owner");
        break;
    case ACL_GROUP_OBJ:
        kind = PyUnicode_FromString("the group");
        break;
    case ACL_OTHER:
        kind = PyUnicode_FromString("the others");
        break;
    case ACL_USER:
        /* FIXME: here and in the group case, we're formatting with
           unsigned, because there's no way to automatically determine
           the signed-ness of the types; on Linux(glibc) they're
           unsigned, so we'll go along with that */
        kind = PyUnicode_FromFormat("user with uid %u", tq.uid);
        break;
    case ACL_GROUP:
        kind = PyUnicode_FromFormat("group with gid %u", tq.gid);
        break;
    case ACL_MASK:
        kind = PyUnicode_FromString("the mask");
        break;
    default: /* LCOV_EXCL_START */
        kind = PyUnicode_FromString("UNKNOWN_TAG_TYPE!");
        break;
        /* LCOV_EXCL_STOP */
    }
    if (kind == NULL) {
        /* LCOV_EXCL_START */
        Py_DECREF(format);
        return NULL;
        /* LCOV_EXCL_STOP */
    }
    PyObject *ret = PyUnicode_Concat(format, kind);
    Py_DECREF(format);
    Py_DECREF(kind);
    return ret;
}

/* Sets the tag type of the entry */
static int Entry_set_tag_type(PyObject* obj, PyObject* value, void* arg) {
    Entry_Object *self = (Entry_Object*) obj;

    ENTRY_SET_CHECK(self, "tag type", value);

    if(!PyLong_Check(value)) {
        PyErr_SetString(PyExc_TypeError,
                        "tag type must be integer");
        return -1;
    }
    if(acl_set_tag_type(self->entry, (acl_tag_t)PyLong_AsLong(value)) == -1) {
        PyErr_SetFromErrno(PyExc_IOError);
        return -1;
    }

    return 0;
}

/* Returns the tag type of the entry */
static PyObject* Entry_get_tag_type(PyObject *obj, void* arg) {
    Entry_Object *self = (Entry_Object*) obj;
    acl_tag_t value;

    if(acl_get_tag_type(self->entry, &value) == -1) {
        /* LCOV_EXCL_START */
        PyErr_SetFromErrno(PyExc_IOError);
        return NULL;
        /* LCOV_EXCL_STOP */
    }

    return PyLong_FromLong(value);
}

/* Sets the qualifier (either uid_t or gid_t) for the entry,
 * usable only if the tag type if ACL_USER or ACL_GROUP
 */
static int Entry_set_qualifier(PyObject* obj, PyObject* value, void* arg) {
    Entry_Object *self = (Entry_Object*) obj;
    unsigned long uidgid;
    uid_t uid;
    gid_t gid;
    void *p;
    acl_tag_t tag;

    ENTRY_SET_CHECK(self, "qualifier", value);

    if(!PyLong_Check(value)) {
        PyErr_SetString(PyExc_TypeError,
                        "qualifier must be integer");
        return -1;
    }
    /* This is the negative value check, and larger than long
       check. If uid_t/gid_t are long-sized, this is enough to check
       for both over and underflow. */
    if((uidgid = PyLong_AsUnsignedLong(value)) == (unsigned long) -1) {
        if(PyErr_Occurred() != NULL) {
            return -1;
        }
    }
    /* Due to how acl_set_qualifier takes its argument, we have to do
       this ugly dance with two variables and a pointer that will
       point to one of them. */
    if(acl_get_tag_type(self->entry, &tag) == -1) {
        /* LCOV_EXCL_START */
        PyErr_SetFromErrno(PyExc_IOError);
        return -1;
        /* LCOV_EXCL_STOP */
    }
    uid = uidgid;
    gid = uidgid;
    /* This is an extra overflow check, in case uid_t/gid_t are
       int-sized (and int size smaller than long size). */
    switch(tag) {
    case ACL_USER:
      if((unsigned long)uid != uidgid) {
        PyErr_SetString(PyExc_OverflowError, "Can't assign given qualifier");
        return -1;
      } else {
        p = &uid;
      }
      break;
    case ACL_GROUP:
      if((unsigned long)gid != uidgid) {
        PyErr_SetString(PyExc_OverflowError, "Can't assign given qualifier");
        return -1;
      } else {
        p = &gid;
      }
      break;
    default:
      PyErr_SetString(PyExc_TypeError,
                      "Can only set qualifiers on ACL_USER or ACL_GROUP entries");
      return -1;
    }
    if(acl_set_qualifier(self->entry, p) == -1) {
        /* LCOV_EXCL_START */
        PyErr_SetFromErrno(PyExc_IOError);
        return -1;
        /* LCOV_EXCL_STOP */
    }

    return 0;
}

/* Returns the qualifier of the entry */
static PyObject* Entry_get_qualifier(PyObject *obj, void* arg) {
    Entry_Object *self = (Entry_Object*) obj;
    unsigned long value;
    tag_qual tq;

    if(get_tag_qualifier(self->entry, &tq) < 0) {
        return NULL;
    }
    if (tq.tag == ACL_USER) {
        value = tq.uid;
    } else if (tq.tag == ACL_GROUP) {
        value = tq.gid;
    } else {
        PyErr_SetString(PyExc_TypeError,
                        "Given entry doesn't have an user or"
                        " group tag");
        return NULL;
    }
    return PyLong_FromUnsignedLong(value);
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
    PyObject *p;

    PyObject *perm_arglist = Py_BuildValue("(O)", obj);
    if (perm_arglist == NULL) {
        return NULL;
    }
    p = PyObject_CallObject((PyObject*)&Permset_Type, perm_arglist);
    Py_DECREF(perm_arglist);
    return p;
}

/* Sets the permset of the entry to the passed Permset */
static int Entry_set_permset(PyObject* obj, PyObject* value, void* arg) {
    Entry_Object *self = (Entry_Object*)obj;
    Permset_Object *p;

    ENTRY_SET_CHECK(self, "permset", value);

    if(!PyObject_IsInstance(value, (PyObject*)&Permset_Type)) {
        PyErr_SetString(PyExc_TypeError, "argument 1 must be posix1e.Permset");
        return -1;
    }
    p = (Permset_Object*)value;
    if(acl_set_permset(self->entry, p->permset) == -1) {
        /* LCOV_EXCL_START */
        PyErr_SetFromErrno(PyExc_IOError);
        return -1;
        /* LCOV_EXCL_STOP */
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
        return PyErr_SetFromErrno(PyExc_IOError);  /* LCOV_EXCL_LINE */

    Py_RETURN_NONE;
}

/**** Permset type *****/

/* Creation of a new Permset instance */
static PyObject* Permset_new(PyTypeObject* type, PyObject* args,
                             PyObject *keywds) {
    PyObject* newpermset;
    Permset_Object* permset;
    Entry_Object* parent = NULL;

    if (!PyArg_ParseTuple(args, "O!", &Entry_Type, &parent)) {
        return NULL;
    }

    newpermset = PyType_GenericNew(type, args, keywds);

    if(newpermset == NULL) {
        return NULL;
    }

    permset = (Permset_Object*)newpermset;

    if(acl_get_permset(parent->entry, &permset->permset) == -1) {
        PyErr_SetFromErrno(PyExc_IOError);
        Py_DECREF(newpermset);
        return NULL;
    }

    permset->parent_entry = (PyObject*)parent;
    Py_INCREF(parent);

    return newpermset;
}

/* Initialization of a new Permset instance */
static int Permset_init(PyObject* obj, PyObject* args, PyObject *keywds) {
    Permset_Object* self = (Permset_Object*) obj;
    Entry_Object* parent = NULL;

    if (!PyArg_ParseTuple(args, "O!", &Entry_Type, &parent))
        return -1;

    if ((PyObject*)parent != self->parent_entry) {
        PyErr_SetString(PyExc_ValueError,
                        "Can't reinitialize with a different parent");
        return -1;
    }

    return 0;
}

/* Free the Permset instance */
static void Permset_dealloc(PyObject* obj) {
    Permset_Object *self = (Permset_Object*) obj;
    PyObject *err_type, *err_value, *err_traceback;

    PyErr_Fetch(&err_type, &err_value, &err_traceback);
    if(self->parent_entry != NULL) {
        Py_DECREF(self->parent_entry);
        self->parent_entry = NULL;
    }
    PyErr_Restore(err_type, err_value, err_traceback);
    Py_TYPE(obj)->tp_free((PyObject *)obj);
}

/* Permset string representation */
static PyObject* Permset_str(PyObject *obj) {
    Permset_Object *self = (Permset_Object*) obj;
    char pstr[3];

    pstr[0] = get_perm(self->permset, ACL_READ) ? 'r' : '-';
    pstr[1] = get_perm(self->permset, ACL_WRITE) ? 'w' : '-';
    pstr[2] = get_perm(self->permset, ACL_EXECUTE) ? 'x' : '-';
    return PyUnicode_FromStringAndSize(pstr, 3);
}

static char __Permset_clear_doc__[] =
    "Clears all permissions from the permission set.\n"
    ;

/* Clears all permissions from the permset */
static PyObject* Permset_clear(PyObject* obj, PyObject* args) {
    Permset_Object *self = (Permset_Object*) obj;

    if(acl_clear_perms(self->permset) == -1)
        return PyErr_SetFromErrno(PyExc_IOError);  /* LCOV_EXCL_LINE */

    Py_RETURN_NONE;
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

    if(!PyLong_Check(value)) {
        PyErr_SetString(PyExc_ValueError, "invalid argument, an integer"
                        " is expected");
        return -1;
    }
    on = PyLong_AsLong(value);
    if(on)
        nerr = acl_add_perm(self->permset, *(acl_perm_t*)arg);
    else
        nerr = acl_delete_perm(self->permset, *(acl_perm_t*)arg);
    if(nerr == -1) {
        /* LCOV_EXCL_START */
        PyErr_SetFromErrno(PyExc_IOError);
        return -1;
        /* LCOV_EXCL_STOP */
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
        return PyErr_SetFromErrno(PyExc_IOError);  /* LCOV_EXCL_LINE */

    Py_RETURN_NONE;
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
        return PyErr_SetFromErrno(PyExc_IOError);  /* LCOV_EXCL_LINE */

    Py_RETURN_NONE;
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
        return PyErr_SetFromErrno(PyExc_IOError);  /* LCOV_EXCL_LINE */

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
    ":param string/bytes/path-like file: creates an ACL representing\n"
    "    the access ACL of the specified file or directory.\n"
    ":param string/bytes/path-like filedef: creates an ACL representing\n"
    "    the default ACL of the given directory.\n"
    ":param int/iostream fd: creates an ACL representing\n"
    "    the access ACL of the given file descriptor.\n"
    ":param string text: creates an ACL from a \n"
    "    textual description; note the ACL must be valid, which\n"
    "    means including a mask for extended ACLs, similar to\n"
    "    ``setfacl --no-mask``\n"
    ":param ACL acl: creates a copy of an existing ACL instance.\n"
    ":param int mode: creates an ACL from a numeric mode\n"
    "    (e.g. ``mode=0644``); this is valid only when the C library\n"
    "    provides the ``acl_from_mode call``, and\n"
    "    note that no validation is done on the given value.\n"
    ":param bytes data: creates an ACL from a serialised form,\n"
    "    as provided by calling ``__getstate__()`` on an existing ACL\n"
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
#ifdef HAVE_ACL_COPY_EXT
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
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "posix1e.ACL",
    .tp_basicsize = sizeof(ACL_Object),
    .tp_itemsize = 0,
    .tp_dealloc = ACL_dealloc,
    .tp_str = ACL_str,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = __ACL_Type_doc__,
#ifdef HAVE_LINUX
    .tp_richcompare = ACL_richcompare,
#endif
#ifdef HAVE_LEVEL2
    .tp_iter = ACL_iter,
    .tp_iternext = ACL_iternext,
#endif
    .tp_methods = ACL_methods,
    .tp_init = ACL_init,
    .tp_new = ACL_new,
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
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "posix1e.Entry",
    .tp_basicsize = sizeof(Entry_Object),
    .tp_itemsize = 0,
    .tp_dealloc = Entry_dealloc,
    .tp_str = Entry_str,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = __Entry_Type_doc__,
    .tp_methods = Entry_methods,
    .tp_getset = Entry_getsets,
    .tp_init = Entry_init,
    .tp_new = Entry_new
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
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "posix1e.Permset",
    .tp_basicsize = sizeof(Permset_Object),
    .tp_itemsize = 0,
    .tp_dealloc = Permset_dealloc,
    .tp_str = Permset_str,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = __Permset_Type_doc__,
    .tp_methods = Permset_methods,
    .tp_getset = Permset_getsets,
    .tp_init = Permset_init,
    .tp_new = Permset_new,
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
        return PyErr_SetFromErrnoWithFilename(PyExc_IOError, filename);
    }

    Py_RETURN_NONE;
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
    PyObject *item, *tmp;
    int nret;
    int fd;

    if (!PyArg_ParseTuple(args, "O", &item))
        return NULL;

    if((fd = PyObject_AsFileDescriptor(item)) != -1) {
        if((nret = acl_extended_fd(fd)) == -1) {
            PyErr_SetFromErrno(PyExc_IOError);
        }
    } else {
      // PyObject_AsFileDescriptor sets an error when failing, so clear
      // it such that further code works; some method lookups fail if an
      // error already occured when called, which breaks at least
      // PyOS_FSPath (called by FSConverter).
      PyErr_Clear();
      if(PyUnicode_FSConverter(item, &tmp)) {
        char *filename = PyBytes_AS_STRING(tmp);
        if ((nret = acl_extended_file(filename)) == -1) {
            PyErr_SetFromErrnoWithFilename(PyExc_IOError, filename);
        }
        Py_DECREF(tmp);
      } else {
          nret = -1;
      }
    }

    if (nret < 0) {
        return NULL;
    } else {
        return PyBool_FromLong(nret);
    }
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
    "  - :py:data:`HAS_COPY_EXT` for the :py:func:`ACL.__getstate__` and\n"
    "    :py:func:`ACL.__setstate__` functions (pickle protocol)\n"
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
    ".. py:data:: HAS_COPY_EXT\n\n"
    "   denotes support for __getstate__()/__setstate__() on an ACL\n"
    "\n"
    ;

static struct PyModuleDef posix1emodule = {
    PyModuleDef_HEAD_INIT,
    .m_name = "posix1e",
    .m_doc = __posix1e_doc__,
    .m_size = 0,
    .m_methods = aclmodule_methods,
};

PyMODINIT_FUNC
PyInit_posix1e(void)
{
    PyObject *m, *d;

    if(PyType_Ready(&ACL_Type) < 0)
        return NULL;

#ifdef HAVE_LEVEL2
    if(PyType_Ready(&Entry_Type) < 0)
        return NULL;

    if(PyType_Ready(&Permset_Type) < 0)
        return NULL;
#endif

    m = PyModule_Create(&posix1emodule);
    if (m==NULL)
        return NULL;

    d = PyModule_GetDict(m);
    if (d == NULL)
        return NULL;

    Py_INCREF(&ACL_Type);
    if (PyDict_SetItemString(d, "ACL",
                             (PyObject *) &ACL_Type) < 0)
        return NULL;

    /* 23.3.6 acl_type_t values */
    PyModule_AddIntConstant(m, "ACL_TYPE_ACCESS", ACL_TYPE_ACCESS);
    PyModule_AddIntConstant(m, "ACL_TYPE_DEFAULT", ACL_TYPE_DEFAULT);


#ifdef HAVE_LEVEL2
    Py_INCREF(&Entry_Type);
    if (PyDict_SetItemString(d, "Entry",
                             (PyObject *) &Entry_Type) < 0)
        return NULL;

    Py_INCREF(&Permset_Type);
    if (PyDict_SetItemString(d, "Permset",
                             (PyObject *) &Permset_Type) < 0)
        return NULL;

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

#define LINUX_EXT_VAL 1
#else
#define LINUX_EXT_VAL 0
#endif
    /* declare the Linux extensions */
    PyModule_AddIntConstant(m, "HAS_ACL_FROM_MODE", LINUX_EXT_VAL);
    PyModule_AddIntConstant(m, "HAS_ACL_CHECK", LINUX_EXT_VAL);
    PyModule_AddIntConstant(m, "HAS_EXTENDED_CHECK", LINUX_EXT_VAL);
    PyModule_AddIntConstant(m, "HAS_EQUIV_MODE", LINUX_EXT_VAL);

    PyModule_AddIntConstant(m, "HAS_COPY_EXT",
#ifdef HAVE_ACL_COPY_EXT
                            1
#else
                            0
#endif
                            );
    return m;
}

#include <sys/types.h>
#include <sys/acl.h>

#include <Python.h>

staticforward PyTypeObject ACLType;
static PyObject* ACL_applyto(PyObject* obj, PyObject* args);
static PyObject* ACL_valid(PyObject* obj, PyObject* args);
#ifdef HAVE_LEVEL2
static PyObject* ACL_get_state(PyObject *obj, PyObject* args);
static PyObject* ACL_set_state(PyObject *obj, PyObject* args);

staticforward PyTypeObject ACLEntryType;
#endif

typedef struct {
    PyObject_HEAD
    acl_t acl;
    int entry_id;
} ACLObject;

#ifdef HAVE_LEVEL2

typedef struct {
    PyObject_HEAD
    PyObject *parent; /* The parent object, so it won't run out on us */
    acl_entry_t entry;
} ACLEntryObject;

typedef struct {
    PyObject_HEAD
    acl_permset_t permset;
} PermsetObject;

#endif

/* Creation of a new ACL instance */
static PyObject* ACL_new(PyTypeObject* type, PyObject* args, PyObject *keywds) {
    PyObject* newacl;

    newacl = type->tp_alloc(type, 0);

    if(newacl != NULL) {
        ((ACLObject*)newacl)->acl = NULL;
        ((ACLObject*)newacl)->entry_id = ACL_FIRST_ENTRY;
    }

    return newacl;
}

/* Initialization of a new ACL instance */
static int ACL_init(PyObject* obj, PyObject* args, PyObject *keywds) {
    ACLObject* self = (ACLObject*) obj;
    static char *kwlist[] = { "file", "fd", "text", "acl", NULL };
    char *file = NULL;
    char *text = NULL;
    int fd = -1;
    ACLObject* thesrc = NULL;
    int tmp;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "|sisO!", kwlist,
                                     &file, &fd, &text, &ACLType, &thesrc))
        return -1;
    tmp = 0;
    if(file != NULL)
        tmp++;
    if(text != NULL)
        tmp++;
    if(fd != -1)
        tmp++;
    if(thesrc != NULL)
        tmp++;
    if(tmp > 1) {
        PyErr_SetString(PyExc_ValueError, "a maximum of one argument must be passed");
        return -1;
    }

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
    ACLObject *self = (ACLObject*) obj;
    PyObject *err_type, *err_value, *err_traceback;
    int have_error = PyErr_Occurred() ? 1 : 0;

    if (have_error)
        PyErr_Fetch(&err_type, &err_value, &err_traceback);
    if(acl_free(self->acl) != 0)
        PyErr_WriteUnraisable(obj);
    if (have_error)
        PyErr_Restore(err_type, err_value, err_traceback);
    PyObject_DEL(self);
}

/* Converts the acl to a text format */
static PyObject* ACL_repr(PyObject *obj) {
    char *text;
    ACLObject *self = (ACLObject*) obj;
    PyObject *ret;

    text = acl_to_text(self->acl, NULL);
    if(text == NULL) {
        return PyErr_SetFromErrno(PyExc_IOError);
    }
    ret = PyString_FromString(text);
    if(acl_free(text) != 0) {
        Py_DECREF(ret);
        return PyErr_SetFromErrno(PyExc_IOError);
    }
    return ret;
}

/* Custom methods */
static char __applyto_doc__[] = \
"Apply the ACL to a file or filehandle.\n" \
"\n" \
"Parameters:\n" \
"  - either a filename or a file-like object or an integer; this\n" \
"    represents the filesystem object on which to act\n" \
;

/* Applyes the ACL to a file */
static PyObject* ACL_applyto(PyObject* obj, PyObject* args) {
    ACLObject *self = (ACLObject*) obj;
    PyObject *myarg;
    int type_default = 0;
    acl_type_t type = ACL_TYPE_ACCESS;
    int nret;
    int fd;

    if (!PyArg_ParseTuple(args, "O|i", &myarg, &type_default))
        return NULL;
    if(type_default)
        type = ACL_TYPE_DEFAULT;

    if(PyString_Check(myarg)) {
        char *filename = PyString_AS_STRING(myarg);
        nret = acl_set_file(filename, type, self->acl);
    } else if((fd = PyObject_AsFileDescriptor(myarg)) != -1) {
        nret = acl_set_fd(fd, self->acl);
    } else {
        PyErr_SetString(PyExc_TypeError, "argument 1 must be string, int, or file-like object");
        return 0;
    }
    if(nret == -1) {
        return PyErr_SetFromErrno(PyExc_IOError);
    }

    /* Return the result */
    Py_INCREF(Py_None);
    return Py_None;
}

static char __valid_doc__[] = \
"Test the ACL for validity.\n" \
"\n" \
"This method tests the ACL to see if it is a valid ACL\n" \
"in terms of the filesystem. More precisely, it checks:\n" \
"A valid ACL contains exactly one entry with each of the ACL_USER_OBJ,\n" \
"ACL_GROUP_OBJ, and ACL_OTHER tag types. Entries with ACL_USER and\n" \
"ACL_GROUP tag types may appear zero or more times in an ACL. An ACL that\n" \
"contains entries of ACL_USER or ACL_GROUP tag types must contain exactly\n" \
"one entry of the ACL_MASK tag type. If an ACL contains no entries of\n" \
"ACL_USER or ACL_GROUP tag types, the ACL_MASK entry is optional.\n" \
"\n" \
"All user ID qualifiers must be unique among all entries of ACL_USER tag\n" \
"type, and all group IDs must be unique among all entries of ACL_GROUP tag\n" \
"type." \
;

/* Checks the ACL for validity */
static PyObject* ACL_valid(PyObject* obj, PyObject* args) {
    ACLObject *self = (ACLObject*) obj;

    if(acl_valid(self->acl) == -1) {
        return PyErr_SetFromErrno(PyExc_IOError);
    }

    /* Return the result */
    Py_INCREF(Py_None);
    return Py_None;
}

#ifdef HAVE_LEVEL2

static PyObject* ACL_get_state(PyObject *obj, PyObject* args) {
    ACLObject *self = (ACLObject*) obj;
    PyObject *ret;
    ssize_t size, nsize;
    char *buf;

    size = acl_size(self->acl);
    if(size == -1)
        return PyErr_SetFromErrno(PyExc_IOError);

    if((ret = PyString_FromStringAndSize(NULL, size)) == NULL)
        return NULL;
    buf = PyString_AsString(ret);
    
    if((nsize = acl_copy_ext(buf, self->acl, size)) == -1) {
        Py_DECREF(ret);
        return PyErr_SetFromErrno(PyExc_IOError);
    }
    
    return ret;
}

static PyObject* ACL_set_state(PyObject *obj, PyObject* args) {
    ACLObject *self = (ACLObject*) obj;
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

static PyObject* ACL_iter(PyObject *obj) {
    ACLObject *self = (ACLObject*)obj;
    self->entry_id = ACL_FIRST_ENTRY;
    Py_INCREF(obj);
    return obj;
}

static PyObject* ACL_iternext(PyObject *obj) {
    ACLObject *self = (ACLObject*)obj;
    acl_entry_t the_entry_t;
    ACLEntryObject *the_entry_obj;
    int nerr;
    
    if((nerr = acl_get_entry(self->acl, self->entry_id, &the_entry_t)) == -1)
        return PyErr_SetFromErrno(PyExc_IOError);
    self->entry_id = ACL_NEXT_ENTRY;
    if(nerr == 0) {
        PyErr_SetObject(PyExc_StopIteration, Py_None);
        return NULL;
    }

    the_entry_obj = (ACLEntryObject*) PyType_GenericNew(&ACLEntryType, NULL, NULL);
    if(the_entry_obj == NULL)
        return NULL;
    
    the_entry_obj->entry = the_entry_t;

    the_entry_obj->parent = obj;
    Py_INCREF(obj); /* For the reference we have in entry->parent */

    return (PyObject*)the_entry_obj;
}

/* Creation of a new ACLEntry instance */
static PyObject* ACLEntry_new(PyTypeObject* type, PyObject* args, PyObject *keywds) {
    PyObject* newentry;

    newentry = PyType_GenericNew(type, args, keywds);

    if(newentry != NULL) {
        ((ACLEntryObject*)newentry)->entry = NULL;
        ((ACLEntryObject*)newentry)->parent = NULL;
    }

    return newentry;
}

/* Initialization of a new ACLEntry instance */
static int ACLEntry_init(PyObject* obj, PyObject* args, PyObject *keywds) {
    ACLEntryObject* self = (ACLEntryObject*) obj;
    ACLObject* parent = NULL;

    if (!PyArg_ParseTuple(args, "O!", &ACLType, &parent))
        return -1;

    if(acl_create_entry(&parent->acl, &self->entry) == -1) {
        PyErr_SetFromErrno(PyExc_IOError);
        return -1;
    }

    self->parent = (PyObject*)parent;
    Py_INCREF(parent);

    return 0;
}

/* Free the ACLEntry instance */
static void ACLEntry_dealloc(PyObject* obj) {
    ACLEntryObject *self = (ACLEntryObject*) obj;
    PyObject *err_type, *err_value, *err_traceback;
    int have_error = PyErr_Occurred() ? 1 : 0;

    if (have_error)
        PyErr_Fetch(&err_type, &err_value, &err_traceback);
    if(self->parent != NULL) {
        Py_DECREF(self->parent);
        self->parent = NULL;
    }
    if (have_error)
        PyErr_Restore(err_type, err_value, err_traceback);
    PyObject_DEL(self);
}

static int ACLEntry_set_tag_type(PyObject* obj, PyObject* value, void* arg) {
    ACLEntryObject *self = (ACLEntryObject*) obj;

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

static PyObject* ACLEntry_get_tag_type(PyObject *obj, void* arg) {
    ACLEntryObject *self = (ACLEntryObject*) obj;
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

static int ACLEntry_set_qualifier(PyObject* obj, PyObject* value, void* arg) {
    ACLEntryObject *self = (ACLEntryObject*) obj;
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

static PyObject* ACLEntry_get_qualifier(PyObject *obj, void* arg) {
    ACLEntryObject *self = (ACLEntryObject*) obj;
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
    
    return PyInt_FromLong(value);
}

static PyObject* ACLEntry_get_parent(PyObject *obj, void* arg) {
    ACLEntryObject *self = (ACLEntryObject*) obj;
    
    Py_INCREF(self->parent);
    return self->parent;
}

#endif

static char __acltype_doc__[] = \
"Type which represents a POSIX ACL\n" \
"\n" \
"Parameters:\n" \
"  Only one keword parameter should be provided:\n"
"  - file=\"...\", meaning create ACL representing\n"
"    the ACL of that file\n" \
"  - fd=<int>, meaning create ACL representing\n" \
"    the ACL of that file descriptor\n" \
"  - text=\"...\", meaning create ACL from a \n" \
"    textual description\n" \
"  - acl=<ACL instance>, meaning create a copy\n" \
"    of an existing ACL instance\n" \
;

/* ACL type methods */
static PyMethodDef ACL_methods[] = {
    {"applyto", ACL_applyto, METH_VARARGS, __applyto_doc__},
    {"valid", ACL_valid, METH_NOARGS, __valid_doc__},
#ifdef HAVE_LEVEL2
    {"__getstate__", ACL_get_state, METH_NOARGS, "Dumps the ACL to an external format."},
    {"__setstate__", ACL_set_state, METH_VARARGS, "Loads the ACL from an external format."},
#endif
    {NULL, NULL, 0, NULL}
};


/* The definition of the ACL Type */
static PyTypeObject ACLType = {
    PyObject_HEAD_INIT(NULL)
    0,
    "posix1e.ACL",
    sizeof(ACLObject),
    0,
    ACL_dealloc,        /* tp_dealloc */
    0,                  /* tp_print */
    0,                  /* tp_getattr */
    0,                  /* tp_setattr */
    0,                  /* tp_compare */
    ACL_repr,           /* tp_repr */
    0,                  /* tp_as_number */
    0,                  /* tp_as_sequence */
    0,                  /* tp_as_mapping */
    0,                  /* tp_hash */
    0,                  /* tp_call */
    0,                  /* tp_str */
    0,                  /* tp_getattro */
    0,                  /* tp_setattro */
    0,                  /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT, /* tp_flags */
    __acltype_doc__,    /* tp_doc */
    0,                  /* tp_traverse */
    0,                  /* tp_clear */
    0,                  /* tp_richcompare */
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

/* ACLEntry type methods */
static PyMethodDef ACLEntry_methods[] = {
    {NULL, NULL, 0, NULL}
};

static char __ACLEntry_tagtype_doc__[] = \
"The tag type of the current entry\n" \
"\n" \
"This is one of:\n" \
" - ACL_UNDEFINED_TAG\n" \
" - ACL_USER_OBJ\n" \
" - ACL_USER\n" \
" - ACL_GROUP_OBJ\n" \
" - ACL_GROUP\n" \
" - ACL_MASK\n" \
" - ACL_OTHER\n" \
;

static char __ACLEntry_qualifier_doc__[] = \
"The qualifier of the current entry\n" \
"\n" \
"If the tag type is ACL_USER, this should be a user id.\n" \
"If the tag type if ACL_GROUP, this should be a group id.\n" \
"Else, it doesn't matter.\n" \
;

static char __ACLEntry_parent_doc__[] = \
"The parent ACL of this entry\n" \
;

/* ACLEntry getset */
static PyGetSetDef ACLEntry_getsets[] = {
    {"tag_type", ACLEntry_get_tag_type, ACLEntry_set_tag_type, __ACLEntry_tagtype_doc__},
    {"qualifier", ACLEntry_get_qualifier, ACLEntry_set_qualifier, __ACLEntry_qualifier_doc__},
    {"parent", ACLEntry_get_parent, NULL, __ACLEntry_parent_doc__},
    {NULL}
};

/* The definition of the ACL Entry Type */
static PyTypeObject ACLEntryType = {
    PyObject_HEAD_INIT(NULL)
    0,
    "posix1e.ACLEntry",
    sizeof(ACLEntryObject),
    0,
    ACLEntry_dealloc,   /* tp_dealloc */
    0,                  /* tp_print */
    0,                  /* tp_getattr */
    0,                  /* tp_setattr */
    0,                  /* tp_compare */
    0, //ACLEntry_repr,      /* tp_repr */
    0,                  /* tp_as_number */
    0,                  /* tp_as_sequence */
    0,                  /* tp_as_mapping */
    0,                  /* tp_hash */
    0,                  /* tp_call */
    0,                  /* tp_str */
    0,                  /* tp_getattro */
    0,                  /* tp_setattro */
    0,                  /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT, /* tp_flags */
    __acltype_doc__,    /* tp_doc */
    0,                  /* tp_traverse */
    0,                  /* tp_clear */
    0,                  /* tp_richcompare */
    0,                  /* tp_weaklistoffset */
    0,                  /* tp_iter */
    0,                  /* tp_iternext */
    ACLEntry_methods,   /* tp_methods */
    0,                  /* tp_members */
    ACLEntry_getsets,   /* tp_getset */
    0,                  /* tp_base */
    0,                  /* tp_dict */
    0,                  /* tp_descr_get */
    0,                  /* tp_descr_set */
    0,                  /* tp_dictoffset */
    ACLEntry_init,      /* tp_init */
    0,                  /* tp_alloc */
    ACLEntry_new,       /* tp_new */
};

#endif

/* Module methods */

static char __deletedef_doc__[] = \
"Delete the default ACL from a directory.\n" \
"\n" \
"This function deletes the default ACL associated with \n" \
"a directory (the ACL which will be ANDed with the mode\n" \
"parameter to the open, creat functions).\n" \
"Parameters:\n" \
"  - a string representing the directory whose default ACL\n" \
"    should be deleted\n" \
;

/* Deletes the default ACL from a directory */
static PyObject* aclmodule_delete_default(PyObject* obj, PyObject* args) {
    char *filename;

    /* Parse the arguments */
    if (!PyArg_ParseTuple(args, "s", &filename))
        return NULL;

    if(acl_delete_def_file(filename) == -1) {
        return PyErr_SetFromErrno(PyExc_IOError);
    }

    /* Return the result */
    Py_INCREF(Py_None);
    return Py_None;
}

/* The module methods */
static PyMethodDef aclmodule_methods[] = {
    {"delete_default", aclmodule_delete_default, METH_VARARGS, __deletedef_doc__},
    {NULL, NULL, 0, NULL}
};

static char __posix1e_doc__[] = \
"POSIX.1e ACLs manipulation\n" \
"\n" \
"This module provides support for manipulating POSIX.1e ACLS\n" \
"\n" \
"Depending on the operating system support for POSIX.1e, \n" \
"the ACL type will have more or less capabilities:\n" \
"  - level 1, only basic support, you can create\n" \
"    ACLs from files and text descriptions;\n" \
"    once created, the type is immutable\n" \
"  - level 2, complete support, you can alter\n"\
"    the ACL once it is created\n" \
"\n" \
"Also, in level 2, more types will be available, corresponding\n" \
"to acl_entry_t, acl_permset_t, etc.\n" \
"\n" \
"Example:\n" \
">>> import posix1e\n" \
">>> acl1 = posix1e.ACL(file=\"file.txt\") \n" \
">>> print acl1\n" \
"user::rw-\n" \
"group::rw-\n" \
"other::r--\n" \
"\n" \
">>> b = posix1e.ACL(text=\"u::rx,g::-,o::-\")\n" \
">>> print b\n" \
"user::r-x\n" \
"group::---\n" \
"other::---\n" \
"\n" \
">>> b.applyto(\"file.txt\")\n" \
">>> print posix1e.ACL(file=\"file.txt\")\n" \
"user::r-x\n" \
"group::---\n" \
"other::---\n" \
"\n" \
">>>\n" \
;

DL_EXPORT(void) initposix1e(void) {
    PyObject *m, *d;

    ACLType.ob_type = &PyType_Type;

    if(PyType_Ready(&ACLType) < 0)
        return;

#ifdef HAVE_LEVEL2
    ACLEntryType.ob_type = &PyType_Type;

    if(PyType_Ready(&ACLEntryType) < 0)
        return;
#endif

    m = Py_InitModule3("posix1e", aclmodule_methods, __posix1e_doc__);

    d = PyModule_GetDict(m);
    if (d == NULL)
        return;

    Py_INCREF(&ACLType);
    if (PyDict_SetItemString(d, "ACL",
                             (PyObject *) &ACLType) < 0)
        return;
#ifdef HAVE_LEVEL2
    Py_INCREF(&ACLEntryType);
    if (PyDict_SetItemString(d, "ACLEntry",
                             (PyObject *) &ACLEntryType) < 0)
        return;

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

    /* 23.3.6 acl_type_t values */    
    PyModule_AddIntConstant(m, "ACL_TYPE_ACCESS", ACL_TYPE_ACCESS);
    PyModule_AddIntConstant(m, "ACL_TYPE_DEFAULT", ACL_TYPE_DEFAULT);

#endif
}

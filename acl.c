#include <sys/types.h>
#include <sys/acl.h>

#include <Python.h>

staticforward PyTypeObject ACLType;
static PyObject* ACL_applyto(PyObject* obj, PyObject* args);
static PyObject* ACL_valid(PyObject* obj, PyObject* args);
#ifdef HAVE_LEVEL2
static PyObject* ACL_get_state(PyObject *obj, PyObject* args);
#endif

typedef struct {
    PyObject_HEAD
    acl_t ob_acl;
} ACLObject;

/* ACL type methods */
static PyMethodDef ACL_methods[] = {
    {"applyto", ACL_applyto, METH_VARARGS, "Apply the ACL to a file or filehandle."},
    {"valid", ACL_valid, METH_NOARGS, "Test the ACL for validity."},
#ifdef HAVE_LEVEL2
    {"__getstate__", ACL_get_state, METH_NOARGS, "Dumps the ACL to an external format."},
#endif
    {NULL, NULL, 0, NULL}
};

/* Creation of a new ACL instance */
static PyObject* ACL_new(PyObject* self, PyObject* args, PyObject *keywds) {
    ACLObject* theacl;
    static char *kwlist[] = { "file", "fd", "text", "acl", NULL };
    char *file = NULL;
    char *text = NULL;
    int fd = -1;
    ACLObject* thesrc = NULL;
    int tmp;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "|sisO!", kwlist,
                                     &file, &fd, &text, &ACLType, &thesrc))
        return NULL;
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
        return NULL;
    }

    theacl = PyObject_New(ACLObject, &ACLType);
    if(file != NULL)
        theacl->ob_acl = acl_get_file(file, ACL_TYPE_ACCESS);
    else if(text != NULL)
        theacl->ob_acl = acl_from_text(text);
    else if(fd != -1)
        theacl->ob_acl = acl_get_fd(fd);
    else if(thesrc != NULL)
        theacl->ob_acl = acl_dup(thesrc->ob_acl);
    else
        theacl->ob_acl = acl_init(0);
    if(theacl->ob_acl == NULL) {
        Py_DECREF(theacl);
        return PyErr_SetFromErrno(PyExc_IOError);
    }

    return (PyObject*)theacl;
}

/* Standard type functions */
static void ACL_dealloc(PyObject* obj) {
    ACLObject *self = (ACLObject*) obj;
    PyObject *err_type, *err_value, *err_traceback;
    int have_error = PyErr_Occurred() ? 1 : 0;

    if (have_error)
        PyErr_Fetch(&err_type, &err_value, &err_traceback);
    if(acl_free(self->ob_acl) != 0)
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

    text = acl_to_text(self->ob_acl, NULL);
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
        nret = acl_set_file(filename, type, self->ob_acl);
    } else if((fd = PyObject_AsFileDescriptor(myarg)) != -1) {
        nret = acl_set_fd(fd, self->ob_acl);
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

/* Checks the ACL for validity */
static PyObject* ACL_valid(PyObject* obj, PyObject* args) {
    ACLObject *self = (ACLObject*) obj;

    if(acl_valid(self->ob_acl) == -1) {
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

    size = acl_size(self->ob_acl);
    if(size == -1)
        return PyErr_SetFromErrno(PyExc_IOError);

    if((ret = PyString_FromStringAndSize(NULL, size)) == NULL)
        return NULL;
    buf = PyString_AsString(ret);
    
    if((nsize = acl_copy_ext(buf, self->ob_acl, size)) == -1) {
        Py_DECREF(ret);
        return PyErr_SetFromErrno(PyExc_IOError);
    }
    
    return ret;
}

#endif

/* The definition of the ACL Type */
static PyTypeObject ACLType = {
    PyObject_HEAD_INIT(NULL)
    0,
    "ACL",
    sizeof(ACLObject),
    0,
    ACL_dealloc,/*tp_dealloc*/
    0,          /*tp_print*/
    0,          /*tp_getattr*/
    0,          /*tp_setattr*/
    0,          /*tp_compare*/
    ACL_repr,   /*tp_repr*/
    0,          /*tp_as_number*/
    0,          /*tp_as_sequence*/
    0,          /*tp_as_mapping*/
    0,          /*tp_hash*/
    0,          /*tp_call*/
    0,          /*tp_str*/
    0,          /*tp_getattro*/
    0,          /*tp_setattro*/
    0,          /*tp_as_buffer*/
    0,          /*tp_flags*/
    "Type which represents a POSIX ACL", /*tp_doc*/
    0,          /*tp_traverse*/
    0,          /*tp_clear*/
    0,          /*tp_richcompare*/
    0,          /*tp_weaklistoffset*/
    0,          /*tp_iter*/
    0,          /*tp_iternext*/
    ACL_methods, /*tp_methods*/
};

/* Module methods */

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
    {"ACL", (PyCFunction)ACL_new, METH_VARARGS|METH_KEYWORDS, "Create a new ACL object."},
    {"delete_default", aclmodule_delete_default, 
     METH_VARARGS, "Delete the default ACL from a directory."},
    {NULL, NULL, 0, NULL}
};

DL_EXPORT(void) initacl(void) {
    ACLType.ob_type = &PyType_Type;

    if(PyType_Ready(&ACLType) < 0)
        return;
    Py_InitModule("acl", aclmodule_methods);
}

#include <sys/types.h>
#include <sys/acl.h>

#include <Python.h>

staticforward PyTypeObject ACLType;

typedef struct {
    PyObject_HEAD
    acl_t ob_acl;
} ACLObject;

static PyObject* new_ACL(PyObject* self, PyObject* args) {
    ACLObject* theacl;

    if (!PyArg_ParseTuple(args,"")) 
        return NULL;

    theacl = PyObject_New(ACLObject, &ACLType);
    theacl->ob_acl = acl_init(0);
    if(theacl->ob_acl == NULL) {
        Py_DECREF(theacl);
        return PyErr_SetFromErrno(PyExc_IOError);
    }

    return (PyObject*)theacl;
}

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

static PyTypeObject ACLType = {
    PyObject_HEAD_INIT(NULL)
    0,
    "ACL",
    sizeof(ACLObject),
    0,
    ACL_dealloc, /*tp_dealloc*/
    0,          /*tp_print*/
    0,          /*tp_getattr*/
    0,          /*tp_setattr*/
    0,          /*tp_compare*/
    ACL_repr,   /*tp_repr*/
    0,          /*tp_as_number*/
    0,          /*tp_as_sequence*/
    0,          /*tp_as_mapping*/
    0,          /*tp_hash */
};

static PyMethodDef acl_methods[] = {
    {"ACL", new_ACL, METH_VARARGS, "Create a new ACL object."},
    {NULL, NULL, 0, NULL}
};

DL_EXPORT(void) initacl(void) {
    ACLType.ob_type = &PyType_Type;

    Py_InitModule("acl", acl_methods);
}

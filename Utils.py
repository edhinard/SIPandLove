#coding: utf-8

import re
import collections

ESCAPE_RE=re.compile('\\\\[\r\n]')
def unquote(string):
    if not (string.startswith('"') and string.endswith('"')):
        return string
    string = string[1:-1].replace('\\\\', '\\').replace('\\"', '"')
    if string and (string[-1] == '\\' or ESCAPE_RE.match(string)):
        raise Exception("Unexpected backslash in quoted-string")
    return string
NONTOKENCHARS_RE=re.compile('[] \t"#$&(),/:;<=>?@[\\\\^{|}]')
def quote(string,forcequote=False):
    if string is None:
        return None
    string = str(string)
    quotealreadythere = False
    if string.startswith('"') and string.endswith('"'):
        quotealreadythere = True
        string = string[1:-1]
    if quotealreadythere or \
       forcequote or \
       NONTOKENCHARS_RE.search(string) or \
       string!=string.encode('ascii','ignore').decode('ascii'):
        return '"{}"'.format(string.replace('\\', '\\\\').replace('"', '\\"'))
    return string


class ParameterDict:
    """Dictionary, that has ordered case-insensitive keys.

    from http://code.activestate.com/recipes/66315-case-insensitive-dictionary/
    + change dict to OrderedDict
    
    Keys are retained in their original form
    when queried with .keys() or .items().

    Implementation: An internal dictionary maps lowercase
    keys to (key,value) pairs. All key lookups are done
    against the lowercase keys, but all methods that expose
    keys to the user retrieve the original keys."""
    
    def __init__(self, dictorlist=None):
        """Create an empty dictionary, or update from 'dict'."""
        self._dict = collections.OrderedDict()
        if isinstance(dictorlist, dict):
            self.update(dictorlist)
        elif dictorlist is not None:
            for k,v in dictorlist:
                self[k] = v

    def __bool__(self):
        return bool(self._dict)
            
    def __getitem__(self, key):
        """Retrieve the value associated with 'key' (in any case)."""
        k = key.lower()
        return self._dict[k][1]

    def __setitem__(self, key, value):
        """Associate 'value' with 'key'. If 'key' already exists, but
        in different case, it will be replaced."""
        k = key.lower()
        self._dict[k] = (key, value)

    def has_key(self, key):
        """Case insensitive test wether 'key' exists."""
        k = key.lower()
        return self._dict.has_key(k)

    def keys(self):
        """List of keys in their original case."""
        return [v[0] for v in self._dict.values()]

    def __iter__(self):
        for k in self.keys():
            yield k

    def values(self):
        """List of values."""
        return [v[1] for v in self._dict.values()]

    def items(self):
        """List of (key,value) pairs."""
        return self._dict.values()

    def get(self, key, default=None):
        """Retrieve value associated with 'key' or return default value
        if 'key' doesn't exist."""
        try:
            return self[key]
        except KeyError:
            return default

    def pop(self, key, default=None):
        """If key is in the dictionary, remove it and return its value, else return default."""
        k = key.lower()
        return self._dict.pop(k, default)

    def setdefault(self, key, default):
        """If 'key' doesn't exists, associate it with the 'default' value.
        Return value associated with 'key'."""
        if not self.has_key(key):
            self[key] = default
        return self[key]

    def update(self, dict):
        """Copy (key,value) pairs from 'dict'."""
        for k,v in dict.items():
            self[k] = v

    def __repr__(self):
        """String representation of the dictionary."""
        items = ", ".join([("%r: %r" % (k,v)) for k,v in self.items()])
        return "{%s}" % items

    def __str__(self):
        """String representation of the dictionary."""
        return repr(self)




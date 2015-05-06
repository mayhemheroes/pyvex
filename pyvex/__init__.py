import pyvex_c
import sys

import collections
_counts = collections.Counter()

class vex(object):
    pass
    #def __init__(self):
    #   #print "CREATING:",type(self)
    #   _counts[type(self)] += 1

    #def __del__(self):
    #   #print "DELETING:",type(self)
    #   _counts[type(self)] -= 1

class PyVEXError(Exception): pass

# various objects
class IRSB(vex):
    def __init__(self, *args, **kwargs):
        vex.__init__(self)

        self.statements = ()
        self.tyenv = None
        self.offsIP = None
        self.next = None
        self.jumpkind = None

        arch = kwargs.pop('arch')
        self.arch = arch
        kwargs['arch'] = arch.vex_arch
        kwargs['endness'] = arch.vex_endness

        pyvex_c.init_IRSB(self, *args, **kwargs)

        for stmt in self.statements:
            stmt.arch = self.arch
        for expr in self.expressions:
            expr.arch = self.arch

    def pp(self):
        print "IRSB {"
        print "   %s" % self.tyenv
        print ""
        for i,s in enumerate(self.statements):
            print "   %02d | %s" % (i,s)
        print "   NEXT: PUT(%s) = %s; %s" % (self.arch.translate_register_name(self.offsIP), self.next, self.jumpkind)
        print "}"

    @property
    def expressions(self):
        '''
        All expressions contained in the IRSB.
        '''
        expressions = [ ]
        for s in self.statements:
            expressions.extend(s.expressions)
        expressions.append(self.next)
        return expressions

    @property
    def operations(self):
        '''
        All operations done by the IRSB.
        '''
        ops = [ ]
        for e in self.expressions:
            if hasattr(e, 'op'):
                ops.append(e.op)
        return ops

    @property
    def all_constants(self):
        '''
        Returns all constants (including incrementing of the program counter).
        '''
        return sum((e.constants for e in self.expressions), [ ])

    @property
    def constants(self):
        '''
        The constants (excluding updates of the program counter) in the IRSB.
        '''
        return sum((s.constants for s in self.statements if not (isinstance(s, IRStmt.Put) and s.offset == self.offsIP)), [ ])

class IRTypeEnv(vex):
    def __init__(self, types):
        vex.__init__(self)
        self.types = types
        self.types_used = len(types)

    def __str__(self):
        return ' '.join(("t%d:%s" % (i,t)) for i,t in enumerate(self.types))

class IRCallee(vex):
    def __init__(self, regparms, name, addr, mcx_mask):
        vex.__init__(self)
        self.regparms = regparms
        self.name = name
        self.mcx_mask = mcx_mask
        self.addr = addr

    def __str__(self):
        return self.name

class IRRegArray(vex):
    def __str__(self):
        return "%s:%sx%d" % (self.base, self.elemTy[4:], self.nElems)

from . import IRConst
from . import IRExpr
from . import IRStmt

# and initialize!
pyvex_c.init(sys.modules[__name__])
for objname in dir(pyvex_c):
    if not objname.startswith('enum'):
        continue
    setattr(sys.modules[__name__], objname, getattr(pyvex_c, objname))
typeOfIROp = pyvex_c.typeOfIROp
set_iropt_level = pyvex_c.set_iropt_level
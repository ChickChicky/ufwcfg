#!/usr/bin/env python3

from typing import Callable, Any, Iterable, TypeVar

from dataclasses import dataclass
from pathlib import Path
from shlex import quote
from subprocess import call
from sys import stdin, stdout, stderr, argv
from traceback import print_exception
from urllib.parse import urlsplit

_CMD = tuple[str,...]|list[str]

BASE_LEVEL = 1000
MIN_LEVEL = 0
TABSIZE = 2

T = TypeVar('T')
U = TypeVar('U')
def first( it: Iterable[T], pred: Callable[[T], bool], default: Callable[[], U] = lambda: None ) -> T|U:
    try:
        return next(i for i in it if pred(i))
    except:
        return default()

def run( cmd: _CMD ):
    cmd = ('ufw', *cmd)
    print('\x1b[94m# \x1b[1m%s\x1b[39;22m'%' '.join(map(quote, cmd)))
    return
    try:
        e = call(cmd, stdin=stdin, stdout=stdout, stderr=stderr)
        if e != 0:
            exit(e)
    except BaseException as e:
        if isinstance(e, FileNotFoundError):
            print('\x1b[31;1mERROR\x1b[90m:\x1b[39;22m %r not found'%e.filename)
        exit(1)
        
class CmdGroup:
    
    base: tuple[str, ...]
    sub: list[_CMD]
    
    def __init__( self, base: _CMD, sub: list|None = None ):
        self.base = tuple(base)
        self.sub = [] if sub == None else sub
        
    def commands( self ) -> tuple[tuple[str, ...], ...]:
        return (self.base,) if len(self.sub) == 0 else tuple(self.base+tuple(sub) for sub in self.sub)
    
    def append( self, sub: _CMD ):
        self.base += tuple(sub)
        
    def add( self, sub: _CMD ):
        self.sub.append(sub)
        
# taken from urllib.parse._NetlocResultMixinStr._hostinfo
def parse_netloc( netloc: str ) -> tuple[str, str|None]:
    _, have_open_br, bracketed = netloc.partition('[')
    if have_open_br:
        hostname, _, port = bracketed.partition(']')
        _, _, port = port.partition(':')
    else:
        hostname, _, port = netloc.partition(':')
    if not port:
        port = None
    return hostname, port

@dataclass
class LinePart:
    raw: str
    col: int
    part: str
    trans: dict[int, int]
    
    # TODO: Make the sheiße more efficient
    def mktrans( self, base: int, count: int = 1 ) -> tuple[int, int]:
        get = lambda k: self.trans.get(k, 0)
        return sum(map(get, range(base))), sum(map(get, range(base, base+count)))
    
    def bite( self, n: int ) -> 'LinePart':
        get = lambda k: self.trans.get(k, 0)
        base = sum(map(get, range(n)))
        return LinePart(self.raw[base:], self.col+n, self.part[n:], {i: c for i, c in self.trans.items() if i >= base})

def split_parts( line: str ) -> list[LinePart]:
    if len(line) == 0:
        return []
    parts = [LinePart('', 0, '', {})]
    part = parts[0]
    i = 0
    o = 0
    while i < len(line):
        c = line[i]
        if c not in (' ', '\t'):
            part.raw += c
        if c == '\\':
            # TODO: Add more complex escapes?
            part.trans[len(part.part)] = 2
            i += 1
            part.part += line[i]
            part.raw += line[i]
        elif c in (' ', '\t'):
            if c == '\t':
                o += 1
            part = LinePart('', i+1+o*2, '', {})
            parts.append(part) 
        else:
            part.trans[len(part.part)] = 1
            part.part += c
        i += 1
    return parts
        
cfg_handlers: dict[str, Callable[[list[CmdGroup]], Callable[[str], Any]]] = {}
        
def cfg_handler( name: str ):
    def wrapper( func: Callable[[list[CmdGroup]], Callable[[str], Any]] ):
        cfg_handlers[name] = func
        return func
    return wrapper

class SE( BaseException ):
    pass

class ERR( BaseException ):
    pass

def parse_cfg( cfg_path: str ) -> list[CmdGroup]:
    path = Path(cfg_path).absolute()
    
    rules: list[CmdGroup] = []
    limits: list[CmdGroup] = []
    
    categories: dict[str, list[CmdGroup]] = {
        'rules': rules,
        'limits': limits
    }
    
    category = ''
    line_handler = None
    
    with open(path, 'rt') as file:
        
        ln = 0
        for line in file:
            ln += 1
            line = line.rstrip()
            
            if len(line) == 0 or line [0] == '#':
                continue
            
            try:
                
                if line[0] == '[':
                    if not line.endswith(']'):
                        raise SE('Category line must end with "]"', len(line))
                    category = line[1:-1]
                    cmds = categories.get(category)
                    if cmds == None:
                        raise SE('Unknown category', 1, len(category))
                    handler = cfg_handlers.get(category)
                    if handler == None:
                        raise SE('Unknown category', 1, len(category))
                    line_handler = handler(cmds)
                    
                else:
                    if not line_handler:
                        raise SE('Junk before categories', 0, len(line))
                    line_handler(line)
            
            except BaseException as e:
                if isinstance(e, SE):
                    err = e.args[0] if len(e.args) >= 1 else '?'
                    cn = int(e.args[1]) if len(e.args) >= 2 else None
                    cc = int(e.args[2]) if len(e.args) >= 3 and e.args[2] else 1
                    tb = e.args[3] if len(e.args) >= 4 and e.args[3] else None
                    print('\x1b[31;1mSYNTAX ERROR\x1b[90m:\x1b[39;22m %s'%err)
                    # TODO: Display spaces/tabs
                    print('  '+line.replace('\t', '\x1b[90;1m›\x1b[39;22m'+' '*(TABSIZE-1)))
                    if cn != None:
                        print('  '+' '*cn+'\x1b[95m'+'^'*cc+'\x1b[39m')
                    print()
                    print('  at %s:%d%s'%(quote(str(path)), ln, ':%d'%(cn+1) if cn != None else ''))
                    if category:
                        print('  in %r'%category)
                    if isinstance(tb, str):
                        print('  '+tb)
                    elif isinstance(tb, (list, tuple)):
                        for l in tb:
                            print('  '+l)
                elif isinstance(e, ERR):
                    # TODO: Handle that
                    print_exception(e)
                else:
                    print_exception(e)
                exit(1)
    
    return rules + limits

_program = argv.pop(0)

if len(argv) == 0:
    print('\x1b[31;1mERROR\x1b[90m:\x1b[39;22m No config file specified')
    exit(1)
cfg_path = argv.pop(0)

@cfg_handler('rules')
def handle_rules( rules: list[CmdGroup] ):
    current_itf = None
    last_rule = None
    
    directions_rev = {
        ('in',): { '<', '<.', '<-', '<=' },
        ('out',): { '>', '.>', '->', '=>' },
        ('in','out'): { '<>', '<.>', '<->', '<=>' }
    }
    directions = {dr: dd for dd, dl in directions_rev.items() for dr in dl}
    
    actions_raw = {
        'allow': { 'a', 'allow', 'y', 'yes', 'v', 'ok',   },
        'deny':  { 'd', 'deny',  'n', 'no',  'x', 'nope', }
    }
    actions = {ar: aa for aa, al in actions_raw.items() for ar in al}
    
    # TODO: Ensure proper rule order (ie. only allow more restrictive rules after lesser ones)
    
    def next( line: str ):
        nonlocal current_itf, last_rule
        errinfo = ('on interface %r'%current_itf,) if current_itf else None
        
        l0 = len(line)
        line = line.lstrip('\t')
        lvl = l0-len(line)
        
        def process_filters( parts: list[LinePart] ):
            if not last_rule:
                raise SE('Not under any rule', lvl*TABSIZE, len(line))
            for part in parts:
                if part.part.startswith('/'):
                    last_rule.append(('proto', part.part[1:]))
                else:
                    rd = first(directions, lambda d: part.part.startswith(d))
                    d = directions.get(rd) if rd else None
                    if d and rd:
                        rest = part.bite(len(rd))
                        host, port = parse_netloc(rest.part)
                        for d2 in d:
                            # append/add?
                            last_rule.append(('to' if d2 == 'in' else 'from', host or 'any'))
                            if port:
                                last_rule.append(('port', port))
                    else:
                        raise SE('Unrecognized filter', part.col+lvl*TABSIZE, len(part.raw))
        
        if lvl == 0:
            raise SE('Bad indentation', 0, 1, errinfo)
        elif lvl == 1:
            current_itf = line
            last_rule = None
        elif lvl == 2:
            if not current_itf:
                raise SE('Not under any interface', 4, len(line))
            parts = split_parts(line)
            if len(parts) < 1:
                raise SE('Missing direction', lvl*TABSIZE, 1, )
            d = directions.get(parts[0].part)
            if not d:
                raise SE('Bad direction', parts[0].col+lvl*TABSIZE, len(parts[0].raw), errinfo)
            if len(parts) < 2:
                raise SE('Missing action', parts[0].col+len(parts[0].raw)+lvl*TABSIZE, 1, errinfo)
            a = actions.get(parts[1].part)
            if not a:
                raise SE('Bad action', parts[1].col+lvl*TABSIZE, len(parts[1].raw), errinfo)
            for d2 in d:
                last_rule = CmdGroup((a, d2, 'on', current_itf))
                rules.append(last_rule)
                process_filters(parts[2:])
        elif lvl == 3:
            process_filters(split_parts(line))
        else:
            raise SE('Bad indentation', 0, lvl*TABSIZE, errinfo)
        
    return next

@cfg_handler('limits')
def handle_limits( limits: list[CmdGroup] ):
    def next( line: str ):
        limits.append(CmdGroup(('limit', line.strip())))
    return next

for command in (('reset',), *parse_cfg(cfg_path), ('enable',)):
    for cmd in command.commands() if isinstance(command, CmdGroup) else (command,):
        run(cmd)

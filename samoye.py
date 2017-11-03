#!/usr/bin/python
import re
import shlex
from cmd import Cmd
import os
import inspect
from ctypes import *
from xml.etree.ElementTree import parse, tostring, iterparse
import json
import time
import traceback
import odsp_path
import math
import string
import sys
sys.path.append('/odsp/scripts')
import devmgt

devmgt.is_return_2_c = False

#log = open('/tmp/ntcli-log', 'a')
debug = False

def cur_time_str():
    return time.strftime('%Y-%m-%d %H:%M:%S')

def write_log(msg):
    pass
    #global log
    #log.write('%s: %s\n' % (cur_time_str(), msg))
    #log.flush()

class Unit:
    unit = ['Byte','KB','MB','GB','TB','PB','EB']
    coef = {'Byte': pow(1024,0),
        'KiB' : pow(1024,1),
        'MiB' : pow(1024,2),
        'GiB' : pow(1024,3),
        'TiB' : pow(1024,4),
        'PiB' : pow(1024,5),
        'EiB' : pow(1024,6),
        'KB'  : pow(1024,1),
        'MB'  : pow(1024,2),
        'GB'  : pow(1024,3),
        'TB'  : pow(1024,4),
        'PB'  : pow(1024,5),
        'EB'  : pow(1024,6)}

    def __init__(self, size, ceil=None):
        m = re.search('([0-9.]+)([a-zA-Z]+)', size)
        val = m.group(1)
        unit = m.group(2)

        self.byte_size = float(val) * Unit.coef[unit]
        if ceil:
           ceil_size = math.ceil(self.__convert_size(self.byte_size, ceil))
           self.byte_size = Unit('%s%s' % (ceil_size, ceil)).byte_size

    def __getattr__(self, name):
        if not name in Unit.coef: return None
        return self.__convert(self.byte_size, name)

    def __convert(self, byte_size, unit):
        size = self.__convert_size(byte_size, unit)
        if float('%.2f' % size).is_integer(): return '%d%s' % (size, unit)
        return '%.2f%s' % (size, unit)

    def __convert_size(self, byte_size, unit):
        d = Unit.coef[unit]
        size = byte_size / d
        return size

    def __str__(self):
        for u in Unit.unit:
            size = self.__convert_size(self.byte_size, u)
            if size < 1024: return getattr(self, u)


class AttrObject(dict):
    def __getattr__(self, name):
        if name in self: return self[name]
        else: return None

class XMLFormat:
    ATTR_ORDER = ('basetype', 'name', 'units', 'key', 'type', 'format')
    def lines(func):
        def expand_lines(lines):
            expanded = []
            for l in lines:
                if isinstance(l, str):
                    expanded.append(l)
                else:
                    expanded.extend(expand_lines(l))
            return expanded

        def __lines_1(*vargs, **kv):
            out = func(*vargs, **kv)
            return expand_lines(out)
        return __lines_1

    def __init__(self):
        self.xml = parse(os.path.join(os.path.split(__file__)[0], 'dothill.xml'))

    def format(self, odsptype, obj):
        self.oid = 0
        if odsptype:
            self.OBJECT = self.xml.find('OBJECT[@odsptype="%s"]' % odsptype)
            self.SUBOBJECT = self.OBJECT.find('SUBOBJECT')
            self.PROPERTY = self.OBJECT.findall('PROPERTY')
            self.SUBPROPERTY = (not self.SUBOBJECT is None) and self.SUBOBJECT.findall('PROPERTY') or []
            self.ALL_PROPERTY = self.OBJECT.findall('.//PROPERTY')

            self.odspfields = [PRO.get('odspfield') for PRO in self.ALL_PROPERTY]
            if isinstance(obj, str):
                obj = self.__mapobj(obj)
        return '\n'.join(self.__format_obj(obj))

    @lines
    def __format_obj(self, obj):
        return ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
                '<RESPONSE VERSION="L100">',
                [self.__indent(self.__format_single_obj(so)) for so in obj],
                self.__indent(self.__status(obj)),
                '</RESPONSE>']

    def error(self, message):
        return '\n'.join(['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
                '<RESPONSE VERSION="L100">',
                '  <COMP G="0" P="1"/>',
                '  <OBJECT basetype="status" name="status" oid="1">',
                '    <PROPERTY name="response-type" type="string">Error</PROPERTY>',
                '    <PROPERTY name="response-type-numeric" type="uint32">1</PROPERTY>',
                '    <PROPERTY name="response" type="string">%s</PROPERTY>' % message,
                '    <PROPERTY name="return-code" type="sint32">0</PROPERTY>',
                '    <PROPERTY name="component-id" type="string"></PROPERTY>',
                '    <PROPERTY name="time-stamp" type="string">%s</PROPERTY>' % cur_time_str(),
                '    <PROPERTY name="time-stamp-numeric" type="uint32">0</PROPERTY>',
                '  </OBJECT>',
                '</RESPONSE>'])

    def __status(self, obj):
        self.oid += 1
        return ['<COMP G="0" P="%s"/>' % self.oid,
                '<OBJECT basetype="status" name="status" oid="%s">' % self.oid,
                '  <PROPERTY name="response-type" type="string">Success</PROPERTY>',
                '  <PROPERTY name="response-type-numeric" type="uint32">0</PROPERTY>',
                '  <PROPERTY name="response" type="string">Command completed successfully.</PROPERTY>',
                '  <PROPERTY name="return-code" type="sint32">0</PROPERTY>',
                '  <PROPERTY name="component-id" type="string"></PROPERTY>',
                '  <PROPERTY name="time-stamp" type="string">%s</PROPERTY>' % cur_time_str(),
                '  <PROPERTY name="time-stamp-numeric" type="string">%s</PROPERTY>' % int(time.time()),
                '</OBJECT>']

    @lines
    def __format_single_obj(self, obj):
        self.oid += 1
        self.suboid = self.oid
        subfield = (not self.SUBOBJECT is None) and self.SUBOBJECT.get('odspfield') or ''
        sub_objs = subfield and obj[subfield] or [obj]

        xml = ['<COMP G="0" P="%s"/>' % self.oid,
               '<OBJECT %s oid="%s">' % (self.__get_attrib(self.OBJECT), self.oid),
               self.__indent(self.__format_prop(self.PROPERTY, obj)),
               '</OBJECT>',
               [self.__format_subobj(so) for so in sub_objs]]
        self.oid = self.suboid
        return xml

    @lines
    def __format_subobj(self, obj):
        if self.SUBOBJECT is None: return []
        self.suboid += 1
        return ['<COMP G="%s" P="%s"/>' % (self.oid, self.suboid),
                '<OBJECT %s oid="%s">' % (self.__get_attrib(self.SUBOBJECT), self.suboid),
                self.__indent(self.__format_prop(self.SUBPROPERTY, obj)),
                '</OBJECT>']

    @lines
    def __format_prop(self, PROPERTY, sobj):
        return ['<PROPERTY %s>%s</PROPERTY>' %\
            (self.__get_attrib(PRO), self.__map_single_prop(PRO, sobj)) for PRO in PROPERTY]

    def __get_attrib(self, NODE):
        items = NODE.attrib.copy()
        odspkey = [k for k in items if k.find('odsp') <> -1]
        for k in odspkey:
            del items[k]
        return ' '.join(['%s="%s"' % (k, items[k]) for k in XMLFormat.ATTR_ORDER if items.has_key(k)])

    def __has_text(self, NODE):
        return NODE.text and NODE.text.lstrip().rstrip()

    def __map_single_prop(self, S_PROPERTY, sobj):
        if self.__has_text(S_PROPERTY): return S_PROPERTY.text
        VALMAP = S_PROPERTY.findall('VALMAP')
        valmap = dict([(VM.get('odspval'), VM.get('val')) for VM in VALMAP])
        odspval = sobj[S_PROPERTY.get('odspfield')]
        return valmap.get(odspval, odspval)

    def __mapobj(self, obj):
        vals = zip(*[re.findall('%s\s*:\s*([^\n]+)' % field, obj) for field in self.odspfields])
        return [dict(zip(self.odspfields, v)) for v in vals]

    def __indent(self, lines):
        return ['  %s' % line for line in lines]


class Str2List:
    def __call__(self, s):
        return self.__colon_list(s)

    def __split2(self, s):
        m = re.search('(\d+)$', s)
        s2 = m.group(1)
        return s[0:-len(s2)], s2

    def __hyphen_list(self, s):
        m = re.search('^([^-]+)-([^-]+)$', s)
        if s.startswith('"') and s.endswith('"'): return [s[1:-1]]
        if not m: return [s.lstrip().rstrip()]
        start1,start2 = self.__split2(m.group(1))
        end1,end2 = self.__split2(m.group(2))
        return ['%s%s' % (start1.lstrip().rstrip(), i) for i in range(int(start2), int(end2)+1)]

    def __comma_list(self, s):
        l = []
        for h in s.split(','):
            l = l + self.__hyphen_list(h)
        return l

    def __colon_list(self, s):
        l = []
        for c in s.split(':'):
            l = l + self.__comma_list(c)
            l = l + [':']
        return l[:-1]

    def to_list(self, s):
        return self.__colon_list(s)

class CmdError(Exception):
    def __init__(self, msg='', detail=''):
        Exception.__init__(self, msg)
        self.detail = detail

class InvalidParameters(CmdError):
    def __init__(self, name='', val=''):
        CmdError.__init__(self, 'Invalid Parameters.(%s=%s)' % (name, val))
        self.name = name
        self.val = val

class NodeNotExisted(CmdError):
    def __init__(self, name):
        CmdError.__init__(self, '%s not existed' % name)

class EnumCheck:
    def __init__(self, enum, ignorecase=True):
        self.enum = enum
        self.ignorecase = ignorecase
        if ignorecase and isinstance(self.enum[0], str):
            self.enum = [e.upper() for e in enum]

    def __call__(self, s):
        if self.ignorecase:
            s = s.upper()
        if not s in self.enum: raise CmdError('Unsurpported Value')

def args():
    _args = inspect.getargvalues(inspect.stack()[1][0]).args
    _locals = inspect.getargvalues(inspect.stack()[1][0]).locals
    return dict([(a, _locals[a]) for a in _args if a <> 'self'])

def make_opt(name, default=None, nokey=False, convertor=str, check=None):
    ao = AttrObject()
    ao.update(args())
    ao['argname'] = name.replace('-', '_')
    return ao


def options(*opt_desc):
    def get_opt_val(tokens, name):
        try:
            idx = tokens.index(name)
            eidx = idx+1
            if ' '.join(tokens[idx:eidx]) == name:
                val = tokens[eidx]
                return tokens[0:idx] + tokens[eidx+1:], val
        except:
            return tokens, None

    def get_opts(line, opt_desc, opt2val):
        opts = {}
        tokens = shlex.split(line)
        for o in opt_desc:
            if o.nokey: continue
            tokens, val = get_opt_val(tokens, o.name)
            if val: 
                opt2val[o.name] = val
                newval = o.convertor(val)
                if o.check: 
                    try:
                        o.check(newval)
                    except:
                        raise InvalidParameters(o.name, val)
                opts[o.argname] = newval
        return opts, tokens

    def check_undefault_opts(opts, opt_desc):
        for desc in opt_desc:
            if desc.default is None and not desc.nokey:
                if not desc.name in opts:
                    raise CmdError('Missing Options: %s' % desc.name)

    def insert_nokey_opts(tokens, opts, opt_desc, opt2val):
        tokens.reverse()
        for desc in opt_desc:
            if desc.nokey:
                if len(tokens) == 0: 
                    if not desc.default is None:
                        opts[desc.argname] = desc.default
                    else:
                        raise CmdError('Missing: %s' % desc.name)
                else:
                    try:
                        val = tokens.pop()
                        opt2val[desc.name] = val
                        newval = desc.convertor(val)
                        if desc.check: 
                            try:
                                desc.check(newval)
                            except:
                                raise InvalidParameters(desc.name, val)
                        opts[desc.argname] = newval
                    except Exception as e:
                        raise e

    def insert_default_opts(opts, opt_desc):
        for desc in opt_desc:
            if not desc.default is None and not desc.name in opts:
                opts[desc.argname] = desc.default

    def _options1(func):
        def _options2(cmd, args):
            opt2val = {}
            opts, tokens = get_opts(args, opt_desc, opt2val)
            check_undefault_opts(opts, opt_desc)
            insert_nokey_opts(tokens, opts, opt_desc, opt2val)
            insert_default_opts(opts, opt_desc)
            try:
                ret = func(cmd, **opts)
            except InvalidParameters as e:
                if not e.val:
                    raise InvalidParameters(e.name, opt2val[e.name])
                raise e

            if ret is None: return '', ''
            else: return ret
        return _options2
    return _options1

def errmatch(*match):
    def _errmatch1(func):
        def _errmatch2(self, *vargs, **kv):
            try:
                all_args = inspect.getcallargs(func, self, *vargs[:], **kv.copy())
                return func(self, *vargs, **kv)
            except CmdError as e:
                all_args['time'] = cur_time_str()
                for m in match:
                    if m[0] and e.detail.find(m[0]) <> -1:
                        raise CmdError(m[1] % all_args)
                raise e
        return _errmatch2
    return _errmatch1

class NTCli(Cmd):
    cmd_map = {}
    prompt = '#'
    def __init__(self):
        Cmd.__init__(self)

    @classmethod
    def register(cls, cmd_class):
        cmd = cmd_class()
        for attr in dir(cmd):
            m = getattr(cmd, attr)
            if callable(m) and attr.endswith('_cmd'):
                cls.__create_cmd(cls.cmd_map, cmd_class, attr, m)
    
    @classmethod
    def __create_cmd(cls, cmd_map, cmd_class, cmdname, method):
        keys = []
        if hasattr(cmd_class, 'cmd_map'):
            try:
                keys = getattr(cmd_class, 'cmd_map')[cmdname]
            except:
                pass
        keys = keys and keys or cmdname.replace('_cmd', '').split('_')
        cls.__register_cmd(cmd_map, keys, (cmd_class, cmdname))
        setattr(cls, 'complete_%s' % keys[0], NTCli.__complete)
        setattr(cls, 'do_%s' % keys[0], NTCli.__do)

    @classmethod
    def __register_cmd(cls, map, keys, cmd):
        if len(keys) == 1: map[keys[0]] = cmd
        else: cls.__register_cmd(map.setdefault(keys[0], {}), keys[1:], cmd)

    def __do(self, args):
        keys = self.lastcmd.split()
        cmd_class, cmdname = self.__get_method(keys)
        if cmd_class and len(keys) >= 2:
            try:
                cmd = cmd_class()
                odsptype, out = getattr(cmd, cmdname)(args.replace(keys[1], '', 1))
                print XMLFormat().format(odsptype, out)
            except Exception as e:
                if debug: print traceback.print_exc()
                else: print XMLFormat().error(e.message)

    def do_enable_debug(self, args):
        global debug
        debug = True

    def do_disable_debug(self, args):
        global debug
        debug = False

    def __complete(self, text, line, begidx, endidx):
        keys = line.split()
        map = NTCli.cmd_map[keys[0]]
        if len(keys) == 1: return map.keys()
        elif len(keys) == 2: 
            completion = [c for c in map if c.startswith(keys[1])]
            idx = keys[1].rfind('-')
            if completion and idx <> -1:
                completion = [completion[0].replace(keys[1][0:idx+1], '')]
            return completion

    def __get_method(self, keys):
        try:
            method = NTCli.cmd_map[keys[0]][keys[1]]
            return method
        except:
            return None, None

    def do_EOF(self, line):
        return True

    def emptyline(self):
        return False

    do_q = do_exit = do_EOF

def shortcut_opts(kv, **remap):
    opts = []
    for k in kv:
        if not k in remap and kv[k]:
            opts.append('-%s %s' % (k[0], kv[k]))
        elif kv[k]:
            opts.append('-%s %s' % (remap[k], kv[k]))
    return ' '.join(opts)


def rollback(rb_func, *params):
    def _rollback1(func):
        def _rollback2(self, *vargs, **kv):
            if not self.rb_enabled:
                return func(self, *vargs, **kv)

            try:
                rb_stack = getattr(self, 'rb_stack')
            except:
                rb_stack = []
                setattr(self, 'rb_stack', rb_stack)

            try:
                all_args = inspect.getcallargs(func, self, *vargs[:], **kv.copy())
                rb_args = dict([(p, all_args[p]) for p in params])
                if not 'self' in rb_args:
                    rb_args['self'] = all_args['self']
                rb_stack.append((rb_func, rb_args))
                return func(self, *vargs, **kv)
            except Exception as e:
                rb_stack.reverse()
                for rb, kv in rb_stack[1:]:
                    rb(**kv)
                raise e

        return _rollback2
    return _rollback1

class uuid_t(Structure):
    libu = CDLL('/odsp/lib/libuuid.so')
    _fields_ = [("id", c_ubyte * 16)]

    def __init__(self, s):
            Structure.__init__(self)
            uuid_t.libu.odsp_string_to_uuid(s, byref(self))

    def __str__(self):
            s = create_string_buffer(38)
            uuid_t.libu.odsp_uuid_to_string(byref(self), s)
            return s.raw[0:-1]

class SeriesFile:
    def __init__(self, name):
        self.name = name
        self.path = os.path.join('/odsp/config/local', 'series_%s.xml' % name)
        self.mtime = -1

    def content(self):
        mtime = os.path.getmtime(self.path)
        if self.mtime <> mtime:
            self.list = []
            self.mtime = mtime
            node = {}
            for event, elem in iterparse(self.path):
                if '%s_0x' % self.name in elem.tag:
                    node['uuid'] = elem.attrib['uuid']
                    self.list.append(node)
                    node = {}
                else:
                    node[elem.tag] = elem.attrib.copy()
                    if 'name' in elem.attrib:
                        node['name'] = elem.attrib['name']
                elem.clear()
        return self.list

    def getnode(self, name):
        for node in self.content():
            if node.get('name','') == name:
                return node
        raise NodeNotExisted(name)
    
    def getnode_by_uuid(self, uuid):
        for node in self.content():
            if node.get('uuid','') == uuid:
                return node
        raise NodeNotExisted(uuid)

class OdspOp:
    libha = CDLL('/odsp/lib/libha.so')
    libw = CDLL('/odsp/lib/libwebsvc.so')    
    libc = CDLL('libc.so.6')
    default_pool = 'Pool-monitoring'
    loc_cfg_path = os.path.join(odsp_path.config, 'local')
    lun_xml = os.path.join(loc_cfg_path, 'series_lun.xml')
    target_xml = os.path.join(loc_cfg_path, 'series_iscsi_target.xml')
    client_xml = os.path.join(loc_cfg_path, 'series_client.xml')
    initiator_xml = os.path.join(loc_cfg_path, 'series_iscsi_initiator.xml')

    series_pool = SeriesFile('pool')
    series_array = SeriesFile('array')
    series_lun = SeriesFile('lun')
    series_target = SeriesFile('iscsi_target')
    series_client = SeriesFile('client')
    series_initiator = SeriesFile('iscsi_initiator')

    def __init__(self, rb_enabled=True):
        self.rb_enabled = rb_enabled
        self.net = self.query_network()

    def exec_cli(self, cmd):
        cmd = 'echo %s | /odsp/bin/odsp-cli' % cmd
        out = os.popen(cmd).read()
        if debug: print cmd
        if debug: print out
        lines = out.splitlines()
        if lines[0].find('Command failed') <> -1:
            raise CmdError('Command failed.', out)
        return out

    def delete_raid(self, name):
        self.exec_cli('raid mgt delete -n %s' % name)

    @rollback(delete_raid, 'raid_name')
    def create_raid(self, raid_name, pool_name, data_disklist, level='RAID5', stripe_size='64KB', spare_disklist=''):
        opts = shortcut_opts(args(), raid_name='n', spare_disklist='D')
        self.exec_cli('raid mgt create %s -c 5' % opts)

    def delete_pool(self, name):
        self.exec_cli('pool mgt delete -n %s' % name)

    @rollback(delete_pool, 'name')
    def create_pool(self, name, type='t'):
        opts = shortcut_opts(args())
        self.exec_cli('pool mgt create %s' % opts)

    def query_raid(self, name):
        return self.exec_cli('raid mgt query -n %s' % name)

    def query_raid_list(self, pool_name):
        return self.exec_cli('raid mgt getlist -p %s' % pool_name)

    def query_network(self):
        buf = c_char_p()
        OdspOp.libw.websvc_devmgt_get_device_info(0, "interface", byref(buf))
        net = str(buf.value)
        OdspOp.libc.free(buf)
        net = json.loads(net)
        for name, eth in net.items():
            name = re.sub('eth', 'e', name)
            name = re.sub('bond', 'b', name)
            eth['name'] = name
        return net.values()

    def query_pool_list(self):
        return self.exec_cli('pool mgt getlist')
 
    def delete_lun(self,name):
        opts = shortcut_opts(args())
        return self.exec_cli('lun mgt delete %s'% opts)
    
    @rollback(delete_lun, 'name')
    def create_lun(self, name, size, raid_list):
        opts = shortcut_opts(args(), raid_list='R')
        return self.exec_cli('lun mgt create -o SP1 -p %s %s'% (OdspOp.default_pool, opts))
    
    def query_lun(self, name):
        lunnode = OdspOp.series_lun.getnode(name)
        raidlist = [v for k, v in lunnode['lun_info'].items() if 'raid_' in k]
        raidlist = [OdspOp.series_array.getnode_by_uuid(uuid) for uuid in raidlist]
        return {'name'      :name, 
                'capacity'  :int(lunnode['lun_info']['capacity']),
                'uuid'      :lunnode['uuid'], 
                'raidlist'  :raidlist}
    
    def query_lun_list(self, pool_name):
        return self.exec_cli('lun mgt getlist -p %s'% OdspOp.default_pool)

    def query_lun_mapping(self, name):
        def ipaddr_name(net, ip):
            for n in net:
                if n['ipaddr'] == ip:
                    return n['name']
            return ''
        uuid = self.query_lun(name)['uuid']
        targets = []
        lun = {'name': name, 'targets':targets}
        for node in OdspOp.series_target.content():
            for n, (dummy, lun_uuid) in enumerate(sorted(node['lun_related'].items())):
                if uuid == lun_uuid:
                    target = node['iscsi_target_info'].copy()
                    target['ipaddrs'] = node['spa_ports'].values()
                    target['id'] = n
                    target['initiator_num'] = 1
                    targets.append(target)
        
        for target in targets:
            for node in OdspOp.series_client.content():
                if target['uuid'] in node['iscsi_target_related'].values():
                    target['authority'] = node['client_info']['authority']
                    attr = node['iscsi_initiator_related'].copy()
                    del attr['iscsi_initiator_num']
                    target['initiator_uuid'] = attr.values()[0]

        for target in targets:
            init = OdspOp.series_initiator.getnode_by_uuid(target['initiator_uuid'])
            target['initiator_name'] = init['name']
        
        for target in targets:
            eths = []
            for ip in target['ipaddrs']:
                eths.append(ipaddr_name(self.net, ip))
            target['ports'] = ','.join(eths)

        if not targets:
            targets.append({'name':'', 'ports':'', 'id':'', 'authority':'not-mapped', 'initiator_name':'', 'initiator_num':'0'})
        return lun

    def query_lun_list_from_raid(self, raid_name):
        array_xml = parse('/odsp/config/local/series_array.xml')
        RAID_BASIC = array_xml.find('.//raid_basic[@raid_name="%s"]' % raid_name)
        raid_uuid = uuid_t(RAID_BASIC.get('raid_uuid'))
        lun_uuid = POINTER(uuid_t)()
        lun_num = c_int()
        OdspOp.libw.websvc_pool_query_lun_list_by_raid_uuid(byref(raid_uuid), byref(lun_uuid), byref(lun_num))

        lun_xml = parse('/odsp/config/local/series_lun.xml')
        lun_name = []
        for i in range(0, lun_num.value):
                LUN_INFO = lun_xml.find('.//lun_info[@uuid="%s"]' % lun_uuid[i])
                lun_name.append(LUN_INFO.get('name'))
        OdspOp.libc.free(lun_uuid)
        return lun_name

    def delete_client(self,name):
        return self.exec_cli('client mgt delete -n %s'%name)
        
    @rollback(delete_client, 'name')
    def create_client(self,name,access_mode):
        opts = shortcut_opts(args(),access_mode='m')
        return self.exec_cli('client mgt create %s'%opts)

    def delete_initiator(self,name,type='iSCSI'):
        opts = shortcut_opts(args())
        return self.exec_cli('client initiator delete %s'%opts)

    @rollback(delete_initiator, 'name')
    def create_initiator(self,name,initiator_type,description):
        opts = shortcut_opts(args(),initiator_type='t')
        return self.exec_cli('client initiator create %s'%opts)

    def query_initiator(self,name):
        initnode = OdspOp.series_initiator.getnode(name)
        init = {'name':name, 'desc':initnode['iscsi_initiator_info']['discription'], 'clients':[]}
        for node in OdspOp.series_client.content():
            if initnode['uuid'] in node['iscsi_initiator_related'].values():
                init['clients'].append(node['name'])

        return init

    def query_initiator_list(self):
        return [{'name':node['name'], 
                 'desc':node['iscsi_initiator_info']['discription']} 
                    for node in OdspOp.series_initiator.content()]
    
    def initiatot_modify(self,name,initiator_type,description):
        opts = shortcut_opts(args(),initiator_type='t')
        return self.exec_cli('client initiator modify %s'%opts)

    def client_addinitiator(self,client_name,initiator_type,initiator_name):
        opts = shortcut_opts(args(),initiator_type='t')
        return self.exec_cli('client mgt addinitiator %s'%opts)
    
    def delete_target(self, target_name, target_type='iSCSI'):
        opts = shortcut_opts(args(), target_name='n')
        return self.exec_cli('client target delete %s -f'%opts)
    
    @rollback(delete_target,'target_name','target_type')
    def create_target(self,client_name,target_name,sp1_port_list,target_type='iSCSI'):
        opts = shortcut_opts(args(),target_name='n',sp1_port_list='f')
        return self.exec_cli('client target create %s'%opts)


    
    def query_disk(self,disk):
        opts = shortcut_opts(args())
        return self.exec_cli('disk mgt query %s' % opts)

    def query_disk_list(self, dsu):
        return self.exec_cli('disk mgt getlist -d %s' % dsu)

    def query_dsu_list(self):
        return self.exec_cli('dsu mgt getlist')

    def modify_access_mode(self,name,access_mode):
        opts = shortcut_opts(args(),access_mode='m')
        return self.exec_cli('client mgt modify %s'%opts)
    
    def remove_lun_target(self,name,lun_list,type):
        opts = shortcut_opts(args(),access_mode='m')
        return self.exec_cli('client target removelun %s'%opts)
        
    @rollback(remove_lun_target, 'name','lun','type')
    def add_lun_target(self,type,name,lun):
        opts = shortcut_opts(args())
        return self.exec_cli('client target addlun -f %s'%opts)

    def modify_target_port(self,name,sp1_port_list,type='iSCSI'):
        opts = shortcut_opts(args(),sp1_port_list='f')
        return self.exec_cli('client target modify %s'%opts)

    def query_client_target(self,name,type='iSCSI'):
        opts = shortcut_opts(args())
        return self.exec_cli('client target query %s'%opts)

    def query_lun_belonged_raidlist(self, name):
        return self.exec_cli('lun mgt queryraidlist -n %s' % name)

    def query_target_list(self, client_name):
        client = OdspOp.series_client.getnode(client_name)
        return [{'name':node['name'],
                 'luns':[lun for id, lun in sorted(node['lun_related'].items())]}
                     for node in OdspOp.series_target.content()
                       if client['uuid'] == node['iscsi_target_info']['client_uuid']]

class Port:
    @options()
    def show_ports_cmd(self):
        write_log('----------------start show ports--------------')
        odsp_op = OdspOp()
        net = odsp_op.query_network()
        write_log('----------------finish show ports--------------')
        return 'net', [{'Port Name'    : n['name'],
                        'IP Version'   : 'IPv4',
                        'IPv4 Address' : n['ipaddr'],
                        'Is Linkup'    : n['status'].title()} for n in net if n['type'].lower() <> 'slave']

class Host:
    def convert_nickname(self,nickname):
        return '\\"%s\\"'%nickname

    def convert_id(self,id):
        return '\\"%s\\"'%id

    @options(make_opt('nickname',nokey=True),
             make_opt('id'))
    @errmatch(('Initiator name duplicated.', 'Bad parameter(s) were specified. - The host identifier or nickname is already in use, or the host identifier is invalid'))
    def create_host_cmd(self,id,nickname):
        odsp_op = OdspOp()
        if self.convert_id(id) == nickname: raise CmdError('name duplicate !')
        write_log('----------------start create host %s--------------'%id)
        existed = False
        write_log('start query initiator list')
        for init in odsp_op.query_initiator_list():
            if init['name'] == id: existed = True
        write_log('finish query initiator list')
        if existed:
            init = odsp_op.query_initiator(id)
            if init['desc'] == 'Discover automatically':
                write_log('start modify initiator')
                odsp_op.initiatot_modify(name=id,initiator_type='iSCSI',description=self.convert_nickname(nickname))
                write_log('finish modify initiator')
                write_log('start create client')
                odsp_op.create_client(name='client-'+id.split('.')[-1],access_mode='N')
                write_log('finish create client')
                write_log('start addinitiator to client')
                odsp_op.client_addinitiator(client_name='client-'+id.split('.')[-1], initiator_type='iSCSI', initiator_name=id)
                write_log('finish addinitiator to client')
            else:
                write_log('start create initiator')
                odsp_op.create_initiator(id, 'iSCSI', self.convert_nickname(nickname))
                write_log('finish create initiator')
                write_log('start addinitiator to client')
                odsp_op.create_client('client-'+id.split('.')[-1], 'N')
                write_log('finish addinitiator to client')
        else:
            write_log('start create initiator')
            odsp_op.create_initiator(id, 'iSCSI', self.convert_nickname(nickname))
            write_log('finish create initiator')
            write_log('start create client after create initiator')
            odsp_op.create_client('client-'+id.split('.')[-1], 'N')
            write_log('finish create client after create initiator')
            write_log('start addinitiator to client after create client')
            odsp_op.client_addinitiator('client-'+id.split('.')[-1], 'iSCSI', id)
            write_log('finish addinitiator to client after create client')
            write_log('------------finish create host %s--------------'%id)
    
    @options(make_opt('id',nokey=True))
    @errmatch(('The client is not existed.', 'The specified host was not found. (%(id)s) - The host was not found.'))
    def delete_host_cmd(self,id):
        odsp_op = OdspOp()
        client_name = 'client-'+id.split('.')[-1]
        odsp_op.delete_client(client_name)
        odsp_op.delete_initiator(id, 'iSCSI')

    def __mapped(self, op, host):
        init = op.query_initiator(host)
        if not init['clients']: return 'No'
        targets = op.query_target_list(init['clients'][0])
        for target in targets:
            if target['luns']: return 'Yes'
        return 'No'


    @options()
    def show_hosts_cmd(self):
        write_log('-----------start show hosts------------')
        odsp_op = OdspOp()
        hosts = odsp_op.query_initiator_list()
        hosts = [host for host in hosts if host['desc'].find('Discover automatically') == -1]
        hosts = [(host['name'], host['desc'], self.__mapped(odsp_op, host['name'])) for host in hosts]
        write_log('-----------finish show hosts------------')
        return 'show_hosts', [dict(zip(('Name', 'Description', 'Mapped'), host)) for host in hosts]
        

class Disk:
    SPECIAL_VAILD_NAME = ['all', 'free', '']
    def convert_location(loc):
        return loc.replace('.', ':').split(',') 

    def check_location(loc):
        for l in loc:
            m = re.search('^\d+:\d+:\d+:\d+$', l)
            if not m: raise CmdError('Unknown Disk Location[%s]' % l)

    def check_name(name):
        if not name in Disk.SPECIAL_VAILD_NAME:
            raise CmdError('Unknown Option[%s]' % name)

    def __get_all_disk_list(self, odsp_op, justfree=True):
        out = odsp_op.query_dsu_list()
        disk_list = '\n'.join([odsp_op.query_disk_list(dsu) for dsu in\
            re.findall('Name:\s+DSU-([^\n]+)', out, re.S)])
        if not justfree: return disk_list
        freedisk = '\n'.join([ 'Name:\s+[^\n]+', 
                               'Type:\s+[^\n]+', 
                               'Capacity:\s+[^\n]+', 
                               'Vendor:\s+[^\n]+', 
                               'RPMs:\s+[^\n]+', 
                               'Health Status:\s+Normal', 
                               'Disk Role:\s+Unused disk', 
                               'Owner\(Pool\):\s+[^\n]+', 
                               'Owner\(RAID\):\s+[^\n]+'])
        s = '\n\n'.join(re.findall('(%s)' % freedisk, disk_list, re.S))
        return re.sub('Disk Role', 'Role', s)

    def __get_raid_disk_list(self, odsp_op, raid_name):
        disk_list = re.findall('Disk-(\d+:\d+:\d+:\d+)', odsp_op.query_raid(raid_name))
        return '\n\n'.join([odsp_op.query_disk(disk) for disk in disk_list])

    def __get_disk(self, odsp_op, location):
        out = odsp_op.query_disk(location)
        fields = ["Name","Vendor","Owner\(RAID\)","Role","Type","Capacity","Health Status","Health Status"]
        disk = {}
        for f in fields:
            m = re.search('%s\s*:\s*([^\n]+)' % f, out)
            disk[f] = m.group(1)
        return disk

    def __get_disk_list(self, odsp_op, locations):
        return [self.__get_disk(odsp_op, loc) for loc in locations]

        
    @options(make_opt('name', nokey=True, default='', check=check_name),
             make_opt('disks', default=[], convertor=convert_location, check=check_location),
             make_opt('vdisk', default=''))
    def show_disks_cmd(self, name, disks, vdisk):
        write_log('-------------show disks----------')
        odsp_op = OdspOp()
        if vdisk: return 'disk', self.__get_raid_disk_list(odsp_op, vdisk)
        elif disks: return 'disk', self.__get_disk_list(odsp_op, disks)
        elif name in Disk.SPECIAL_VAILD_NAME: return 'disk', self.__get_all_disk_list(odsp_op, name == 'free')
        

class Vdisk:
    def mk_attr(**kv):
        return kv

    disk_cnt_limit = mk_attr(
            RAID0  = (2, 16),
            RAID1  = (2, 2),
            RAID5  = (3, 16),
            RAID10 = (4, 16))
    support_raid_lvl = 'RAID0|RAID1|RAID5|RAID10'.split('|')
    support_chunk_size = '16KB|32KB|64KB'.split('|')

    def convert_lvl(lvl):
        if len(lvl) > 6: raise CmdError()
        lvl = re.sub('(r)(\d+)', 'raid\\2', lvl).upper()
        return lvl

    def convert_chunk_size(size):
        return re.sub('k|K', 'KB', size)

    def convert_location(loc):
        return [l.replace('.', ':') for l in loc.split(',')]

    def check_location(loc):
        for l in loc:
            m = re.search('^\d+:\d+:\d+:\d+$', l)
            if not m: raise CmdError()

    @options(make_opt('name', nokey=True),
             make_opt('level', convertor=convert_lvl, check=EnumCheck(support_raid_lvl)),
             make_opt('disks', convertor=convert_location, check=check_location),
             make_opt('spare', default=[], convertor=convert_location, check=check_location),
             make_opt('chunk-size', default='', convertor=convert_chunk_size, check=EnumCheck(support_chunk_size)))
    @errmatch(('The RAID has been existed', 'A duplicate name was specified. (%(name)s) -  Failed to create the vdisk(%(time)s).'))
    def create_vdisk_cmd(self, name, level, disks, chunk_size, spare):
        limit = Vdisk.disk_cnt_limit[level]
        if not limit[0] <= len(disks) <= limit[1]:
            raise InvalidParameters('disks')

        odsp_op = OdspOp()
        odsp_op.create_raid(name, OdspOp.default_pool, ','.join(disks), level, chunk_size, ','.join(spare))

    @options(make_opt('name', nokey=True))
    @errmatch(('the raid is not existed.', 'The vdisk was not found on this system. (%(name)s) - %(name)s NOT deleted.(%(time)s)'))
    def delete_vdisks_cmd(self, name):
        odsp_op = OdspOp()
        odsp_op.delete_raid(name)

    @options(make_opt('name', nokey=True, default=''))
    def show_vdisks_cmd(self, name):
        write_log("------------start show  vdisks-----------")
        odsp_op = OdspOp()
        if name: 
            write_log("----------finish show vdisk with raid--------------") 
            return 'raid', odsp_op.query_raid(name)
        else: 
            write_log("-------finish show vdisk with nothing") 
            return 'raid', odsp_op.query_raid_list(OdspOp.default_pool)

class Volume:
    cmd_map = {'show_volume_maps_cmd':['show', 'volume-maps']}
    support_eth = 'e0|e1|e2|e3|e4|b1|b2|b3|b4'.split('|')

    def convert_GB(size):
        try:
            return Unit(size,'GB').GB[:-2]
        except:
            raise InvalidParameters('size','%s'%size)

    def check_vdisk_num(vdisk):
        if len(vdisk.split(',')) > 1: raise CmdError('Only support one vdisk')

    def check_port_num_name(ports):
        op = OdspOp()
        enum_check = EnumCheck(Volume.support_eth)
        net = [n['name'] for n in op.query_network()]
        for port in ports.split(','):
            enum_check(port)
            if port not in net: 
                raise InvalidParameters('ports', '%s' % ports)
        if len(ports.split(',')) > 4 : raise CmdError("Don't support more than four port!")

    def __get_lun(self, odsp_op, name):
        lun = odsp_op.query_lun(name)
        return {'Name'      : lun['name'],
                'Total Size': Unit('%sKB' % (lun['capacity'] / 2)).GB,
                'RAID Name' : ','.join(lun['raidlist']),
                'UUID'      : lun['uuid']}

    def __get_all_lun_name(self, odsp_op):
        out = odsp_op.query_lun_list(OdspOp.default_pool)
        return re.findall('Name\s*:\s*([^\n]+)', out)

    def __target_name(self, op, host, volume):
        return 'iqn.2010-05.com.ms:%s.%s' % (op.query_lun(volume)['uuid'], host.split('.')[-1])

    @options(make_opt('name', nokey=True),
             make_opt('vdisk', check=check_vdisk_num),
             make_opt('size', convertor=convert_GB))
    @errmatch(('LUN name duplicated.', 'A duplicate name was specified. (%(name)s) -  Failed to create the volume.(%(time)s).'))
    def create_volume_cmd(self,vdisk,size,name):
        write_log("------------start create lun-----------")
        odsp_op = OdspOp()
        odsp_op.create_lun(name, size, vdisk)
        write_log("------------finish create lun-----------")
        return 'create_volume', [{'UUID':odsp_op.query_lun(name)['uuid']}]

    def _name_to_list(self, name):
        return name and name.split(',') or []

    @options(make_opt('name', nokey=True))
    @errmatch(('LUN don\'t exist.', 'The volume was not found on this system. (%(name)s) - %(name)s was NOT deleted. (%(time)s)'))
    def delete_volumes_cmd(self,name):
        write_log("------------start delete volumes-----------")
        odsp_op = OdspOp()
        series_lun = SeriesFile('lun')
        lun_list = []
        name = self._name_to_list(name)
        try:
            for lun_name_1 in name:
                lun_list.append(series_lun.getnode(lun_name_1)['name'])
            for lun_name in lun_list:
                if name.count(lun_name) >= 2: raise CmdError('paramater is duplicate!')

            for lun_name in name:
                if lun_name in lun_list:
                    mapping = odsp_op.query_lun_mapping(lun_name)
                    for target in mapping['targets']:
                        if target['name']:
                            odsp_op.delete_target(target['name'],'iSCSI')
                odsp_op.delete_lun(lun_name)
                write_log("------------finish delete volumes %s-----------"%lun_name)
        except NodeNotExisted:
            raise CmdError("Command failed", "LUN don't exist.")
        except Exception as e:
            raise e
            

    @options(make_opt('vdisk',default=''),
             make_opt('volumes', nokey=True, default=''))
    def show_volumes_cmd(self,vdisk,volumes):
        write_log("---------show volumes---------------")
        odsp_op = OdspOp()
        volumes = self._name_to_list(volumes)
        out = ''
        try:
            if vdisk: out = [self.__get_lun(odsp_op, lun) for lun in odsp_op.query_lun_list_from_raid(vdisk)]
            elif volumes: out = [self.__get_lun(odsp_op, lun) for lun in volumes]
            else: out = [self.__get_lun(odsp_op, lun) for lun in self.__get_all_lun_name(odsp_op)]
        except:
            write_log("---------finish show volumes---------------")
            raise CmdError("Command failed.")
        else:
            write_log("---------finish show volumes---------------")
            return 'lun', out

    @options(make_opt('access'),
             make_opt('lun'),
             make_opt('ports',check=check_port_num_name),
             make_opt('host'),
             make_opt('volume',nokey=True))
    def map_volume_cmd(self,access,lun,ports,host,volume):
        odsp_op = OdspOp()
        write_log("---------start map %s to %s-------------"%(volume,host))
        write_log("start query network")
        net = odsp_op.query_network()
        ipaddrs = [n['ipaddr'] for port in ports.split(',') for n in net if n['name'] == port]
        write_log("finish query network")
        write_log("start lun mgt getlist")
        lun_list = re.findall('Name\s+:\s+(\S+)',odsp_op.query_lun_list(odsp_op.default_pool))
        write_log("finish lun mgt getlist")
        if volume in lun_list:
            write_log("start get target_name")
            target_name = self.__target_name(odsp_op, host, volume)
            write_log("finish get target_name")
        else: raise CmdError('Command failed.')
        write_log("start client_name")
        client_name = 'client-'+host.split('.')[-1]
        write_log("finish client_name")
        write_log("start create_target")
        odsp_op.create_target(client_name, target_name, ','.join(ipaddrs), 'iSCSI')
        write_log("finish create_target")
        write_log("start add lun to target")
        odsp_op.add_lun_target('iSCSI', target_name, volume)
        write_log("finish add lun to target")
        write_log("---------finish map %s to %s-------------"%(volume,host))
        return 'map_volume', '\n'.join(['ID:0', 'Name:%s' % target_name])
        
    @options(make_opt('host'),
             make_opt('volume',nokey=True))
    def unmap_volume_cmd(self,host,volume):
        odsp_op = OdspOp()
        lun_list = re.findall('Name\s+:\s+(\S+)',odsp_op.query_lun_list(odsp_op.default_pool))
        if volume in lun_list:
            odsp_op.delete_target(self.__target_name(odsp_op, host, volume), target_type='iSCSI')
        else:raise CmdError('Command failed.')

    @options(make_opt('volume',nokey=True,default=''))
    def show_volume_maps_cmd(self,volume):
        write_log("------------start show  volumes-maps----------")

        odsp_op = OdspOp()
        if volume: return 'volume-view', [odsp_op.query_lun_mapping(volume)]
        else: return 'volume-view', [odsp_op.query_lun_mapping(v) for v in self.__get_all_lun_name(odsp_op)]


def setup_env():
    op = OdspOp(False)
    out = op.query_pool_list()
    pool_list = re.findall('Name:\s+([^\n]+).+?Type:\s+([^\n]+)', out, re.S)
    if (OdspOp.default_pool, 'Traditional') in pool_list:
        return

    for n, t in pool_list:
        if t == 'Traditional':
            OdspOp.default_pool = n
            return

    try:
        op.create_pool(OdspOp.default_pool)
    except: pass

NTCli.register(Port)
NTCli.register(Disk)
NTCli.register(Vdisk)
NTCli.register(Volume)
NTCli.register(Host)


if __name__ == '__main__':
    try:
        write_log('===== ntcli run =====')
        setup_env()
        cli = NTCli()
        cli.cmdloop()
    finally:
        write_log('===== ntcli exit =====')
        #log.close()

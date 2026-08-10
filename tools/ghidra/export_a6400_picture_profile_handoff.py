# @category Sony.PictureProfile
# @runtime PyGhidra
"""Read-only, metadata-only α6400 Picture Profile hand-off exporter."""
from __future__ import annotations
import hashlib, json, os, sys, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from pmca.analysis.picture_profile_handoff import *

def _constructor_refs(): return [{"slot":s,"owner":"0x8351f8","site":site,"target":n,"reference_type":"PARAM"} for s,_p,n,a,b in PROPERTY_LISTS for site in (a,b)]
def _objects(): return [{"slot":s,"address":p,"symbol":"cmnViewSettingPropertyListPictureProfile"+s,"size":120} for s,p,*_ in PROPERTY_LISTS]
def _edges(): return [{"id":i,"caller":c,"site":site,"target":t} for i,c,site,t in ROOT_EDGES]

def build_raw_export(a, expected_program, expected_sha256):
 if expected_program!="CautionConfig.so" or expected_sha256!=CAUTION_CONFIG_SHA256: raise RuntimeError("expected source identity is invalid")
 if a.program_name()!="CautionConfig.so" or a.program_sha256().lower()!=CAUTION_CONFIG_SHA256 or a.program_headless_read_only() is not True or a.program_noanalysis() is not True or a.program_is_changed() is not False: raise RuntimeError("source mode/identity/dirty state is invalid")
 if a.construction_owner()!=CONSTRUCTION_OWNER or a.constructor_parameter_references()!=_constructor_refs() or a.property_lists()!=_objects() or a.root_edges()!=_edges(): raise RuntimeError("pinned metadata was not verified")
 r=a.resource_identity(); scan=a.uxc_scan()
 if r!={"path":"share/app/viewPictureProfile.uxc","size":PICTURE_PROFILE_UXC_SIZE,"sha256":PICTURE_PROFILE_UXC_SHA256} or scan!={"name_needles":list(UXC_NAME_NEEDLES),"name_hit_count":0}: raise RuntimeError("resource identity/scan is invalid")
 refs=a.property_list_references()
 document={"program":"CautionConfig.so","sha256":CAUTION_CONFIG_SHA256,"file_size":CAUTION_CONFIG_SIZE,"analysis_mode":{"read_only":True,"noanalysis":True},"program_changed":False,"construction_owner":CONSTRUCTION_OWNER,"constructor_parameter_references":_constructor_refs(),"property_lists":_objects(),"root_edges":_edges(),"property_list_references":refs,"resource":r,"uxc_scan":scan,"resource_references":[],"state_paths":[],"persistence_paths":[],"truncated":False}
 normalize_picture_profile_handoff_export(document)
 return document

def write_json_atomic(output, document, approved_root):
 out=Path(output); root=Path(approved_root).resolve(strict=True)
 if out.name!="raw-picture-profile-handoff.json" or out.parent.resolve(strict=True)!=root or (out.exists() and (out.is_symlink() or not out.is_file())): raise RuntimeError("output containment is invalid")
 fd,tmp=tempfile.mkstemp(dir=str(root),prefix=".pp-handoff-",suffix=".tmp")
 try:
  with os.fdopen(fd,"wb") as f: f.write(json.dumps(document,sort_keys=True,separators=(",",":")).encode()+b"\n"); f.flush(); os.fsync(f.fileno())
  os.replace(tmp,out)
 except BaseException:
  try: os.unlink(tmp)
  except FileNotFoundError: pass
  raise

class GhidraProgramAdapter:
 def __init__(self,p): self.p=p; self.fm=p.getFunctionManager(); self.rm=p.getReferenceManager(); self.listing=p.getListing(); self.sym=p.getSymbolTable(); self.space=p.getAddressFactory().getDefaultAddressSpace()
 def ad(self,v): return self.space.getAddress(v.replace("0x",""))
 def program_name(self): return str(self.p.getName())
 def program_sha256(self): return str(self.p.getExecutableSHA256())
 def program_is_changed(self): return bool(self.p.isChanged())
 def _opt(self,n):
  from ghidra.app.util.headless import HeadlessAnalyzer
  o=HeadlessAnalyzer.getInstance().getOptions(); f=o.getClass().getDeclaredField(n); f.setAccessible(True); return bool(f.getBoolean(o))
 def program_headless_read_only(self): return self._opt("readOnly")
 def program_noanalysis(self): return not self._opt("analyze")
 def construction_owner(self):
  f=self.fm.getFunctionAt(self.ad("0x8351f8"))
  if f is None or int(f.getEntryPoint().getOffset())!=0x8351f8 or str(f.getName())!="_INIT_3": raise RuntimeError("construction owner not resolved")
  return CONSTRUCTION_OWNER
 def constructor_parameter_references(self):
  found=[]
  expected=_constructor_refs()
  for slot,_property,target,_first,_second in PROPERTY_LISTS:
   for ref in self.rm.getReferencesTo(self.ad(target)):
    owner=self.fm.getFunctionContaining(ref.getFromAddress())
    if owner and int(owner.getEntryPoint().getOffset())==0x8351f8 and str(ref.getReferenceType())=="PARAM": found.append({"slot":slot,"owner":"0x8351f8","site":"0x%x"%int(ref.getFromAddress().getOffset()),"target":target,"reference_type":"PARAM"})
  if sorted(found,key=lambda x:(x["slot"],x["site"])) != sorted(expected,key=lambda x:(x["slot"],x["site"])): raise RuntimeError("constructor PARAM references are incomplete or contain extras")
  return expected
 def _source_binary(self): return ROOT/".artifacts"/"decrypted"/"a6400-tw-v2.00"/"ma1co"/"firmware.tar_unpacked"/"0700_part_image"/"dev"/"nflasha15_unpacked"/"lib"/"CautionConfig.so"
 def _elf_object_symbols(self):
  import struct
  b=self._source_binary().read_bytes()
  if hashlib.sha256(b).hexdigest()!=CAUTION_CONFIG_SHA256: raise RuntimeError("ELF source digest differs")
  shoff=struct.unpack_from("<I",b,32)[0]; entsize=struct.unpack_from("<H",b,46)[0]; count=struct.unpack_from("<H",b,48)[0]
  out={}
  for i in range(count):
   off=shoff+i*entsize; typ=struct.unpack_from("<I",b,off+4)[0]
   if typ!=11: continue
   data_off,data_size=struct.unpack_from("<II",b,off+16); link=struct.unpack_from("<I",b,off+24)[0]; entry=struct.unpack_from("<I",b,off+36)[0]
   strhdr=shoff+link*entsize; str_off,str_size=struct.unpack_from("<II",b,strhdr+16); strings=b[str_off:str_off+str_size]
   for pos in range(data_off,data_off+data_size,entry):
    name,value,size,info=struct.unpack_from("<IIIB",b,pos)
    end=strings.find(b"\0",name); label=strings[name:end].decode("ascii","ignore")
    if label: out[label]=(value,size,info&15)
  return out
 def property_lists(self):
  elf=self._elf_object_symbols()
  for want in _objects():
   ad=self.ad("0x%x"%(int(want["address"],16)+0x10000)); names=[str(x.getName()) for x in self.sym.getSymbols(ad)]
   expected=(int(want["address"],16),120,1)
   if want["symbol"] not in names or elf.get(want["symbol"])!=expected: raise RuntimeError("property-list OBJECT symbol/size not verified")
  return _objects()
 def root_edges(self):
  found=[]
  for want in _edges():
   fun=self.fm.getFunctionAt(self.ad(want["caller"]))
   if fun is None: raise RuntimeError("root function not resolved")
   hit=False
   for ins in self.listing.getInstructions(fun.getBody(),True):
    if int(ins.getAddress().getOffset())!=int(want["site"],16): continue
    for flow in ins.getFlows():
     if int(flow.getOffset())==int(want["target"],16): hit=True
   if not hit: raise RuntimeError("exact root call edge not verified")
   found.append(want)
  return found
 def property_list_references(self):
  out=[]
  for obj in _objects():
   ad=self.ad("0x%x"%(int(obj["address"],16)+0x10000))
   for direction, refs in (("to",self.rm.getReferencesTo(ad)),("from",self.rm.getReferencesFrom(ad))):
    for ref in refs:
     src=ref.getFromAddress(); dst=ref.getToAddress(); owner=self.fm.getFunctionContaining(src)
     source="0x%x"%int(src.getOffset()); destination="0x%x"%int(dst.getOffset())
     out.append({"source":source,"destination":destination,"property_slot":obj["slot"],"property_address":"0x%x"%(int(obj["address"],16)+0x10000),"direction":"to-property" if direction=="to" else "from-property","reference_type":str(ref.getReferenceType())})
     if len(out)>1024: raise RuntimeError("property-list reference bound exceeded")
  return sorted(out,key=lambda x:(x["property_address"],x["direction"],x["source"],x["destination"],x["reference_type"]))
 def resource_identity(self):
  p=ROOT/".artifacts"/"decrypted"/"a6400-tw-v2.00"/"ma1co"/"firmware.tar_unpacked"/"0700_part_image"/"dev"/"nflasha15_unpacked"/"share"/"app"/"viewPictureProfile.uxc"
  if not p.is_file() or p.stat().st_size!=PICTURE_PROFILE_UXC_SIZE or hashlib.sha256(p.read_bytes()).hexdigest()!=PICTURE_PROFILE_UXC_SHA256: raise RuntimeError("resource identity unavailable")
  return {"path":"share/app/viewPictureProfile.uxc","size":PICTURE_PROFILE_UXC_SIZE,"sha256":PICTURE_PROFILE_UXC_SHA256}
 def uxc_scan(self):
  p=ROOT/".artifacts"/"decrypted"/"a6400-tw-v2.00"/"ma1co"/"firmware.tar_unpacked"/"0700_part_image"/"dev"/"nflasha15_unpacked"/"share"/"app"/"viewPictureProfile.uxc"; b=p.read_bytes()
  return {"name_needles":list(UXC_NAME_NEEDLES),"name_hit_count":sum(b.count(x.encode()) for x in UXC_NAME_NEEDLES)}

def _run():
 args=list(getScriptArgs())
 if len(args)!=3: raise RuntimeError("usage: <output> CautionConfig.so <sha256>")
 out,program,digest=args; doc=build_raw_export(GhidraProgramAdapter(currentProgram),program,digest); root=ROOT/".artifacts"/"picture-profile-handoff-trace"/"a6400-v2.00"; write_json_atomic(out,doc,root); print("PICTURE_PROFILE_HANDOFF_EXPORT|constructor_refs=18|property_lists=9|property_refs=%d|uxc_hits=0|state=0|persistence=0"%len(doc["property_list_references"]))
try: currentProgram; getScriptArgs
except NameError: pass
else: _run()

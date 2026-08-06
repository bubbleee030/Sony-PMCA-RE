"""Fail-closed α6400 Picture Profile construction-to-state metadata contract."""
from __future__ import annotations
import copy, hashlib, json, re

CAUTION_CONFIG_SHA256 = "bfd1bd7bad0ab3478b894da5dbb51c15464b1bedc4201240ccb61cd743150ef7"
CAUTION_CONFIG_SIZE = 12070800
PICTURE_PROFILE_UXC_SHA256 = "66a66c2b800331e8a76246321888a3264f0249b48aa51df86c8686d4076f2d71"
PICTURE_PROFILE_UXC_SIZE = 1292
CONSTRUCTION_OWNER = {"address":"0x8351f8","symbol":"_INIT_3"}
PROPERTY_LISTS = (
 ("PP1","0x9816b0","0xbac208","0x85285e","0x85286a"),("PP2","0x981728","0xc5ee70","0x852880","0x85288c"),("PP3","0x9817a0","0xc5ee98","0x8528a2","0x8528ae"),("PP4","0x981818","0xc5eec0","0x8528c4","0x8528d0"),("PP5","0x981890","0xc5eee8","0x8528e6","0x8528f2"),("PP6","0x981908","0xbac240","0x852908","0x852914"),("PP7","0x981980","0xc5ef38","0x85292a","0x852936"),("PP8","0x9df610","0xc5ef60","0x85294c","0x852958"),("PP9","0x981a40","0xc5ef88","0x85296e","0x85297a"))
ROOT_EDGES = (
 ("picture-profile-selector","0x7ebc04","0x7ebc1c","0x7c81a0"),("picture-profile-clone","0x7ebbe0","0x7ebbe8","0x7c7528"),("picture-profile-clone","0x7ebbe0","0x7ebbf0","0x7c3540"),("picture-profile-copy","0x7eb824","0x7eb83c","0x7c81a0"),("picture-profile-gamma","0x7eb6bc","0x7eb6d4","0x7c81a0"),("picture-profile-color-mode","0x7edf5c","0x7edf74","0x7c81a0"))
UXC_NAME_NEEDLES = ("CmnViewSettingNodePictureProfile","CmnViewSettingNodePictureProfileCopyPage1","cmnViewSettingPropertyListPictureProfilePP1","cmnViewSettingPropertyListPictureProfilePP2","cmnViewSettingPropertyListPictureProfilePP3","cmnViewSettingPropertyListPictureProfilePP4","cmnViewSettingPropertyListPictureProfilePP5","cmnViewSettingPropertyListPictureProfilePP6","cmnViewSettingPropertyListPictureProfilePP7","cmnViewSettingPropertyListPictureProfilePP8","cmnViewSettingPropertyListPictureProfilePP9")
FALSE_CLAIMS = {"reusable_target_interface_primitives":False,"reusable_target_state_primitives":False,"persistence_found":False,"base_look_processing":False,"live_view_binding":False,"still_jpeg_binding":False,"movie_binding":False,"first_class_creative_look":False}
CONCLUSION = "The exact PP1-PP9 constructor parameter wiring, property-list object references, root call edges, and metadata-only UXC scan are established. No typed UXC-to-handler, selected-slot/clone/property read/setter, configuration save-plus-matching-load, processing, or output path is established."
_HEX=re.compile(r"0x[0-9a-f]+")
class PictureProfileHandoffError(ValueError): pass
def _exact(v, fields, label):
 if not isinstance(v,dict) or set(v)!=set(fields): raise PictureProfileHandoffError(label+" has invalid fields")
 return v
def _hex(v,label):
 if not isinstance(v,str) or not _HEX.fullmatch(v): raise PictureProfileHandoffError(label+" is invalid")
 return v
def _digest(v): return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def _constructor_refs(): return [{"slot":s,"owner":"0x8351f8","site":site,"target":node,"reference_type":"PARAM"} for s,_p,node,a,b in PROPERTY_LISTS for site in (a,b)]
def _objects(): return [{"slot":s,"address":p,"symbol":"cmnViewSettingPropertyListPictureProfile"+s,"size":120} for s,p,*_ in PROPERTY_LISTS]
def _edges(): return [{"id":i,"caller":c,"site":site,"target":t} for i,c,site,t in ROOT_EDGES]
def _forbid(v):
 if isinstance(v,dict):
  for k,x in v.items():
   if any(q in str(k).lower() for q in ("raw","byte","disassembly","key","device","write")): raise PictureProfileHandoffError("forbidden raw or device material")
   _forbid(x)
 elif isinstance(v,list):
  for x in v:_forbid(x)

def normalize_picture_profile_handoff_export(d):
 _forbid(d)
 fields={"program","sha256","file_size","analysis_mode","program_changed","construction_owner","constructor_parameter_references","property_lists","root_edges","property_list_references","resource","uxc_scan","resource_references","state_paths","persistence_paths","truncated"}
 _exact(d,fields,"raw export")
 if (d["program"],d["sha256"],d["file_size"]) != ("CautionConfig.so",CAUTION_CONFIG_SHA256,CAUTION_CONFIG_SIZE): raise PictureProfileHandoffError("source identity is not pinned")
 if d["analysis_mode"]!={"read_only":True,"noanalysis":True} or d["program_changed"] is not False or d["truncated"] is not False: raise PictureProfileHandoffError("source mode or dirty state is unsafe")
 if d["construction_owner"]!=CONSTRUCTION_OWNER or d["constructor_parameter_references"]!=_constructor_refs() or d["property_lists"]!=_objects() or d["root_edges"]!=_edges(): raise PictureProfileHandoffError("pinned construction/property/root evidence differs")
 _exact(d["resource"],{"path","size","sha256"},"resource")
 if d["resource"]!={"path":"share/app/viewPictureProfile.uxc","size":PICTURE_PROFILE_UXC_SIZE,"sha256":PICTURE_PROFILE_UXC_SHA256}: raise PictureProfileHandoffError("resource identity differs")
 _exact(d["uxc_scan"],{"name_needles","name_hit_count"},"uxc scan")
 if d["uxc_scan"]!={"name_needles":list(UXC_NAME_NEEDLES),"name_hit_count":0}: raise PictureProfileHandoffError("UXC scan is not exact zero-hit evidence")
 if any(d[x] for x in ("resource_references","state_paths","persistence_paths")): raise PictureProfileHandoffError("unverified paths cannot be supplied")
 refs=d["property_list_references"]
 if not isinstance(refs,list) or len(refs)>1024: raise PictureProfileHandoffError("property references exceed bound")
 objects={"0x%x"%(int(x["address"],16)+0x10000):x["slot"] for x in _objects()}; seen=set(); out=[]
 for r in refs:
  _exact(r,{"source","destination","property_slot","property_address","direction","reference_type"},"property reference")
  for k in ("source","destination","property_address"): _hex(r[k],"property reference "+k)
  if r["property_address"] not in objects or r["property_slot"]!=objects[r["property_address"]] or r["direction"] not in {"to-property","from-property"} or not isinstance(r["reference_type"],str) or not r["reference_type"]: raise PictureProfileHandoffError("property reference is invalid")
  if (r["direction"]=="to-property" and r["destination"]!=r["property_address"]) or (r["direction"]=="from-property" and r["source"]!=r["property_address"]): raise PictureProfileHandoffError("property reference direction is inconsistent")
  key=tuple(r[field] for field in ("source","destination","property_slot","property_address","direction","reference_type"))
  if key in seen: raise PictureProfileHandoffError("duplicate property reference")
  seen.add(key); out.append(copy.deepcopy(r))
 return {"artifact_sha256":_digest(d),"constructor_parameter_reference_count":18,"property_list_count":9,"property_list_reference_count":len(out),"claims":copy.deepcopy(FALSE_CLAIMS),"readiness":"CONSTRUCTION_WIRING_ONLY"}
def summarize_picture_profile_handoff(d): return normalize_picture_profile_handoff_export(d)
def validate_picture_profile_handoff_report(d):
 _exact(d,{"schema_version","analysis_scope","camera_policy","camera_executed","installable","camera_test_eligible","summary","claims","readiness","conclusion"},"report")
 if type(d["schema_version"]) is not int or d["schema_version"]!=1 or d["analysis_scope"]!="offline-static-picture-profile-construction-to-state-handoff" or d["camera_policy"]!="physically-disconnected" or any(d[x] is not False for x in ("camera_executed","installable","camera_test_eligible")): raise PictureProfileHandoffError("report scope/policy is unsafe")
 _exact(d["summary"],{"artifact_sha256","constructor_parameter_reference_count","property_list_count","property_list_reference_count"},"report summary")
 if d["summary"]!={"artifact_sha256":REPORT_ARTIFACT_SHA256,"constructor_parameter_reference_count":18,"property_list_count":9,"property_list_reference_count":REPORT_PROPERTY_REFERENCE_COUNT}: raise PictureProfileHandoffError("report digest or counts are forged")
 if d["claims"]!=FALSE_CLAIMS or d["readiness"]!="CONSTRUCTION_WIRING_ONLY" or d["conclusion"]!=CONCLUSION: raise PictureProfileHandoffError("report promotes unestablished support")
 return copy.deepcopy(d)
REPORT_ARTIFACT_SHA256 = "c1c792b2aa28bbae168209329df4c0ce46dc5834f0d024f8d21cebb364aa74ff"
REPORT_PROPERTY_REFERENCE_COUNT = 27

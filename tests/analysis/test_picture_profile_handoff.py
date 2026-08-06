"""Strict tests for the non-promotable Picture Profile hand-off export."""
from __future__ import annotations
import copy, importlib.util, json, tempfile, unittest
from pathlib import Path
from pmca.analysis.picture_profile_handoff import *
ROOT=Path(__file__).resolve().parents[2]; EP=ROOT/"tools/ghidra/export_a6400_picture_profile_handoff.py"; RP=ROOT/"analysis/a6400-picture-profile-handoff.json"
def ex():
 s=importlib.util.spec_from_file_location("pph",EP); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
def raw():
 return {"program":"CautionConfig.so","sha256":CAUTION_CONFIG_SHA256,"file_size":CAUTION_CONFIG_SIZE,"analysis_mode":{"read_only":True,"noanalysis":True},"program_changed":False,"construction_owner":CONSTRUCTION_OWNER,"constructor_parameter_references":[{"slot":s,"owner":"0x8351f8","site":site,"target":n,"reference_type":"PARAM"} for s,_p,n,a,b in PROPERTY_LISTS for site in(a,b)],"property_lists":[{"slot":s,"address":p,"symbol":"cmnViewSettingPropertyListPictureProfile"+s,"size":120} for s,p,*_ in PROPERTY_LISTS],"root_edges":[{"id":i,"caller":c,"site":site,"target":t} for i,c,site,t in ROOT_EDGES],"property_list_references":[],"resource":{"path":"share/app/viewPictureProfile.uxc","size":1292,"sha256":PICTURE_PROFILE_UXC_SHA256},"uxc_scan":{"name_needles":list(UXC_NAME_NEEDLES),"name_hit_count":0},"resource_references":[],"state_paths":[],"persistence_paths":[],"truncated":False}
class Tests(unittest.TestCase):
 def test_exact_evidence_is_fail_closed(self):
  x=summarize_picture_profile_handoff(raw()); self.assertEqual((x["constructor_parameter_reference_count"],x["property_list_count"],x["property_list_reference_count"]),(18,9,0)); self.assertEqual(x["claims"],FALSE_CLAIMS); self.assertEqual(x["readiness"],"CONSTRUCTION_WIRING_ONLY")
 def test_source_mode_dirty_property_root_resource_and_output_tamper_rejected(self):
  for mutate in (lambda x:x.update(program="bad"),lambda x:x["analysis_mode"].update(noanalysis=False),lambda x:x.update(program_changed=True),lambda x:x["property_lists"][0].update(size=119),lambda x:x["root_edges"][0].update(target="0x0"),lambda x:x["resource"].update(sha256="0"*64),lambda x:x["uxc_scan"].update(name_hit_count=1),lambda x:x["property_list_references"].append({"source":"0x1","destination":"0x2","property_slot":"PP1","property_address":"0x0","direction":"to-property","reference_type":"DATA"})):
   x=raw(); mutate(x)
   with self.subTest(mutate=mutate),self.assertRaises(PictureProfileHandoffError): normalize_picture_profile_handoff_export(x)
 def test_paths_cannot_be_injected_to_promote_claims(self):
  for field in ("resource_references","state_paths","persistence_paths"):
   x=raw(); x[field]=[{"arbitrary":"text"}]
   with self.subTest(field=field),self.assertRaises(PictureProfileHandoffError): summarize_picture_profile_handoff(x)
 def test_duplicate_reference_is_rejected_independent_of_key_order(self):
  record={"source":"0x1","destination":"0x9916b0","property_slot":"PP1","property_address":"0x9916b0","direction":"to-property","reference_type":"DATA"}
  x=raw(); x["property_list_references"]=[record,dict(reversed(list(record.items())))]
  with self.assertRaises(PictureProfileHandoffError): normalize_picture_profile_handoff_export(x)
 def test_report_is_exact_and_rejects_forged_digest_claim_policy_or_conclusion(self):
  r=json.loads(RP.read_text())
  self.assertEqual(validate_picture_profile_handoff_report(r),r)
  for mutate in (lambda x:x["summary"].update(artifact_sha256="0"*64),lambda x:x["claims"].update(reusable_target_state_primitives=True),lambda x:x.update(camera_policy="unknown"),lambda x:x.update(conclusion="forged")):
   x=copy.deepcopy(r); mutate(x)
   with self.subTest(mutate=mutate),self.assertRaises(PictureProfileHandoffError): validate_picture_profile_handoff_report(x)
class ExporterTests(unittest.TestCase):
 class A:
  def program_name(s):return"CautionConfig.so"
  def program_sha256(s):return CAUTION_CONFIG_SHA256
  def program_headless_read_only(s):return True
  def program_noanalysis(s):return True
  def program_is_changed(s):return False
  def construction_owner(s):return CONSTRUCTION_OWNER
  def constructor_parameter_references(s):return raw()["constructor_parameter_references"]
  def property_lists(s):return raw()["property_lists"]
  def root_edges(s):return raw()["root_edges"]
  def property_list_references(s):return []
  def resource_identity(s):return raw()["resource"]
  def uxc_scan(s):return raw()["uxc_scan"]
 def test_mode_and_metadata_are_required(self):
  m=ex(); a=self.A(); self.assertEqual(m.build_raw_export(a,"CautionConfig.so",CAUTION_CONFIG_SHA256)["root_edges"],raw()["root_edges"])
  for name,value in (("program_headless_read_only",False),("program_noanalysis",False),("program_is_changed",True),("root_edges",[])):
   a=self.A(); setattr(a,name,lambda value=value:value)
   with self.subTest(name=name),self.assertRaises(RuntimeError):m.build_raw_export(a,"CautionConfig.so",CAUTION_CONFIG_SHA256)
 def test_malformed_adapter_reference_is_rejected_before_export(self):
  m=ex(); a=self.A(); a.property_list_references=lambda:[{"source":"0x1"}]
  with self.assertRaises(PictureProfileHandoffError):m.build_raw_export(a,"CautionConfig.so",CAUTION_CONFIG_SHA256)
 def test_output_is_contained(self):
  m=ex()
  with tempfile.TemporaryDirectory() as d:
   p=Path(d); good=p/"good"; bad=p/"bad"; good.mkdir(); bad.mkdir()
   with self.assertRaises(RuntimeError):m.write_json_atomic(bad/"raw-picture-profile-handoff.json",{},good)
if __name__=="__main__":unittest.main()

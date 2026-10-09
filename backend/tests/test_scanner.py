from scanner.terraform_plan import scan_plan

def test_detects_expected_risks():
    plan = {"planned_values": {"root_module": {"resources": [
        {"address":"aws_s3_bucket.data","type":"aws_s3_bucket","values":{"bucket":"demo"}},
        {"address":"aws_security_group.ssh","type":"aws_security_group","values":{"ingress":[{"from_port":22,"to_port":22,"protocol":"tcp","cidr_blocks":["0.0.0.0/0"]}]}},
        {"address":"aws_ebs_volume.disk","type":"aws_ebs_volume","values":{"encrypted":False}},
        {"address":"aws_db_instance.db","type":"aws_db_instance","values":{"storage_encrypted":False}},
        {"address":"aws_iam_policy.admin","type":"aws_iam_policy","values":{"policy":{"Statement":[{"Action":"*","Resource":"*"}]}}},
    ]}}}
    findings = scan_plan(plan)
    rules = {f.rule_id for f in findings}
    assert {"CG-S3-001","CG-NET-001","CG-STO-001","CG-STO-002","CG-IAM-001","CG-IAM-002"} <= rules

def test_resource_changes_fallback():
    plan = {"resource_changes":[{"address":"aws_ebs_volume.x","type":"aws_ebs_volume","change":{"after":{"encrypted":False}}}]}
    assert any(f.rule_id == "CG-STO-001" for f in scan_plan(plan))

def test_fingerprints_are_stable():
    plan = {"planned_values":{"root_module":{"resources":[{"address":"aws_s3_bucket.x","type":"aws_s3_bucket","values":{}}]}}}
    assert scan_plan(plan)[0].fingerprint == scan_plan(plan)[0].fingerprint

def test_does_not_flag_encrypted_storage():
    plan = {"planned_values":{"root_module":{"resources":[
      {"address":"aws_ebs_volume.x","type":"aws_ebs_volume","values":{"encrypted":True}},
      {"address":"aws_db_instance.x","type":"aws_db_instance","values":{"storage_encrypted":True}},
    ]}}}
    assert scan_plan(plan) == []

def test_rejects_non_object():
    try:
        scan_plan([])
    except ValueError:
        return
    assert False, "expected ValueError"

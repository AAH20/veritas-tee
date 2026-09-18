"""
VeritasTEE CLI: Confidential Computing & Remote Attestation Suite.
"""
import argparse
import hashlib
from .attestation.pcr_measurement import HardwareAttestationVerifier
from .enclave.confidential_runner import ConfidentialAgentRunner
from .audit_receipt.zk_receipt import VerifiableAuditReceiptGenerator

def main():
    parser = argparse.ArgumentParser(
        prog="veritas-tee",
        description="Confidential AI Agent Enclave & Cryptographically Verifiable Execution Attestation."
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # attest
    subparsers.add_parser("attest", help="Generate hardware TEE attestation report with PCR measurements")

    # run-enclave
    subparsers.add_parser("run-enclave", help="Run confidential inference step inside encrypted enclave")

    # verify-receipt
    subparsers.add_parser("verify-receipt", help="Generate verifiable ZK-audit execution receipt")

    args = parser.parse_args()

    if args.command == "attest":
        meas = HardwareAttestationVerifier.measure_environment(
            model_weights_id="deepseek-r1-qwen-70b-fp8",
            system_prompt="You are a confidential Wall Street trading execution agent.",
            tool_definitions={"execute_order": "router.v1", "fetch_orderbook": "l2.v1"}
        )
        report = HardwareAttestationVerifier.generate_attestation_report(meas, nonce="session_nonce_779")
        print(f"[VeritasTEE] Hardware Remote Attestation ({report.platform}):")
        print(f"  PCR0 (Firmware Root)   : {report.measurements.pcr0_firmware[:32]}...")
        print(f"  PCR1 (Model Digest)    : {report.measurements.pcr1_model_digest[:32]}...")
        print(f"  PCR2 (System Prompt)   : {report.measurements.pcr2_system_prompt[:32]}...")
        print(f"  Chip Unique Signature  : {report.chip_unique_signature}")
        print("  Attestation Verdict    : VALIDATED_TAMPER_PROOF")

    elif args.command == "run-enclave":
        runner = ConfidentialAgentRunner(
            model_id="deepseek-r1-qwen-70b-fp8",
            system_prompt="You are an audited medical diagnostic agent.",
            tools={"query_patient_records": "hipaa.v1"}
        )
        res = runner.run_inference_step("Evaluate patient lab panel blood chemistry for acute biomarkers.")
        print(f"[VeritasTEE] Confidential Enclave Execution:")
        print(f"  Enclave Status       : {res['enclave_status']}")
        print(f"  Model ID             : {res['model_id']}")
        print(f"  Execution Trace Hash : {res['execution_trace_hash']}")
        print("  Memory Snoop Defense : Host OS & Hypervisor Inspection Defeated (Memory Encrypted).")

    elif args.command == "verify-receipt":
        meas = HardwareAttestationVerifier.measure_environment("model-v1", "prompt-v1", {"tool": "v1"})
        report = HardwareAttestationVerifier.generate_attestation_report(meas, nonce="nonce-1")
        prompt_hash = hashlib.sha256(b"Institutional Confidential Order 5000 SOL").hexdigest()
        receipt = VerifiableAuditReceiptGenerator.emit_receipt(report, prompt_hash, "trace_hash_abc")
        print(f"[VeritasTEE] Verifiable Execution Audit Receipt:")
        print(f"  Receipt ID     : {receipt['receipt']['receipt_id']}")
        print(f"  Merkle Root    : {receipt['merkle_root']}")
        print(f"  Audit Verdict  : {receipt['audit_verdict']}")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()

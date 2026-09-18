import unittest
from veritas_tee.attestation.pcr_measurement import HardwareAttestationVerifier
from veritas_tee.enclave.confidential_runner import ConfidentialAgentRunner
from veritas_tee.audit_receipt.zk_receipt import VerifiableAuditReceiptGenerator

class TestVeritasTEE(unittest.TestCase):
    def test_pcr_measurements_and_attestation(self):
        meas = HardwareAttestationVerifier.measure_environment(
            model_weights_id="weights_sha256_1234",
            system_prompt="System prompt locked in TEE.",
            tool_definitions={"tool1": "v1"}
        )
        self.assertEqual(len(meas.pcr0_firmware), 64)
        self.assertEqual(len(meas.pcr1_model_digest), 64)
        self.assertEqual(len(meas.pcr2_system_prompt), 64)

        report = HardwareAttestationVerifier.generate_attestation_report(meas, nonce="nonce_123", platform="AMD_SEV_SNP")
        self.assertTrue(report.is_valid)
        self.assertIn("hw_vcek_sig_", report.chip_unique_signature)

    def test_confidential_runner_execution(self):
        runner = ConfidentialAgentRunner(
            model_id="llama-3-70b-confidential",
            system_prompt="Trading system.",
            tools={"swap": "router"}
        )
        res = runner.run_inference_step("Swap 100 USDC for SOL")
        self.assertEqual(res["enclave_status"], "HARDWARE_ISOLATED")
        self.assertEqual(len(res["execution_trace_hash"]), 64)

    def test_zk_verifiable_receipt(self):
        meas = HardwareAttestationVerifier.measure_environment("m1", "p1", {})
        report = HardwareAttestationVerifier.generate_attestation_report(meas, "nonce_abc")
        receipt = VerifiableAuditReceiptGenerator.emit_receipt(report, "prompt_hash_xyz", "trace_123")
        self.assertEqual(receipt["audit_verdict"], "VERIFIED_AUTHENTIC_EXECUTION")
        self.assertEqual(len(receipt["merkle_root"]), 64)

if __name__ == "__main__":
    unittest.main()

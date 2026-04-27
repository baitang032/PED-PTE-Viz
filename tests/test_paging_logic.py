import unittest

from tf_ped_pte.paging_logic import analyze_translation, render_text_report, split_linear_address


class SplitLinearAddressTests(unittest.TestCase):
    def test_split_non_pae_address(self):
        parts = split_linear_address(0x12345678, pae_enabled=False)
        self.assertEqual(parts.pdpt_index, None)
        self.assertEqual(parts.pde_index, 72)
        self.assertEqual(parts.pte_index, 837)
        self.assertEqual(parts.offset, 1656)

    def test_split_pae_address(self):
        parts = split_linear_address(0xCAFEBABE, pae_enabled=True)
        self.assertEqual(parts.pdpt_index, 3)
        self.assertEqual(parts.pde_index, 87)
        self.assertEqual(parts.pte_index, 491)
        self.assertEqual(parts.offset, 2750)


class AnalyzeTranslationTests(unittest.TestCase):
    def test_non_pae_invalid_when_pde_not_present(self):
        result = analyze_translation(
            linear_address=0x12345678,
            cr3=0x00123000,
            pae_enabled=False,
            pde_value=0x00000000,
            pte_value=None,
            pdpte_value=None,
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.verdict, "无效")
        self.assertEqual(result.reason_code, "PDE_NOT_PRESENT")
        self.assertEqual(result.summary, "PDE.P=0，线性地址无效")

    def test_non_pae_valid_4k_page_translation(self):
        result = analyze_translation(
            linear_address=0x12345678,
            cr3=0x00123000,
            pae_enabled=False,
            pde_value=0x00ABC003,
            pte_value=0x0FEDC007,
            pdpte_value=None,
        )
        self.assertTrue(result.valid)
        self.assertEqual(result.page_size, "4KB")
        self.assertEqual(result.physical_address, 0x0FEDC678)
        self.assertEqual(result.summary, "PDE.P=1，PDE.PS=0，PTE.P=1，PTE.PAT=0，线性地址有效")

    def test_non_pae_valid_4mb_page_translation(self):
        result = analyze_translation(
            linear_address=0x12345678,
            cr3=0x00123000,
            pae_enabled=False,
            pde_value=0x12800083,
            pte_value=None,
            pdpte_value=None,
        )
        self.assertTrue(result.valid)
        self.assertEqual(result.page_size, "4MB")
        self.assertEqual(result.physical_address, 0x12B45678)
        self.assertEqual(result.summary, "PDE.P=1，PDE.PS=1，4MB大页有效")

    def test_pae_invalid_when_pdpte_not_present(self):
        result = analyze_translation(
            linear_address=0xCAFEBABE,
            cr3=0x00123020,
            pae_enabled=True,
            pde_value=None,
            pte_value=None,
            pdpte_value=0x0,
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.reason_code, "PDPTE_NOT_PRESENT")
        self.assertEqual(result.summary, "PDPTE.P=0，线性地址无效")

    def test_pae_valid_4k_page_translation(self):
        result = analyze_translation(
            linear_address=0xCAFEBABE,
            cr3=0x00123020,
            pae_enabled=True,
            pdpte_value=0x0000000000200001,
            pde_value=0x0000000000300003,
            pte_value=0x0000000012345087,
        )
        self.assertTrue(result.valid)
        self.assertEqual(result.page_size, "4KB")
        self.assertEqual(result.physical_address, 0x12345ABE)
        self.assertEqual(result.summary, "PDPTE.P=1，PDE.P=1，PDE.PS=0，PTE.P=1，PTE.PAT=1，线性地址有效")


class RenderReportTests(unittest.TestCase):
    def test_report_contains_non_pae_flags_and_addresses(self):
        result = analyze_translation(
            linear_address=0x12345678,
            cr3=0x00123000,
            pae_enabled=False,
            pde_value=0x00ABC003,
            pte_value=0x0FEDC007,
            pdpte_value=None,
        )
        text = render_text_report(result)
        self.assertIn("模式: 非PAE", text)
        self.assertIn("PDE 索引: 72", text)
        self.assertIn("PTE 索引: 837", text)
        self.assertIn("PDE.P = 1", text)
        self.assertIn("PDE.PS = 0", text)
        self.assertIn("PTE.P = 1", text)
        self.assertIn("PTE.PAT = 0", text)
        self.assertIn("物理地址: 0x0FEDC678", text)

    def test_report_contains_pae_pdpte_details(self):
        result = analyze_translation(
            linear_address=0xCAFEBABE,
            cr3=0x00123020,
            pae_enabled=True,
            pdpte_value=0x0000000000200001,
            pde_value=0x0000000000300003,
            pte_value=0x0000000012345087,
        )
        text = render_text_report(result)
        self.assertIn("模式: PAE", text)
        self.assertIn("PDPTE 索引: 3", text)
        self.assertIn("PDPTE.P = 1", text)
        self.assertIn("PDE.P = 1", text)
        self.assertIn("PTE.PAT = 1", text)
        self.assertIn("物理地址: 0x0000000012345ABE", text)


if __name__ == '__main__':
    unittest.main()

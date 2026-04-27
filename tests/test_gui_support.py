import unittest

from tf_ped_pte.gui_support import (
    build_status_rows,
    parse_int_value,
    parse_windbg_text,
    render_entry_flag_panel,
)
from tf_ped_pte.paging_logic import analyze_translation


class ParseIntValueTests(unittest.TestCase):
    def test_parse_hex_value(self):
        self.assertEqual(parse_int_value("0x1234"), 0x1234)

    def test_parse_binary_value(self):
        self.assertEqual(parse_int_value("0b1010"), 10)

    def test_parse_empty_value_as_none(self):
        self.assertIsNone(parse_int_value("   "))


class ParseWindbgTextTests(unittest.TestCase):
    def test_parse_non_pae_pte_output(self):
        parsed = parse_windbg_text(
            """
            VA 12345678
            PDE at C030048C    PTE at C0091A28
            contains 00ABC003  contains 0FEDC007
            """
        )
        self.assertFalse(parsed["pae_enabled"])
        self.assertEqual(parsed["linear_address"], 0x12345678)
        self.assertIsNone(parsed["cr3"])
        self.assertIsNone(parsed["pdpte_value"])
        self.assertEqual(parsed["pde_value"], 0x00ABC003)
        self.assertEqual(parsed["pte_value"], 0x0FEDC007)

    def test_parse_pae_output_with_explicit_pdpte_and_cr3(self):
        parsed = parse_windbg_text(
            """
            cr3=00123020
            VA CAFEBABE
            PDPTE at 00123038 contains 0000000000200001
            PDE at C06032B0    PTE at C07F5F58
            contains 0000000000300003  contains 0000000012345087
            """
        )
        self.assertTrue(parsed["pae_enabled"])
        self.assertEqual(parsed["cr3"], 0x00123020)
        self.assertEqual(parsed["linear_address"], 0xCAFEBABE)
        self.assertEqual(parsed["pdpte_value"], 0x0000000000200001)
        self.assertEqual(parsed["pde_value"], 0x0000000000300003)
        self.assertEqual(parsed["pte_value"], 0x0000000012345087)

    def test_parse_vtop_style_labels(self):
        parsed = parse_windbg_text(
            """
            DirBase: 00123020
            VA 804E3A10
            PDPTE = 0000000000200001
            PDE   = 0000000000300003
            PTE   = 0000000012345087
            """
        )
        self.assertTrue(parsed["pae_enabled"])
        self.assertEqual(parsed["cr3"], 0x00123020)
        self.assertEqual(parsed["linear_address"], 0x804E3A10)
        self.assertEqual(parsed["pdpte_value"], 0x0000000000200001)
        self.assertEqual(parsed["pde_value"], 0x0000000000300003)
        self.assertEqual(parsed["pte_value"], 0x0000000012345087)

    def test_parse_x86vtop_output(self):
        parsed = parse_windbg_text(
            """
            kd> !vtop 3eb63ac0 0028E928
            X86VtoP: Virt 0028e928, pagedir 3eb63ac0
            X86VtoP: PAE PDPE 3eb63ac0 - 0000000019487801
            X86VtoP: PAE PDE 19487008 - 0000000023ec2867
            X86VtoP: PAE PTE 23ec2470 - 8000000019ed2967
            X86VtoP: PAE Mapped phys 19ed2928
            Virtual address 28e928 translates to physical address 19ed2928.
            """
        )
        self.assertTrue(parsed["pae_enabled"])
        self.assertEqual(parsed["cr3"], 0x3EB63AC0)
        self.assertEqual(parsed["linear_address"], 0x0028E928)
        self.assertEqual(parsed["pdpte_value"], 0x0000000019487801)
        self.assertEqual(parsed["pde_value"], 0x0000000023EC2867)
        self.assertEqual(parsed["pte_value"], 0x8000000019ED2967)
        self.assertEqual(parsed["physical_address"], 0x19ED2928)


class RenderEntryFlagPanelTests(unittest.TestCase):
    def test_render_pae_pde_flag_panel(self):
        panel = render_entry_flag_panel("PDE", 0x0000000023EC2867, pae_enabled=True, large_page=False)
        self.assertIn("PDE 标志位", panel)
        self.assertIn("P ", panel)
        self.assertIn("R/W", panel)
        self.assertIn("PS", panel)
        self.assertIn("NX", panel)
        self.assertIn("绿", panel)
        self.assertIn("红", panel)

    def test_render_pae_pte_flag_panel_with_nx(self):
        panel = render_entry_flag_panel("PTE", 0x8000000019ED2967, pae_enabled=True, large_page=False)
        self.assertIn("PTE 标志位", panel)
        self.assertIn("PAT", panel)
        self.assertIn("NX", panel)
        self.assertIn(" 1 ", panel)


class BuildStatusRowsTests(unittest.TestCase):
    def test_build_rows_for_non_pae_small_page(self):
        result = analyze_translation(
            linear_address=0x12345678,
            cr3=0x00123000,
            pae_enabled=False,
            pde_value=0x00ABC003,
            pte_value=0x0FEDC007,
            pdpte_value=None,
        )
        rows = build_status_rows(result)
        self.assertEqual(rows[0], ("结果", "有效"))
        self.assertIn(("PDE.P", "1"), rows)
        self.assertIn(("PDE.PS", "0"), rows)
        self.assertIn(("PTE.P", "1"), rows)
        self.assertIn(("PTE.PAT", "0"), rows)

    def test_build_rows_for_pae_invalid_pdpte(self):
        result = analyze_translation(
            linear_address=0xCAFEBABE,
            cr3=0x00123020,
            pae_enabled=True,
            pde_value=None,
            pte_value=None,
            pdpte_value=0,
        )
        rows = build_status_rows(result)
        self.assertIn(("PDPTE.P", "0"), rows)
        self.assertIn(("原因", "PDPTE_NOT_PRESENT"), rows)


if __name__ == '__main__':
    unittest.main()

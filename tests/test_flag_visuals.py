import unittest

from tf_ped_pte.gui_support import build_entry_flag_cells


class BuildEntryFlagCellsTests(unittest.TestCase):
    def test_build_pae_pde_cells_has_true_colors(self):
        cells, note = build_entry_flag_cells("PDE", 0x0000000023EC2867, pae_enabled=True, large_page=False)
        self.assertEqual(cells[0].label, "P (bit 0)")
        self.assertEqual(cells[0].value_text, "1")
        self.assertEqual(cells[0].color_name, "green")
        self.assertTrue(cells[0].bg_color.startswith("#"))
        ps_cell = next(cell for cell in cells if "PS" in cell.label)
        self.assertEqual(ps_cell.value_text, "0")
        self.assertEqual(ps_cell.color_name, "red")
        self.assertIsNotNone(note)

    def test_build_non_pae_pte_cells_marks_nx_as_disabled(self):
        cells, note = build_entry_flag_cells("PTE", 0x0000000000000067, pae_enabled=False, large_page=False)
        nx_cell = next(cell for cell in cells if "NX" in cell.label)
        self.assertEqual(nx_cell.value_text, "-")
        self.assertEqual(nx_cell.color_name, "gray")
        self.assertIsNotNone(note)


if __name__ == '__main__':
    unittest.main()

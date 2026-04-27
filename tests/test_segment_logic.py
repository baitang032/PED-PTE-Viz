import unittest

from tf_ped_pte.segment_logic import analyze_segment_descriptor, split_address_for_mode


class SegmentDescriptorTests(unittest.TestCase):
    def test_parse_32bit_code_descriptor(self):
        result = analyze_segment_descriptor(0x00CF9A000000FFFF)
        self.assertEqual(result.kind, "代码段")
        self.assertTrue(result.executable)
        self.assertTrue(result.readable_writable)
        self.assertEqual(result.type_bits, 0xA)
        self.assertEqual(result.s, 1)
        self.assertEqual(result.dpl, 0)
        self.assertEqual(result.present, 1)
        self.assertEqual(result.granularity, 1)
        self.assertEqual(result.db, 1)
        self.assertEqual(result.l, 0)
        self.assertEqual(result.default_operand_size, "32位")
        self.assertEqual(result.effective_limit, 0xFFFFFFFF)

    def test_parse_32bit_data_descriptor(self):
        result = analyze_segment_descriptor(0x00CF92000000FFFF)
        self.assertEqual(result.kind, "数据段")
        self.assertFalse(result.executable)
        self.assertTrue(result.readable_writable)
        self.assertEqual(result.default_stack_pointer, "ESP")
        self.assertEqual(result.push_pop_size, "4字节")

    def test_parse_64bit_code_descriptor(self):
        result = analyze_segment_descriptor(0x00AF9A000000FFFF)
        self.assertEqual(result.kind, "代码段")
        self.assertEqual(result.l, 1)
        self.assertEqual(result.db, 0)
        self.assertEqual(result.default_operand_size, "64位代码段")


class PagingSplitTests(unittest.TestCase):
    def test_split_non_pae_address(self):
        result = split_address_for_mode(0x002BE938, "non_pae")
        self.assertEqual(result.mode_name, "32位 非PAE")
        self.assertEqual(result.indices["PDE"], 0)
        self.assertEqual(result.indices["PTE"], 0x2BE)
        self.assertEqual(result.indices["OFFSET"], 0x938)
        self.assertEqual(result.bit_groups, ["00 0000 0000", "10 1011 1110", "1001 0011 1000"])

    def test_split_pae_address(self):
        result = split_address_for_mode(0xCAFEBABE, "pae")
        self.assertEqual(result.mode_name, "32位 PAE")
        self.assertEqual(result.indices["PDPTE"], 3)
        self.assertEqual(result.indices["PDE"], 87)
        self.assertEqual(result.indices["PTE"], 491)
        self.assertEqual(result.indices["OFFSET"], 2750)

    def test_split_x64_address(self):
        result = split_address_for_mode(0xFFFFF80412345678, "x64")
        self.assertEqual(result.mode_name, "x64 四级页表")
        self.assertIn("PML4", result.indices)
        self.assertIn("PDPT", result.indices)
        self.assertIn("PD", result.indices)
        self.assertIn("PT", result.indices)
        self.assertIn("OFFSET", result.indices)


if __name__ == '__main__':
    unittest.main()

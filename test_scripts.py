import struct
import sys
import os

# Add the repository root to the path so we can import the scripts
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def test_ror32_from_apl():
    """Test the ROR32 helper used in dec_uUpd_Atom_apl."""
    import dec_uUpd_Atom_apl as apl
    assert apl.ROR32(0x80000000, 1) == 0x40000000
    assert apl.ROR32(0x00000001, 1) == 0x80000000
    assert apl.ROR32(0xABCD1234, 0) == 0xABCD1234


def test_ror32_from_glp():
    """Test the ROR32 helper used in dec_uUpd_xu_Atom_glp."""
    import dec_uUpd_xu_Atom_glp as glp
    assert glp.ROR32(0x80000000, 1) == 0x40000000
    assert glp.ROR32(0x00000001, 1) == 0x80000000
    assert glp.ROR32(0xABCD1234, 0) == 0xABCD1234


def test_calc_entropy():
    """Test the entropy calculation function."""
    import pytest
    import dec_uUpd_Atom_apl as apl
    # Uniform distribution (all same byte) has 0 entropy
    data = b'\x00' * 256
    assert apl.calcEntropy(data) == pytest.approx(0.0, abs=1e-9)
    # bytes(range(256)) is a perfectly uniform distribution: entropy = 8.0 bits
    data2 = bytes(range(256))
    assert apl.calcEntropy(data2) == pytest.approx(8.0, abs=1e-9)


def test_my_sha256_init():
    """Test that my_SHA256 initializes with the correct IV."""
    import dec_uUpd_Atom_apl as apl
    mh = apl.my_SHA256()
    assert mh.h[0] == 0x6a09e667
    assert mh.h[7] == 0x5be0cd19


def test_my_sha256_transform():
    """Test that my_SHA256 transform produces a 32-byte result."""
    import dec_uUpd_Atom_apl as apl
    mh = apl.my_SHA256()
    # Transform requires exactly 64 bytes
    block = b'\x00' * 64
    result = mh.transform(block)
    assert len(result) == 32


def test_pack_secret_key_apl():
    """Test that the APL secret key is packed correctly."""
    import dec_uUpd_Atom_apl as apl
    aX = [0x9db2770e, 0x5d76919e, 0x994866a2, 0xab13688b]
    expected = struct.pack("<4L", *aX)
    assert apl.abX == expected


def test_pack_secret_key_glp():
    """Test that the GLP secret key is packed correctly."""
    import dec_uUpd_xu_Atom_glp as glp
    aX = [0xff062483, 0x9c7f0b6b, 0x2c5c83a4, 0x1e266274]
    expected = struct.pack("<4L", *aX)
    assert glp.abX == expected
